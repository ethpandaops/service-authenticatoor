package oidc

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"

	"github.com/ethpandaops/service-authenticatoor/pkg/protection"
	"github.com/ethpandaops/service-authenticatoor/pkg/protection/oidc/oidctest"
)

// cliAudience is the client id of the non-browser client in these tests.
const cliAudience = "devnet-cli"

func bearerOn() *BearerConfig { return &BearerConfig{Audiences: []string{cliAudience}} }

// bearerRequest is a request to the token alias carrying the token.
func bearerRequest(token string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/oidc/token", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}

func ambient(t *testing.T, p *Provider, r *http.Request) protection.Outcome {
	t.Helper()
	out, err := p.AuthenticateAmbient(context.Background(), r)
	if err != nil {
		t.Fatalf("authenticate ambient: %v", err)
	}
	if out.RedirectTo != "" || len(out.SetCookies) != 0 {
		t.Fatalf("the bearer path redirected or set a cookie: %+v", out)
	}
	return out
}

// TestBearer_Verification: every check a presented token has to pass.
// Each rejected row differs from the accepted token in one respect.
func TestBearer_Verification(t *testing.T) {
	idp := oidctest.New(t, oidctest.User{Subject: "u1", Email: "alice@example.org"})
	// The JWKS names no algorithm, so the allow-list of the verifier is
	// the only thing between it and another RSA algorithm.
	idp.OmitKeyAlg()
	other := oidctest.New(t, oidctest.User{Subject: "u1", Email: "alice@example.org"})
	p := newIdPProvider(t, idp, Config{Bearer: bearerOn()})

	with := func(change func(c map[string]any)) string {
		claims := idp.Claims(cliAudience)
		change(claims)
		return idp.Sign(t, claims)
	}
	signedAs := func(method jwt.SigningMethod, key any) string {
		tok := jwt.NewWithClaims(method, jwt.MapClaims(idp.Claims(cliAudience)))
		tok.Header["kid"] = "oidctest"
		signed, err := tok.SignedString(key)
		if err != nil {
			t.Fatalf("sign %s: %v", method.Alg(), err)
		}
		return signed
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{
		Type: "PUBLIC KEY", Bytes: mustMarshalPublicKey(t, idp),
	})
	valid := idp.Token(t, cliAudience)
	parts := strings.Split(valid, ".")

	tests := []struct {
		name   string
		token  string
		status int // 0: accepted
	}{
		{"valid", valid, 0},
		{"audience in a list", with(func(c map[string]any) { c["aud"] = []string{"other", cliAudience} }), 0},
		{"wrong audience", idp.Token(t, "another-client"), http.StatusUnauthorized},
		{"the provider's own client id is not an audience", idp.Token(t, "authenticatoor"), http.StatusUnauthorized},
		{"audience only in azp", with(func(c map[string]any) {
			c["aud"], c["azp"] = "another-client", cliAudience
		}), http.StatusUnauthorized},
		{"no audience", with(func(c map[string]any) { delete(c, "aud") }), http.StatusUnauthorized},
		{"wrong issuer", with(func(c map[string]any) { c["iss"] = other.URL }), http.StatusUnauthorized},
		{"issuer with a trailing slash", with(func(c map[string]any) { c["iss"] = idp.URL + "/" }), http.StatusUnauthorized},
		{"signed by another IdP", other.Sign(t, idp.Claims(cliAudience)), http.StatusUnauthorized},
		{"expired", with(func(c map[string]any) { c["exp"] = time.Now().Add(-time.Minute).Unix() }), http.StatusUnauthorized},
		{"no exp", with(func(c map[string]any) { delete(c, "exp") }), http.StatusUnauthorized},
		{"not yet valid", with(func(c map[string]any) { c["nbf"] = time.Now().Add(time.Hour).Unix() }), http.StatusUnauthorized},
		{"missing sub", with(func(c map[string]any) { delete(c, "sub") }), http.StatusUnauthorized},
		{"empty sub", with(func(c map[string]any) { c["sub"] = "" }), http.StatusUnauthorized},
		{"alg none", signedAs(jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType), http.StatusUnauthorized},
		{"HS256 keyed with the public key", signedAs(jwt.SigningMethodHS256, publicPEM), http.StatusUnauthorized},
		{"another RSA algorithm", signedAs(jwt.SigningMethodRS384, idp.Key()), http.StatusUnauthorized},
		{"signature stripped", parts[0] + "." + parts[1] + ".", http.StatusUnauthorized},
		{"garbage", "not-a-jwt", http.StatusUnauthorized},
		{"empty", "", http.StatusUnauthorized},
		// A valid token: only its size is wrong.
		{"oversize header", with(func(c map[string]any) { c["pad"] = strings.Repeat("x", maxBearerHeader) }), http.StatusUnauthorized},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := ambient(t, p, bearerRequest(tc.token))
			if tc.status == 0 {
				if out.Identity == nil || out.Identity.Subject != "alice@example.org" {
					t.Fatalf("not accepted: %+v", out)
				}
				return
			}
			if out.Identity != nil {
				t.Fatalf("accepted as %+v", out.Identity)
			}
			if out.Status != tc.status {
				t.Errorf("status %d, want %d", out.Status, tc.status)
			}
			if got := out.Challenge.Get("WWW-Authenticate"); got != `Bearer error="invalid_token"` {
				t.Errorf("challenge %q", got)
			}
		})
	}

	// A verifier that was given no audience refuses everything; the
	// parser would otherwise skip the audience check.
	t.Run("verifier without audiences", func(t *testing.T) {
		open := *p.bearer
		open.audiences = nil
		if _, err := open.parse(valid); err == nil {
			t.Error("a verifier without audiences accepted a token")
		}
	})
	t.Run("no header", func(t *testing.T) {
		out := ambient(t, p, httptest.NewRequest(http.MethodGet, "/oidc/token", nil))
		if out.Identity != nil || out.Status != http.StatusUnauthorized || out.Challenge.Get("WWW-Authenticate") != "Bearer" {
			t.Errorf("outcome %+v", out)
		}
	})
	t.Run("another scheme", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/oidc/token", nil)
		r.Header.Set("Authorization", "Basic "+valid)
		if out := ambient(t, p, r); out.Identity != nil || out.Status != http.StatusUnauthorized {
			t.Errorf("outcome %+v", out)
		}
	})
	t.Run("scheme in lower case", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/oidc/token", nil)
		r.Header.Set("Authorization", "bearer "+valid)
		if out := ambient(t, p, r); out.Identity == nil {
			t.Errorf("outcome %+v", out)
		}
	})
	t.Run("a session cookie is not looked at", func(t *testing.T) {
		_, cookie := login(t, p, idp)
		r := httptest.NewRequest(http.MethodGet, "/oidc/token", nil)
		r.AddCookie(cookie)
		if out := ambient(t, p, r); out.Identity != nil {
			t.Errorf("authenticated from the cookie: %+v", out.Identity)
		}
	})
}

func mustMarshalPublicKey(t *testing.T, idp *oidctest.IdP) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&idp.Key().PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	return der
}

// TestBearer_SecondIssuer: with bearer.issuerURL the presented tokens
// are those of that issuer — its keys, its "iss" — and tokens of the
// login issuer are not accepted, whatever their audience.
func TestBearer_SecondIssuer(t *testing.T) {
	user := oidctest.User{Subject: "u1", Email: "alice@example.org"}
	login := oidctest.New(t, user)
	cli := oidctest.New(t, user)
	p := newIdPProvider(t, login, Config{
		Bearer: &BearerConfig{Audiences: []string{cliAudience}, IssuerURL: cli.URL + "/"},
	})

	if out := ambient(t, p, bearerRequest(cli.Token(t, cliAudience))); out.Identity == nil {
		t.Errorf("token of the bearer issuer refused: %+v", out)
	}
	if out := ambient(t, p, bearerRequest(login.Token(t, cliAudience))); out.Identity != nil {
		t.Errorf("token of the login issuer accepted: %+v", out.Identity)
	}
	// The login issuer's key under the bearer issuer's name.
	forged := login.Claims(cliAudience)
	forged["iss"] = cli.URL
	if out := ambient(t, p, bearerRequest(login.Sign(t, forged))); out.Identity != nil {
		t.Errorf("token signed by the login issuer accepted: %+v", out.Identity)
	}
	// The browser login is still the login issuer's.
	if _, cookie := loginFlow(t, p, login); cookie == nil {
		t.Error("browser login refused")
	}

	// An issuer that cannot be discovered fails the start.
	bad := New(logrus.New(), Config{
		IssuerURL: login.URL, PublicURL: "https://auth.test.example", ClientID: "authenticatoor",
		CallbackURL: "https://auth.test.example/oidc/callback", ClientSecret: "s", SessionKey: testSessionKey,
		Bearer: &BearerConfig{Audiences: []string{cliAudience}, IssuerURL: login.URL + "/nowhere"},
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := bad.Start(ctx); err == nil {
		t.Error("start with an undiscoverable bearer issuer succeeded")
	}
}

// loginFlow is login under a name that a local variable does not hide.
func loginFlow(t *testing.T, p *Provider, idp *oidctest.IdP) (*httptest.ResponseRecorder, *http.Cookie) {
	t.Helper()
	return login(t, p, idp)
}

// TestBearer_SameIdentityAsBrowser: for the same user of the same IdP,
// the bearer path yields exactly the identity of a browser login.
func TestBearer_SameIdentityAsBrowser(t *testing.T) {
	rules := teamRules(prefixRule, protection.TeamRule{
		Claim: "email", Map: map[string][]string{"alice@example.org": {"owners"}},
	})
	members := []protection.AttributeMember{
		{Attribute: "groups", Value: "panda-access"},
		{Attribute: "email", Value: "alice@example.org"},
		{Attribute: "sub", Value: "u1"},
	}
	groups := []string{"team:panda", "panda-access"}

	tests := []struct {
		name        string
		user        oidctest.User
		trust       bool
		wantSubject string
		wantIsEmail bool
		wantMatches []string
	}{
		{
			"verified email", oidctest.User{Subject: "u1", Email: "alice@example.org", Groups: groups}, false,
			"alice@example.org", true, []string{"email:alice@example.org", "groups:panda-access", "sub:u1"},
		},
		{
			"unverified email",
			oidctest.User{Subject: "u1", Email: "alice@example.org", Groups: groups, Claims: map[string]any{"email_verified": false}},
			false, "u1", false, []string{"groups:panda-access", "sub:u1"},
		},
		{
			"unverified email, trusted",
			oidctest.User{Subject: "u1", Email: "alice@example.org", Groups: groups, Claims: map[string]any{"email_verified": false}},
			true, "alice@example.org", true, []string{"email:alice@example.org", "groups:panda-access", "sub:u1"},
		},
		{
			"email_verified under another name",
			oidctest.User{Subject: "u1", Email: "alice@example.org", Claims: map[string]any{"email_verified": nil, "Email_Verified": true}},
			false, "u1", false, []string{"sub:u1"},
		},
		{"no email", oidctest.User{Subject: "u1", Groups: groups}, false, "u1", false, []string{"groups:panda-access", "sub:u1"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			idp := oidctest.New(t, tc.user)
			p := newIdPProvider(t, idp, Config{
				Teams: []string{"everyone"}, TeamRules: rules, GrantMembers: members,
				TrustUnverifiedEmail: tc.trust, Bearer: bearerOn(),
			})
			_, cookie := login(t, p, idp)
			if cookie == nil {
				t.Fatal("browser login refused")
			}
			browser := identityFor(t, p, cookie)
			bearer := ambient(t, p, bearerRequest(idp.Token(t, cliAudience))).Identity
			if bearer == nil {
				t.Fatal("bearer refused")
			}
			if !reflect.DeepEqual(browser, bearer) {
				t.Errorf("identities differ:\nbrowser %+v\n bearer %+v", browser, bearer)
			}
			if bearer.Subject != tc.wantSubject || bearer.SubjectIsEmail != tc.wantIsEmail {
				t.Errorf("subject %q (email: %v), want %q (%v)", bearer.Subject, bearer.SubjectIsEmail, tc.wantSubject, tc.wantIsEmail)
			}
			if !reflect.DeepEqual(bearer.Matches, tc.wantMatches) {
				t.Errorf("matches %v, want %v", bearer.Matches, tc.wantMatches)
			}
		})
	}
}

// TestBearer_AllowedGroups: a valid token of a user outside
// allowedGroups is authenticated and refused — 403, not 401.
func TestBearer_AllowedGroups(t *testing.T) {
	idp := oidctest.New(t, oidctest.User{Subject: "u1", Email: "alice@example.org", Groups: []string{"sigp"}})
	p, hook := newLoggedIdPProvider(t, idp, Config{AllowedGroups: []string{"ethpandaops"}, Bearer: bearerOn()})

	out := ambient(t, p, bearerRequest(idp.Token(t, cliAudience)))
	if out.Identity != nil || out.Status != http.StatusForbidden {
		t.Fatalf("outcome %+v", out)
	}
	if got := messages(hook, logrus.WarnLevel); len(got) != 1 || got[0] != "user not in any allowed group" {
		t.Errorf("warnings: %v", got)
	}
	if _, cookie := login(t, p, idp); cookie != nil {
		t.Error("the browser login let the same user in")
	}

	idp.SetUser(oidctest.User{Subject: "u1", Email: "alice@example.org", Groups: []string{"ethpandaops:core"}})
	if out := ambient(t, p, bearerRequest(idp.Token(t, cliAudience))); out.Identity == nil {
		t.Errorf("member of an allowed group refused: %+v", out)
	}
}

// TestBearer_MatchesAreNotCutToACookie: the browser session holds at
// most what fits a cookie; the bearer path stores nothing and reports
// every grant member the token satisfies.
func TestBearer_MatchesAreNotCutToACookie(t *testing.T) {
	const n = protection.MaxMatches + 16
	groups := make([]string, 0, n)
	members := make([]protection.AttributeMember, 0, n)
	for i := range n {
		groups = append(groups, fmt.Sprintf("g%03d", i))
		members = append(members, protection.AttributeMember{Attribute: "groups", Value: groups[i]})
	}
	idp := oidctest.New(t, oidctest.User{Subject: "u1", Email: "alice@example.org", Groups: groups})
	p := newIdPProvider(t, idp, Config{GrantMembers: members, Bearer: bearerOn()})

	_, cookie := login(t, p, idp)
	if got := len(identityFor(t, p, cookie).Matches); got != protection.MaxMatches {
		t.Fatalf("browser session holds %d matches, want %d", got, protection.MaxMatches)
	}
	out := ambient(t, p, bearerRequest(idp.Token(t, cliAudience)))
	if out.Identity == nil || len(out.Identity.Matches) != n {
		t.Errorf("bearer identity: %+v, want %d matches", out.Identity, n)
	}
}

// TestBearer_Off: without Config.Bearer the provider does not ask for
// the token alias, authenticates nothing from a header and ignores an
// Authorization header on /auth/*.
func TestBearer_Off(t *testing.T) {
	idp := oidctest.New(t, oidctest.User{Subject: "u1", Email: "alice@example.org"})
	p := newIdPProvider(t, idp, Config{})
	if p.AmbientEnabled() {
		t.Error("AmbientEnabled without a bearer config")
	}
	// The provider's own client id is no audience either.
	for _, aud := range []string{cliAudience, "authenticatoor"} {
		r := bearerRequest(idp.Token(t, aud))
		if out := ambient(t, p, r); out.Identity != nil || out.Status != http.StatusUnauthorized {
			t.Errorf("aud %s: outcome %+v", aud, out)
		}
		out, err := p.Authenticate(context.Background(), r)
		if err != nil || out.Identity != nil || out.RedirectTo == "" {
			t.Errorf("aud %s: /auth/* outcome %+v, %v; want the login redirect", aud, out, err)
		}
	}

	on := newIdPProvider(t, idp, Config{Bearer: bearerOn()})
	if !on.AmbientEnabled() {
		t.Error("AmbientEnabled is false with a bearer config")
	}
}

// TestBearer_OnAuthRoutes: with bearer on, /auth/* takes the header as
// the token alias does — as the cloudflare provider takes its ambient
// headers there. A request with a bad token is not answered with a
// login redirect, and is not rescued by a session cookie.
func TestBearer_OnAuthRoutes(t *testing.T) {
	idp := oidctest.New(t, oidctest.User{Subject: "u1", Email: "alice@example.org"})
	p := newIdPProvider(t, idp, Config{Bearer: bearerOn()})
	_, cookie := login(t, p, idp)

	authenticate := func(r *http.Request) protection.Outcome {
		t.Helper()
		out, err := p.Authenticate(context.Background(), r)
		if err != nil {
			t.Fatalf("authenticate: %v", err)
		}
		return out
	}
	r := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
	r.Header.Set("Authorization", "Bearer "+idp.Token(t, cliAudience))
	if out := authenticate(r); out.Identity == nil || len(out.SetCookies) != 0 {
		t.Errorf("valid token: %+v", out)
	}

	r = httptest.NewRequest(http.MethodGet, "/auth/token", nil)
	r.Header.Set("Authorization", "Bearer "+idp.Token(t, "another-client"))
	r.AddCookie(cookie)
	if out := authenticate(r); out.Identity != nil || out.RedirectTo != "" || out.Status != http.StatusUnauthorized {
		t.Errorf("bad token next to a session cookie: %+v", out)
	}

	// Without the header nothing changed: cookie, or the login redirect.
	r = httptest.NewRequest(http.MethodGet, "/auth/token", nil)
	if out := authenticate(r); out.RedirectTo == "" {
		t.Errorf("no credentials: %+v", out)
	}
	r.AddCookie(cookie)
	if out := authenticate(r); out.Identity == nil {
		t.Errorf("session cookie: %+v", out)
	}
}

// TestBearer_Logging: the start says once that bearer tokens are
// accepted, from whom and for which audiences; every authentication is
// logged with its subject or its reason, and never with the token.
func TestBearer_Logging(t *testing.T) {
	idp := oidctest.New(t, oidctest.User{Subject: "u1", Email: "alice@example.org"})
	log, hook := test.NewNullLogger()
	p := New(log, Config{
		IssuerURL: idp.URL, PublicURL: "https://auth.test.example", ClientID: "authenticatoor",
		CallbackURL: "https://auth.test.example/oidc/callback", ClientSecret: "s", SessionKey: testSessionKey,
		Bearer: bearerOn(),
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := p.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	var startup []*logrus.Entry
	for _, e := range hook.AllEntries() {
		if strings.Contains(e.Message, "bearer tokens are accepted") {
			startup = append(startup, e)
		}
	}
	if len(startup) != 1 || startup[0].Data["issuer"] != idp.URL ||
		!reflect.DeepEqual(startup[0].Data["audiences"], []string{cliAudience}) {
		t.Errorf("startup lines: %v", startup)
	}
	hook.Reset()

	good, bad := idp.Token(t, cliAudience), idp.Token(t, "another-client")
	ambient(t, p, bearerRequest(good))
	ambient(t, p, bearerRequest(bad))
	entries := hook.AllEntries()
	if len(entries) != 2 {
		t.Fatalf("log entries: %v", entries)
	}
	if e := entries[0]; e.Level != logrus.InfoLevel || e.Data["sub"] != "alice@example.org" {
		t.Errorf("success entry: %v %v", e.Message, e.Data)
	}
	if e := entries[1]; e.Level != logrus.WarnLevel || e.Data[logrus.ErrorKey] == nil {
		t.Errorf("failure entry: %v %v", e.Message, e.Data)
	}
	for _, e := range entries {
		line, err := e.String()
		if err != nil {
			t.Fatalf("format entry: %v", err)
		}
		for _, token := range []string{good, bad} {
			if strings.Contains(line, token) || strings.Contains(line, strings.Split(token, ".")[2]) {
				t.Errorf("the token is in the log: %s", line)
			}
		}
	}

	// A config without audiences never starts.
	none := New(log, Config{
		IssuerURL: idp.URL, PublicURL: "https://auth.test.example", ClientID: "authenticatoor",
		CallbackURL: "https://auth.test.example/oidc/callback", ClientSecret: "s", SessionKey: testSessionKey,
		Bearer: &BearerConfig{},
	})
	if err := none.Start(ctx); err == nil {
		t.Error("start without bearer audiences succeeded")
	}
}
