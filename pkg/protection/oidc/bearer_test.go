package oidc

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MicahParks/keyfunc/v3"
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
	// Said at debug level here, where it would repeat per request.
	if got := messages(hook, logrus.DebugLevel); len(got) != 1 || got[0] != "user not in any allowed group" {
		t.Errorf("debug lines: %v", got)
	}
	if got := messages(hook, logrus.WarnLevel); len(got) != 0 {
		t.Errorf("warnings: %v", got)
	}
	if _, cookie := login(t, p, idp); cookie != nil {
		t.Error("the browser login let the same user in")
	}
	if got := messages(hook, logrus.WarnLevel); len(got) != 1 || got[0] != "user not in any allowed group" {
		t.Errorf("warnings after the browser login: %v", got)
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

// TestBearer_OnAuthRoutes: bearer tokens are for the token alias. On
// /auth/* the provider does not read an Authorization header, with the
// bearer block as without it: a request is authenticated by its session
// cookie or sent to the login, whatever token it carries — valid, bad,
// or garbage. So the answer there cannot depend on where this provider
// stands among several.
func TestBearer_OnAuthRoutes(t *testing.T) {
	idp := oidctest.New(t, oidctest.User{Subject: "u1", Email: "alice@example.org"})
	on, hook := newLoggedIdPProvider(t, idp, Config{Bearer: bearerOn()})
	off := newIdPProvider(t, idp, Config{})
	_, cookie := login(t, on, idp)
	hook.Reset()

	authenticate := func(p *Provider, r *http.Request) protection.Outcome {
		t.Helper()
		out, err := p.Authenticate(context.Background(), r)
		if err != nil {
			t.Fatalf("authenticate: %v", err)
		}
		return out
	}
	headers := map[string]string{
		"no header":         "",
		"a valid token":     "Bearer " + idp.Token(t, cliAudience),
		"a bad token":       "Bearer " + idp.Token(t, "another-client"),
		"garbage":           "Bearer garbage",
		"an oversize token": "Bearer " + strings.Repeat("x", maxBearerHeader),
	}
	for name, header := range headers {
		t.Run(name, func(t *testing.T) {
			request := func(withCookie bool) *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
				if header != "" {
					r.Header.Set("Authorization", header)
				}
				if withCookie {
					r.AddCookie(cookie)
				}
				return r
			}

			// Without a session: the login redirect, as with bearer off.
			got, want := authenticate(on, request(false)), authenticate(off, request(false))
			if got.Identity != nil || got.RedirectTo == "" || got.Status != 0 || len(got.Challenge) != 0 {
				t.Errorf("without a session: %+v, want the login redirect", got)
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("without a session: bearer on %+v, bearer off %+v", got, want)
			}

			// With one: the session's identity, whatever the header says.
			got, want = authenticate(on, request(true)), authenticate(off, request(true))
			if got.Identity == nil || got.Identity.Subject != "alice@example.org" || len(got.SetCookies) != 0 {
				t.Errorf("with a session: %+v", got)
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("with a session: bearer on %+v, bearer off %+v", got, want)
			}
		})
	}
	// The header was never looked at: nothing was said about a token.
	for _, e := range hook.AllEntries() {
		if strings.Contains(e.Message, "bearer") {
			t.Errorf("/auth/* logged %q", e.Message)
		}
	}
}

// countingKeyfunc counts how often the verifier asks for a key — that
// is, how often a token got as far as its signature check.
type countingKeyfunc struct {
	keySource
	calls atomic.Int64
}

// keySource is keyfunc.Keyfunc under a name that does not collide with
// its own method when embedded.
type keySource = keyfunc.Keyfunc

func (c *countingKeyfunc) Keyfunc(token *jwt.Token) (any, error) {
	c.calls.Add(1)
	return c.keySource.Keyfunc(token)
}

// TestBearer_SizeLimitComesFirst: a header over the limit is refused
// before its token is parsed. The token here is one the provider
// accepts — it is the header that is too long — and the verifier is
// never asked for a key. One byte less, and the same token is accepted.
func TestBearer_SizeLimitComesFirst(t *testing.T) {
	idp := oidctest.New(t, oidctest.User{Subject: "u1", Email: "alice@example.org"})
	p := newIdPProvider(t, idp, Config{Bearer: bearerOn()})
	keys := &countingKeyfunc{keySource: p.bearer.kf}
	p.bearer.kf = keys

	valid := idp.Token(t, cliAudience)
	// Padding between the scheme and the token is trimmed away, so the
	// token stays valid whatever the length of the header.
	header := func(size int) string {
		return bearerScheme + strings.Repeat(" ", size-len(bearerScheme)-len(valid)) + valid
	}
	request := func(size int) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/oidc/token", nil)
		r.Header.Set("Authorization", header(size))
		if got := len(r.Header.Get("Authorization")); got != size {
			t.Fatalf("header is %d bytes, want %d", got, size)
		}
		return r
	}

	out := ambient(t, p, request(maxBearerHeader+1))
	if out.Identity != nil || out.Status != http.StatusUnauthorized ||
		out.Challenge.Get("WWW-Authenticate") != `Bearer error="invalid_token"` {
		t.Errorf("one byte over the limit: %+v", out)
	}
	if got := keys.calls.Load(); got != 0 {
		t.Errorf("the verifier was asked for a key %d times for an oversize header", got)
	}

	// At the limit the very same token is accepted, and verified.
	if out := ambient(t, p, request(maxBearerHeader)); out.Identity == nil || out.Identity.Subject != "alice@example.org" {
		t.Errorf("at the limit: %+v", out)
	}
	if got := keys.calls.Load(); got != 1 {
		t.Errorf("the verifier was asked for a key %d times for a header at the limit, want 1", got)
	}

	// A token that is itself too large never reaches the verifier
	// either.
	claims := idp.Claims(cliAudience)
	claims["pad"] = strings.Repeat("x", maxBearerHeader)
	if out := ambient(t, p, bearerRequest(idp.Sign(t, claims))); out.Identity != nil {
		t.Errorf("oversize token accepted: %+v", out.Identity)
	}
	if got := keys.calls.Load(); got != 1 {
		t.Errorf("an oversize token reached the verifier (%d key lookups)", got)
	}
}

// TestBearer_SeveralAudiences: with several audiences configured a
// token has to name one of them — any one, not the first and not all.
func TestBearer_SeveralAudiences(t *testing.T) {
	idp := oidctest.New(t, oidctest.User{Subject: "u1", Email: "alice@example.org"})
	p := newIdPProvider(t, idp, Config{Bearer: &BearerConfig{Audiences: []string{"first-cli", "second-cli", "third-cli"}}})

	with := func(aud any) string {
		claims := idp.Claims("first-cli")
		claims["aud"] = aud
		return idp.Sign(t, claims)
	}
	tests := []struct {
		name     string
		aud      any
		accepted bool
	}{
		{"only the first", "first-cli", true},
		{"only the second", "second-cli", true},
		{"only the last", "third-cli", true},
		{"only the second, in a list", []string{"second-cli"}, true},
		{"the second next to a stranger", []string{"another-client", "second-cli"}, true},
		{"all of them", []string{"first-cli", "second-cli", "third-cli"}, true},
		{"none of them", "another-client", false},
		{"none of them, in a list", []string{"another-client", "authenticatoor"}, false},
		{"a prefix of one", "second", false},
		{"two of them joined", "first-cli,second-cli", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := ambient(t, p, bearerRequest(with(tc.aud)))
			if (out.Identity != nil) != tc.accepted {
				t.Errorf("accepted: %t, want %t (%+v)", out.Identity != nil, tc.accepted, out)
			}
		})
	}
}

// TestBearer_OwnClientIDWarning: listing the provider's own clientId as
// an audience makes the id_tokens of its browser login bearer
// credentials. That is allowed, and said at startup.
func TestBearer_OwnClientIDWarning(t *testing.T) {
	idp := oidctest.New(t, oidctest.User{Subject: "u1", Email: "alice@example.org"})
	other := oidctest.New(t, oidctest.User{Subject: "u1", Email: "alice@example.org"})

	tests := []struct {
		name   string
		bearer *BearerConfig
		warns  bool
	}{
		{"a dedicated client", &BearerConfig{Audiences: []string{cliAudience}}, false},
		{"the own client id", &BearerConfig{Audiences: []string{"authenticatoor"}}, true},
		{"the own client id among others", &BearerConfig{Audiences: []string{cliAudience, "authenticatoor"}}, true},
		{"the own client id, the same issuer spelled out", &BearerConfig{Audiences: []string{"authenticatoor"}, IssuerURL: idp.URL + "/"}, true},
		// Another issuer's tokens are not this provider's id_tokens.
		{"the same id at another issuer", &BearerConfig{Audiences: []string{"authenticatoor"}, IssuerURL: other.URL}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			log, hook := test.NewNullLogger()
			p := New(log, Config{
				IssuerURL: idp.URL, PublicURL: "https://auth.test.example", ClientID: "authenticatoor",
				CallbackURL: "https://auth.test.example/oidc/callback", ClientSecret: "s", SessionKey: testSessionKey,
				Bearer: tc.bearer,
			})
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			if err := p.Start(ctx); err != nil {
				t.Fatalf("start: %v", err)
			}
			var warnings []string
			for _, msg := range messages(hook, logrus.WarnLevel) {
				if strings.Contains(msg, "own clientId") {
					warnings = append(warnings, msg)
				}
			}
			if (len(warnings) == 1) != tc.warns || len(warnings) > 1 {
				t.Fatalf("warnings: %q, want one: %t", warnings, tc.warns)
			}
			if tc.warns && !strings.Contains(warnings[0], "id_tokens") {
				t.Errorf("the warning does not say what follows: %s", warnings[0])
			}
		})
	}

	// What the warning says: the id_token of a browser login is then a
	// bearer credential.
	p := newIdPProvider(t, idp, Config{Bearer: &BearerConfig{Audiences: []string{"authenticatoor"}}})
	if out := ambient(t, p, bearerRequest(idp.Token(t, "authenticatoor"))); out.Identity == nil {
		t.Errorf("a token for the own client id was refused: %+v", out)
	}
}

// TestBearer_PerRequestLogsAreDebug: what identify has to say about a
// user it says at its own level once per browser login, and at debug
// level on the bearer path, where it would repeat with every request.
// A failed bearer authentication is a debug line too.
func TestBearer_PerRequestLogsAreDebug(t *testing.T) {
	tests := []struct {
		name    string
		user    oidctest.User
		cfg     Config
		message string
		level   logrus.Level // on the browser callback
	}{
		{
			"email not verified",
			oidctest.User{Subject: "u1", Email: "alice@example.org", Claims: map[string]any{"email_verified": false}},
			Config{}, "id_token email is not marked email_verified", logrus.InfoLevel,
		},
		{
			"subject looks like an email",
			oidctest.User{Subject: "alice@example.org"},
			Config{}, "the IdP subject looks like an email address", logrus.WarnLevel,
		},
		{
			"not in an allowed group",
			oidctest.User{Subject: "u1", Email: "alice@example.org", Groups: []string{"sigp"}},
			Config{AllowedGroups: []string{"ethpandaops"}}, "user not in any allowed group", logrus.WarnLevel,
		},
	}
	levelsOf := func(hook *test.Hook, message string) []logrus.Level {
		var out []logrus.Level
		for _, e := range hook.AllEntries() {
			if strings.HasPrefix(e.Message, message) {
				out = append(out, e.Level)
			}
		}
		return out
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			idp := oidctest.New(t, tc.user)
			tc.cfg.Bearer = bearerOn()
			p, hook := newLoggedIdPProvider(t, idp, tc.cfg)

			for range 3 {
				ambient(t, p, bearerRequest(idp.Token(t, cliAudience)))
			}
			want := []logrus.Level{logrus.DebugLevel, logrus.DebugLevel, logrus.DebugLevel}
			if got := levelsOf(hook, tc.message); !reflect.DeepEqual(got, want) {
				t.Errorf("bearer path: levels %v, want %v", got, want)
			}
			for _, e := range hook.AllEntries() {
				if e.Level < logrus.InfoLevel {
					t.Errorf("bearer path logged above info: %s %q", e.Level, e.Message)
				}
			}
			hook.Reset()

			login(t, p, idp)
			if got := levelsOf(hook, tc.message); !reflect.DeepEqual(got, []logrus.Level{tc.level}) {
				t.Errorf("browser callback: levels %v, want [%v]", got, tc.level)
			}
		})
	}

	t.Run("a failed authentication", func(t *testing.T) {
		idp := oidctest.New(t, oidctest.User{Subject: "u1", Email: "alice@example.org"})
		p, hook := newLoggedIdPProvider(t, idp, Config{Bearer: bearerOn()})
		for _, token := range []string{"garbage", idp.Token(t, "another-client"), ""} {
			ambient(t, p, bearerRequest(token))
		}
		want := []logrus.Level{logrus.DebugLevel, logrus.DebugLevel, logrus.DebugLevel}
		if got := levelsOf(hook, "oidc bearer authentication failed"); !reflect.DeepEqual(got, want) {
			t.Errorf("levels %v, want %v", got, want)
		}
		if got := len(hook.AllEntries()); got != 3 {
			t.Errorf("%d entries for three failures", got)
		}
	})
}

// TestBearer_Logging: the start says once that bearer tokens are
// accepted, from whom and for which audiences; every authentication is
// logged with its subject (info) or its reason (debug), and never with
// the token.
func TestBearer_Logging(t *testing.T) {
	idp := oidctest.New(t, oidctest.User{Subject: "u1", Email: "alice@example.org"})
	log, hook := test.NewNullLogger()
	log.SetLevel(logrus.DebugLevel)
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
	if e := entries[1]; e.Level != logrus.DebugLevel || e.Data[logrus.ErrorKey] == nil {
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

// TestStart_JWKSFailureDoesNotFailStart: the discovery document has to
// be there at Start; the keys do not. With a JWKS that cannot be
// fetched the provider starts, and refuses every token for want of a
// key — which is what the docs tell operators.
func TestStart_JWKSFailureDoesNotFailStart(t *testing.T) {
	signer := oidctest.New(t, oidctest.User{Subject: "u1", Email: "alice@example.org"})

	var base string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q,"jwks_uri":%q}`,
			base, base+"/authorize", base+"/token", base+"/keys")
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no keys today", http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	base = srv.URL

	log := logrus.New()
	log.SetOutput(io.Discard)
	p := New(log, Config{
		IssuerURL: base, PublicURL: "https://auth.test.example", ClientID: "authenticatoor",
		CallbackURL: "https://auth.test.example/oidc/callback", ClientSecret: "s", SessionKey: testSessionKey,
		Bearer: bearerOn(),
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := p.Start(ctx); err != nil {
		t.Fatalf("start with an unreachable JWKS: %v", err)
	}

	// A token that would be good, were its key known.
	claims := signer.Claims(cliAudience)
	claims["iss"] = base
	out := ambient(t, p, bearerRequest(signer.Sign(t, claims)))
	if out.Identity != nil || out.Status != http.StatusUnauthorized {
		t.Errorf("without keys: %+v", out)
	}
}
