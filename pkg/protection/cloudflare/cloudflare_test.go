package cloudflare

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"

	"github.com/ethpandaops/service-authenticatoor/pkg/cfaccess"
	"github.com/ethpandaops/service-authenticatoor/pkg/protection"
	"github.com/ethpandaops/service-authenticatoor/pkg/session"
)

// stubVerifier lets tests substitute the JWT verifier without standing up a
// real CF JWKS endpoint.
type stubVerifier struct {
	email      string
	commonName string
	aud        []string
	err        error
}

func (s stubVerifier) Verify(_ context.Context, _ string) (*cfaccess.Claims, error) {
	if s.err != nil {
		return nil, s.err
	}
	c := &cfaccess.Claims{Email: s.email, CommonName: s.commonName}
	c.Audience = s.aud
	return c, nil
}

var testSessionKey = []byte("0123456789abcdef0123456789abcdef")

func newTestProvider(t *testing.T, cfg Config) *Provider {
	t.Helper()
	log := logrus.New()
	log.SetOutput(io.Discard)
	if cfg.SessionKey == nil {
		cfg.SessionKey = testSessionKey
	}
	return New(log, cfg)
}

func TestProvider_VerifyOff_TrustsHeader(t *testing.T) {
	p := newTestProvider(t, Config{VerifyJWT: false})
	if err := p.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}

	r := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
	r.Header.Set(DefaultUserHeader, "alice@example.com")

	out, err := p.Authenticate(context.Background(), r)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	if out.Identity == nil {
		t.Fatalf("expected identity, got status %d", out.Status)
	}
	if out.Identity.Email != "alice@example.com" {
		t.Errorf("email: %q", out.Identity.Email)
	}
	if out.Identity.Subject != "alice@example.com" {
		t.Errorf("subject: %q", out.Identity.Subject)
	}
}

func TestProvider_VerifyOff_MissingHeaderRedirectsToLogin(t *testing.T) {
	p := newTestProvider(t, Config{VerifyJWT: false})
	if err := p.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}

	r := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
	out, err := p.Authenticate(context.Background(), r)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	if out.Identity != nil {
		t.Fatal("expected no identity")
	}
	if !strings.HasPrefix(out.RedirectTo, DefaultLoginPath+"?") {
		t.Errorf("redirect: got %q, want %s?...", out.RedirectTo, DefaultLoginPath)
	}
	if !strings.Contains(out.RedirectTo, "return_to=%2Fauth%2Ftoken") {
		t.Errorf("redirect missing return_to: %q", out.RedirectTo)
	}
}

func TestProvider_VerifyOn_MissingAssertionRedirectsToLogin(t *testing.T) {
	p := newTestProvider(t, Config{VerifyJWT: true, TeamDomain: "team.test"})
	p.SetVerifier(stubVerifier{email: "alice@example.com"})

	// Header present but no assertion: the trust-the-header value must
	// NOT authenticate; without any credential the outcome is a redirect
	// to the login entry.
	r := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
	r.Header.Set(DefaultUserHeader, "alice@example.com")
	out, err := p.Authenticate(context.Background(), r)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	if out.Identity != nil {
		t.Fatal("expected no identity (assertion missing)")
	}
	if !strings.HasPrefix(out.RedirectTo, DefaultLoginPath+"?") {
		t.Errorf("redirect: got %q, want %s?...", out.RedirectTo, DefaultLoginPath)
	}
}

func TestProvider_VerifyOn_TrustsAssertionOverHeader(t *testing.T) {
	p := newTestProvider(t, Config{VerifyJWT: true, TeamDomain: "team.test"})
	// Verifier returns "verified@example.com"; the header claims someone
	// else. The verified value must win.
	p.SetVerifier(stubVerifier{email: "verified@example.com"})

	r := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
	r.Header.Set(DefaultUserHeader, "spoofed@example.com")
	r.Header.Set(cfaccess.DefaultJWTHeader, "non-empty")

	out, err := p.Authenticate(context.Background(), r)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	if out.Identity == nil {
		t.Fatalf("expected identity, got status %d", out.Status)
	}
	if out.Identity.Email != "verified@example.com" {
		t.Errorf("email: got %q want %q (verified must win)", out.Identity.Email, "verified@example.com")
	}
}

func TestProvider_VerifyOn_ServiceToken_AllowedUsesCommonName(t *testing.T) {
	p := newTestProvider(t, Config{VerifyJWT: true, TeamDomain: "team.test", AllowServiceTokens: true})
	// A service token assertion carries no email, only a common_name.
	p.SetVerifier(stubVerifier{commonName: "ci-bot.access"})

	r := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
	r.Header.Set(cfaccess.DefaultJWTHeader, "non-empty")

	out, err := p.Authenticate(context.Background(), r)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	if out.Identity == nil {
		t.Fatalf("expected identity for service token, got status %d", out.Status)
	}
	if out.Identity.Subject != "ci-bot.access" {
		t.Errorf("subject: got %q want %q (service token common_name)", out.Identity.Subject, "ci-bot.access")
	}
	if out.Identity.Email != "" {
		t.Errorf("email: got %q want empty (service tokens have no email)", out.Identity.Email)
	}
}

func TestProvider_VerifyOn_ServiceToken_DeniedWhenDisabled(t *testing.T) {
	p := newTestProvider(t, Config{VerifyJWT: true, TeamDomain: "team.test", AllowServiceTokens: false})
	p.SetVerifier(stubVerifier{commonName: "ci-bot.access"})

	r := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
	r.Header.Set(cfaccess.DefaultJWTHeader, "non-empty")

	out, err := p.Authenticate(context.Background(), r)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	if out.Identity != nil {
		t.Fatal("expected no identity when service tokens are disabled")
	}
	if !strings.HasPrefix(out.RedirectTo, DefaultLoginPath+"?") {
		t.Errorf("redirect: got %q, want %s?...", out.RedirectTo, DefaultLoginPath)
	}
}

func TestProvider_VerifyOn_ServiceToken_EmailWinsOverCommonName(t *testing.T) {
	p := newTestProvider(t, Config{VerifyJWT: true, TeamDomain: "team.test", AllowServiceTokens: true})
	// When both are present the email identity must win.
	p.SetVerifier(stubVerifier{email: "alice@example.com", commonName: "ci-bot.access"})

	r := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
	r.Header.Set(cfaccess.DefaultJWTHeader, "non-empty")

	out, err := p.Authenticate(context.Background(), r)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	if out.Identity == nil {
		t.Fatalf("expected identity, got status %d", out.Status)
	}
	if out.Identity.Subject != "alice@example.com" || out.Identity.Email != "alice@example.com" {
		t.Errorf("expected email identity to win, got subject=%q email=%q", out.Identity.Subject, out.Identity.Email)
	}
}

func TestProvider_VerifyOn_RejectsBadAssertion(t *testing.T) {
	p := newTestProvider(t, Config{VerifyJWT: true, TeamDomain: "team.test"})
	p.SetVerifier(stubVerifier{err: errors.New("bad signature")})

	r := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
	r.Header.Set(cfaccess.DefaultJWTHeader, "garbage")

	out, err := p.Authenticate(context.Background(), r)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	if out.Identity != nil {
		t.Fatal("expected no identity for bad assertion")
	}
	if out.Status != http.StatusUnauthorized {
		t.Errorf("status: got %d, want 401", out.Status)
	}
}

func TestProvider_Start_RejectsMissingTeamDomain(t *testing.T) {
	p := newTestProvider(t, Config{VerifyJWT: true})
	err := p.Start(context.Background())
	if err == nil {
		t.Error("expected error for missing TeamDomain")
	}
}

func TestProvider_Start_RejectsShortSessionKey(t *testing.T) {
	log := logrus.New()
	log.SetOutput(io.Discard)
	p := New(log, Config{SessionKey: []byte("short")})
	if err := p.Start(context.Background()); err == nil {
		t.Error("expected error for short SessionKey")
	}
}

// TestProvider_LoginMintsSessionCookie exercises the narrowed-edge
// topology: the login entry (behind CF Access) converts the ambient
// identity into a session cookie, and a later /auth/* request without
// any CF headers authenticates via that cookie.
func TestProvider_LoginMintsSessionCookie(t *testing.T) {
	p := newTestProvider(t, Config{VerifyJWT: true, TeamDomain: "team.test"})
	p.SetVerifier(stubVerifier{email: "alice@example.com"})

	r := httptest.NewRequest(http.MethodGet, DefaultLoginPath+"?return_to=%2Fauth%2Ftoken", nil)
	r.Header.Set(cfaccess.DefaultJWTHeader, "non-empty")
	rr := httptest.NewRecorder()
	p.handleLogin(rr, r)

	if rr.Code != http.StatusFound {
		t.Fatalf("login status: got %d, body: %s", rr.Code, rr.Body.String())
	}
	if loc := rr.Header().Get("Location"); loc != "/auth/token" {
		t.Errorf("login redirect: got %q", loc)
	}
	cookies := rr.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != DefaultSessionCookieName {
		t.Fatalf("expected one session cookie, got %v", cookies)
	}

	// Replay the cookie on a bare /auth/* request — no CF headers.
	r2 := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
	r2.AddCookie(cookies[0])
	out, err := p.Authenticate(context.Background(), r2)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	if out.Identity == nil {
		t.Fatalf("expected identity from session cookie, got redirect %q", out.RedirectTo)
	}
	if out.Identity.Subject != "alice@example.com" {
		t.Errorf("subject: %q", out.Identity.Subject)
	}
}

func TestProvider_LoginWithoutAmbientIdentityIs403(t *testing.T) {
	p := newTestProvider(t, Config{VerifyJWT: true, TeamDomain: "team.test"})
	p.SetVerifier(stubVerifier{email: "alice@example.com"})

	r := httptest.NewRequest(http.MethodGet, DefaultLoginPath, nil)
	rr := httptest.NewRecorder()
	p.handleLogin(rr, r)

	if rr.Code != http.StatusForbidden {
		t.Errorf("status: got %d, want 403", rr.Code)
	}
}

// TestProvider_AmbientIgnoresSessionCookie pins the machine-alias
// contract: /<name>/token must only accept edge credentials, never the
// browser session cookie.
func TestProvider_AmbientIgnoresSessionCookie(t *testing.T) {
	p := newTestProvider(t, Config{VerifyJWT: true, TeamDomain: "team.test"})
	p.SetVerifier(stubVerifier{email: "alice@example.com"})

	// Mint a valid cookie via login.
	r := httptest.NewRequest(http.MethodGet, DefaultLoginPath, nil)
	r.Header.Set(cfaccess.DefaultJWTHeader, "non-empty")
	rr := httptest.NewRecorder()
	p.handleLogin(rr, r)
	cookies := rr.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected one cookie, got %v", cookies)
	}

	r2 := httptest.NewRequest(http.MethodGet, "/cfaccess/token", nil)
	r2.AddCookie(cookies[0])
	out, err := p.AuthenticateAmbient(context.Background(), r2)
	if err != nil {
		t.Fatalf("ambient: %v", err)
	}
	if out.Identity != nil {
		t.Fatal("session cookie must not satisfy ambient authentication")
	}
	if out.Status != http.StatusUnauthorized {
		t.Errorf("status: got %d, want 401", out.Status)
	}
}

// TestProvider_Teams covers every path that builds an Identity: ambient
// headers (verify off), a verified assertion, a service token, the
// machine alias, and the session cookie minted by the login entry.
func TestProvider_Teams(t *testing.T) {
	tests := []struct {
		name   string
		static []string
		want   []string
	}{
		{"none configured", nil, nil},
		{"panda", []string{"panda"}, []string{"panda"}},
		{"sorted, de-duplicated", []string{"panda", "ops", "panda"}, []string{"ops", "panda"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			check := func(what string, out protection.Outcome, err error) {
				t.Helper()
				if err != nil || out.Identity == nil {
					t.Fatalf("%s: identity=%v err=%v", what, out.Identity, err)
				}
				if !slices.Equal(out.Identity.Teams, tc.want) {
					t.Errorf("%s teams: got %v, want %v", what, out.Identity.Teams, tc.want)
				}
			}
			ctx := context.Background()

			// Verify off: the header alone.
			off := newTestProvider(t, Config{VerifyJWT: false, Teams: tc.static})
			if err := off.Start(ctx); err != nil {
				t.Fatalf("start: %v", err)
			}
			r := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
			r.Header.Set(DefaultUserHeader, "alice@example.com")
			out, err := off.Authenticate(ctx, r)
			check("header", out, err)

			// Verified assertion, user identity.
			on := newTestProvider(t, Config{VerifyJWT: true, TeamDomain: "team.test", Teams: tc.static})
			on.SetVerifier(stubVerifier{email: "alice@example.com"})
			r = httptest.NewRequest(http.MethodGet, "/auth/token", nil)
			r.Header.Set(cfaccess.DefaultJWTHeader, "non-empty")
			out, err = on.Authenticate(ctx, r)
			check("assertion", out, err)

			// Machine alias (ambient only).
			out, err = on.AuthenticateAmbient(ctx, r)
			check("ambient alias", out, err)

			// Session cookie from the login entry, no CF headers.
			rr := httptest.NewRecorder()
			on.handleLogin(rr, r)
			cookies := rr.Result().Cookies()
			if len(cookies) != 1 {
				t.Fatalf("login cookies: %v", cookies)
			}
			viaCookie := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
			viaCookie.AddCookie(cookies[0])
			out, err = on.Authenticate(ctx, viaCookie)
			check("session", out, err)

			// Service token.
			svc := newTestProvider(t, Config{
				VerifyJWT: true, TeamDomain: "team.test", AllowServiceTokens: true, Teams: tc.static,
			})
			svc.SetVerifier(stubVerifier{commonName: "abc123.access"})
			out, err = svc.Authenticate(ctx, r)
			check("service token", out, err)
		})
	}
}

// TestProvider_SessionFollowsCurrentStaticTeams: a login-path session
// minted under one config gets the static teams of the config in force
// when it is used.
func TestProvider_SessionFollowsCurrentStaticTeams(t *testing.T) {
	before := newTestProvider(t, Config{VerifyJWT: true, TeamDomain: "team.test", Teams: []string{"panda"}})
	before.SetVerifier(stubVerifier{email: "alice@example.com"})
	r := httptest.NewRequest(http.MethodGet, DefaultLoginPath, nil)
	r.Header.Set(cfaccess.DefaultJWTHeader, "non-empty")
	rr := httptest.NewRecorder()
	before.handleLogin(rr, r)
	cookies := rr.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("login cookies: %v", cookies)
	}

	tests := []struct {
		name   string
		static []string
		want   []string
	}{
		{"unchanged", []string{"panda"}, []string{"panda"}},
		{"replaced", []string{"ops"}, []string{"ops"}},
		{"removed", nil, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			after := newTestProvider(t, Config{VerifyJWT: true, TeamDomain: "team.test", Teams: tc.static})
			after.SetVerifier(stubVerifier{email: "alice@example.com"})
			req := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
			req.AddCookie(cookies[0])
			out, err := after.Authenticate(context.Background(), req)
			if err != nil || out.Identity == nil {
				t.Fatalf("auth: identity=%v err=%v", out.Identity, err)
			}
			if !slices.Equal(out.Identity.Teams, tc.want) {
				t.Errorf("teams: got %v, want %v", out.Identity.Teams, tc.want)
			}
		})
	}
}

// TestProvider_TeamsNotTakenFromRequest: with a verified assertion the
// teams are the configured ones whatever else the request carries, and a
// request without a valid credential gets no identity.
func TestProvider_TeamsNotTakenFromRequest(t *testing.T) {
	p := newTestProvider(t, Config{VerifyJWT: true, TeamDomain: "team.test", Teams: []string{"geth"}})
	p.SetVerifier(stubVerifier{email: "alice@example.com"})

	r := httptest.NewRequest(http.MethodGet, "/auth/token?teams=panda", nil)
	r.Header.Set(cfaccess.DefaultJWTHeader, "non-empty")
	r.Header.Set("X-Teams", "panda")
	r.Header.Set("Cf-Access-Teams", "panda")
	out, err := p.Authenticate(context.Background(), r)
	if err != nil || out.Identity == nil {
		t.Fatalf("auth: identity=%v err=%v", out.Identity, err)
	}
	if !slices.Equal(out.Identity.Teams, []string{"geth"}) {
		t.Errorf("teams: got %v, want only the configured [geth]", out.Identity.Teams)
	}

	// Tampered session cookie, no CF headers: no identity.
	rr := httptest.NewRecorder()
	p.handleLogin(rr, r)
	cookie := rr.Result().Cookies()[0]
	cookie.Value = cookie.Value[:len(cookie.Value)-2] + "xx"
	r2 := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
	r2.AddCookie(cookie)
	out, err = p.Authenticate(context.Background(), r2)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	if out.Identity != nil {
		t.Errorf("tampered cookie produced an identity: %+v", out.Identity)
	}
}

func TestProvider_Start_RejectsInvalidTeams(t *testing.T) {
	for name, cfg := range map[string]Config{
		"static":    {VerifyJWT: false, Teams: []string{"team:panda"}},
		"uppercase": {VerifyJWT: false, Teams: []string{"Panda"}},
		"rule":      {VerifyJWT: false, TeamRules: []protection.TeamRule{{Claim: "email", Regex: "no-group"}}},
	} {
		if err := newTestProvider(t, cfg).Start(context.Background()); err == nil {
			t.Errorf("%s: expected Start to reject the team configuration", name)
		}
	}
}

// accessToken builds a value for the Cf-Access-Jwt-Assertion header
// with the given claims. The tests' stub verifier stands in for the
// signature check; what matters here is which claims the provider reads
// once a token has been verified.
func accessToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	return "e30." + base64.RawURLEncoding.EncodeToString(payload) + ".c2ln"
}

// TestProvider_TeamRules covers the rule forms against this provider's
// attributes: the claims of the verified Access token plus "principal".
func TestProvider_TeamRules(t *testing.T) {
	userToken := map[string]any{
		"email":   "alice@example.com",
		"sub":     "cf-user-1",
		"country": "DE",
		"custom":  map[string]any{"department": "eng", "groups": []string{"staff", "oncall"}},
		"type":    "app",
	}
	serviceToken := map[string]any{"common_name": "abc123.access", "sub": "", "type": "app"}

	staffOnly := []protection.TeamRule{{Claim: "principal", Map: map[string][]string{"user": {"panda"}}}}

	tests := []struct {
		name     string
		rules    []protection.TeamRule
		verifier stubVerifier
		token    map[string]any
		want     []string
	}{
		{"principal: a person is staff", staffOnly, stubVerifier{email: "alice@example.com"}, userToken, []string{"panda"}},
		{"principal: a service token is not", staffOnly, stubVerifier{commonName: "abc123.access"}, serviceToken, nil},
		{
			"principal: a team for machines",
			[]protection.TeamRule{{Claim: "principal", Map: map[string][]string{"service": {"bots"}}}},
			stubVerifier{commonName: "abc123.access"}, serviceToken, []string{"bots"},
		},
		{
			"common_name: one service token",
			[]protection.TeamRule{{Claim: "common_name", Map: map[string][]string{"abc123.access": {"deployer"}}}},
			stubVerifier{commonName: "abc123.access"}, serviceToken, []string{"deployer"},
		},
		{
			"email map",
			[]protection.TeamRule{{Claim: "email", Map: map[string][]string{"*@example.com": {"example"}}}},
			stubVerifier{email: "alice@example.com"}, userToken, []string{"example"},
		},
		{
			"a custom claim, nested list",
			[]protection.TeamRule{{Claim: "custom.groups", Value: true}},
			stubVerifier{email: "alice@example.com"}, userToken, []string{"oncall", "staff"},
		},
		{
			"a custom claim through a regex, and country",
			[]protection.TeamRule{{Claim: "custom.department", Regex: "(eng|ops)"}, {Claim: "country", Map: map[string][]string{"de": {"eu"}}}},
			stubVerifier{email: "alice@example.com"}, userToken, []string{"eng", "eu"},
		},
		{
			"sub and the token's own type claim",
			[]protection.TeamRule{{Claim: "sub", Map: map[string][]string{"cf-user-1": {"one"}}}, {Claim: "type", Map: map[string][]string{"app": {"app"}}}},
			stubVerifier{email: "alice@example.com"}, userToken, []string{"app", "one"},
		},
		{
			"the verifier's email wins over the payload",
			[]protection.TeamRule{{Claim: "email", Map: map[string][]string{"alice@example.com": {"alice"}, "mallory@example.com": {"mallory"}}}},
			stubVerifier{email: "alice@example.com"}, map[string]any{"email": "mallory@example.com"}, []string{"alice"},
		},
		{
			"a service token has no email attribute",
			[]protection.TeamRule{{Claim: "email", Map: map[string][]string{"*": {"has-email"}}}},
			stubVerifier{commonName: "abc123.access"}, map[string]any{"email": "leftover@example.com", "common_name": "abc123.access"}, nil,
		},
		{"a missing claim", []protection.TeamRule{{Claim: "custom.missing", Value: true}, {Claim: "groups", Value: true}}, stubVerifier{email: "alice@example.com"}, userToken, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			p := newTestProvider(t, Config{
				VerifyJWT: true, TeamDomain: "team.test", AllowServiceTokens: true,
				Teams: []string{"door"}, TeamRules: tc.rules,
			})
			p.SetVerifier(tc.verifier)
			want := append([]string{"door"}, tc.want...)
			slices.Sort(want)

			// Ambient, on /auth/* and on the machine alias.
			r := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
			r.Header.Set(cfaccess.DefaultJWTHeader, accessToken(t, tc.token))
			for what, auth := range map[string]func(context.Context, *http.Request) (protection.Outcome, error){
				"ambient": p.Authenticate, "alias": p.AuthenticateAmbient,
			} {
				out, err := auth(ctx, r)
				if err != nil || out.Identity == nil {
					t.Fatalf("%s: identity=%v err=%v", what, out.Identity, err)
				}
				if !slices.Equal(out.Identity.Teams, want) {
					t.Errorf("%s teams: got %v, want %v", what, out.Identity.Teams, want)
				}
			}

			// Login entry → session cookie → a request without CF headers:
			// the rule results were captured from the token at login.
			rr := httptest.NewRecorder()
			p.handleLogin(rr, r)
			cookies := rr.Result().Cookies()
			if rr.Code != http.StatusFound || len(cookies) != 1 {
				t.Fatalf("login: status %d cookies %v", rr.Code, cookies)
			}
			viaCookie := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
			viaCookie.AddCookie(cookies[0])
			out, err := p.Authenticate(ctx, viaCookie)
			if err != nil || out.Identity == nil {
				t.Fatalf("session: identity=%v err=%v", out.Identity, err)
			}
			if !slices.Equal(out.Identity.Teams, want) {
				t.Errorf("session teams: got %v, want %v", out.Identity.Teams, want)
			}
		})
	}
}

// TestProvider_TeamRules_VerifyOff: without a verified token the only
// attributes are the email header and principal=user. Headers a client
// could add next to it are not attributes.
func TestProvider_TeamRules_VerifyOff(t *testing.T) {
	p := newTestProvider(t, Config{
		VerifyJWT: false,
		TeamRules: []protection.TeamRule{
			{Claim: "email", Map: map[string][]string{"*@ethpandaops.io": {"panda"}}},
			{Claim: "principal", Map: map[string][]string{"user": {"people"}}},
			{Claim: "country", Map: map[string][]string{"*": {"country"}}},
			{Claim: "custom.groups", Value: true},
			{Claim: "groups", Value: true},
			{Claim: "common_name", Map: map[string][]string{"*": {"service"}}},
		},
	})
	if err := p.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}

	r := httptest.NewRequest(http.MethodGet, "/auth/token?groups=admins&country=DE", nil)
	r.Header.Set(DefaultUserHeader, "staff@ethpandaops.io")
	// An unverified assertion and assorted headers: none of it counts.
	r.Header.Set(cfaccess.DefaultJWTHeader, accessToken(t, map[string]any{
		"country": "DE", "groups": []string{"admins"}, "custom": map[string]any{"groups": []string{"admins"}},
	}))
	r.Header.Set("X-Groups", "admins")
	r.Header.Set("Cf-Access-Groups", "admins")
	out, err := p.Authenticate(context.Background(), r)
	if err != nil || out.Identity == nil {
		t.Fatalf("auth: identity=%v err=%v", out.Identity, err)
	}
	if want := []string{"panda", "people"}; !slices.Equal(out.Identity.Teams, want) {
		t.Errorf("teams: got %v, want %v", out.Identity.Teams, want)
	}
}

// TestProvider_TeamRules_AmbientFollowsCurrentConfig: on the ambient
// path the rules run on every request, so a config change applies at
// once; a login-path session keeps what was captured, plus the current
// static teams.
func TestProvider_TeamRules_AmbientFollowsCurrentConfig(t *testing.T) {
	token := map[string]any{"email": "alice@example.com", "custom": map[string]any{"groups": []string{"staff"}}}
	build := func(static []string, rules []protection.TeamRule) *Provider {
		p := newTestProvider(t, Config{VerifyJWT: true, TeamDomain: "team.test", Teams: static, TeamRules: rules})
		p.SetVerifier(stubVerifier{email: "alice@example.com"})
		return p
	}
	ctx := context.Background()
	r := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
	r.Header.Set(cfaccess.DefaultJWTHeader, accessToken(t, token))

	before := build([]string{"door"}, []protection.TeamRule{{Claim: "custom.groups", Value: true}})
	rr := httptest.NewRecorder()
	before.handleLogin(rr, r)
	cookie := rr.Result().Cookies()[0]

	after := build([]string{"gate"}, []protection.TeamRule{{Claim: "custom.groups", Map: map[string][]string{"staff": {"panda"}}}})

	out, err := after.Authenticate(ctx, r)
	if err != nil || out.Identity == nil {
		t.Fatalf("ambient: identity=%v err=%v", out.Identity, err)
	}
	if want := []string{"gate", "panda"}; !slices.Equal(out.Identity.Teams, want) {
		t.Errorf("ambient teams: got %v, want %v", out.Identity.Teams, want)
	}

	viaCookie := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
	viaCookie.AddCookie(cookie)
	out, err = after.Authenticate(ctx, viaCookie)
	if err != nil || out.Identity == nil {
		t.Fatalf("session: identity=%v err=%v", out.Identity, err)
	}
	if want := []string{"gate", "staff"}; !slices.Equal(out.Identity.Teams, want) {
		t.Errorf("session teams: got %v, want %v", out.Identity.Teams, want)
	}
}

// TestProvider_RejectsSessionsOfAnotherDoor: a provider entry that was
// "oidc" and becomes "cloudflare" under the same name keeps its session
// key (it is derived from the name). The old cookies, with whatever
// teams the IdP gave, must not count at the new door — nor those of
// another Cloudflare team, nor of the same team with verification off.
func TestProvider_RejectsSessionsOfAnotherDoor(t *testing.T) {
	p := newTestProvider(t, Config{VerifyJWT: true, TeamDomain: "team.test", Teams: []string{"door"}})
	p.SetVerifier(stubVerifier{email: "alice@example.com"})
	payload := session.Payload{Subject: "mallory@idp.example", Email: "mallory@idp.example", Teams: []string{"panda"}}

	tests := []struct {
		name string
		door session.Door
		want []string // nil: no identity
	}{
		{"its own door: the captured teams count", p.door, []string{"door", "panda"}},
		{"an oidc door", session.NewDoor("oidc", "https://idp.example", "authenticatoor"), nil},
		{"a github door", session.NewDoor("github", "https://api.github.com"), nil},
		{"a basic door", session.NewDoor("basic"), nil},
		{"another Cloudflare team", session.NewDoor("cloudflare", "other.test", "true"), nil},
		{"the same team without verification", session.NewDoor("cloudflare", "team.test", "false"), nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			signed, err := session.Sign(testSessionKey, tc.door, payload, DefaultSessionTTL, p.cfg.Now())
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			r := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
			r.AddCookie(&http.Cookie{Name: DefaultSessionCookieName, Value: signed})
			out, err := p.Authenticate(context.Background(), r)
			if err != nil {
				t.Fatalf("auth: %v", err)
			}
			switch {
			case tc.want == nil && out.Identity != nil:
				t.Errorf("a session of another door authenticated: %+v", out.Identity)
			case tc.want != nil && (out.Identity == nil || !slices.Equal(out.Identity.Teams, tc.want)):
				t.Errorf("identity: %+v, want teams %v", out.Identity, tc.want)
			}
		})
	}
}

// TestProvider_GrantMembers: attribute members are evaluated on every
// request that carries the Access headers, against the members of the
// current config; a login-path session keeps the matches of its login.
func TestProvider_GrantMembers(t *testing.T) {
	token := accessToken(t, map[string]any{
		"email": "alice@example.com", "country": "DE",
		"custom": map[string]any{"groups": []string{"staff", "oncall"}},
	})
	build := func(members ...protection.AttributeMember) *Provider {
		p := newTestProvider(t, Config{VerifyJWT: true, TeamDomain: "team.test", AllowServiceTokens: true, GrantMembers: members})
		p.SetVerifier(stubVerifier{email: "alice@example.com"})
		return p
	}
	ctx := context.Background()
	r := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
	r.Header.Set(cfaccess.DefaultJWTHeader, token)

	principal := protection.AttributeMember{Attribute: "principal", Value: "user"}
	staff := protection.AttributeMember{Attribute: "custom.groups", Value: "Staff"}
	country := protection.AttributeMember{Attribute: "country", Value: "de"}

	before := build(principal, staff, protection.AttributeMember{Attribute: "principal", Value: "service"})
	out, err := before.Authenticate(ctx, r)
	if err != nil || out.Identity == nil {
		t.Fatalf("ambient: identity=%v err=%v", out.Identity, err)
	}
	if want := []string{"custom.groups:staff", "principal:user"}; !slices.Equal(out.Identity.Matches, want) {
		t.Errorf("ambient matches: got %v, want %v", out.Identity.Matches, want)
	}
	alias, err := before.AuthenticateAmbient(ctx, r)
	if err != nil || alias.Identity == nil || !slices.Equal(alias.Identity.Matches, out.Identity.Matches) {
		t.Errorf("alias matches: %+v err=%v", alias.Identity, err)
	}

	rr := httptest.NewRecorder()
	before.handleLogin(rr, r)
	cookie := rr.Result().Cookies()[0]

	// A member added to the config: at once on the ambient path, not
	// for the login-path session.
	after := build(principal, staff, country)
	out, err = after.Authenticate(ctx, r)
	if err != nil || out.Identity == nil {
		t.Fatalf("ambient: identity=%v err=%v", out.Identity, err)
	}
	if want := []string{"country:de", "custom.groups:staff", "principal:user"}; !slices.Equal(out.Identity.Matches, want) {
		t.Errorf("ambient matches after the change: got %v, want %v", out.Identity.Matches, want)
	}
	viaCookie := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
	viaCookie.AddCookie(cookie)
	out, err = after.Authenticate(ctx, viaCookie)
	if err != nil || out.Identity == nil {
		t.Fatalf("session: identity=%v err=%v", out.Identity, err)
	}
	if want := []string{"custom.groups:staff", "principal:user"}; !slices.Equal(out.Identity.Matches, want) {
		t.Errorf("session matches: got %v, want %v", out.Identity.Matches, want)
	}

	// A service token is principal=service and has no email.
	svc := newTestProvider(t, Config{
		VerifyJWT: true, TeamDomain: "team.test", AllowServiceTokens: true,
		GrantMembers: []protection.AttributeMember{principal, {Attribute: "principal", Value: "service"}, {Attribute: "email", Value: "alice@example.com"}},
	})
	svc.SetVerifier(stubVerifier{commonName: "abc123.access"})
	out, err = svc.Authenticate(ctx, r)
	if err != nil || out.Identity == nil {
		t.Fatalf("service token: identity=%v err=%v", out.Identity, err)
	}
	if want := []string{"principal:service"}; !slices.Equal(out.Identity.Matches, want) {
		t.Errorf("service token matches: got %v, want %v", out.Identity.Matches, want)
	}
}

// TestProvider_SubjectKind: a person's subject is the email Cloudflare
// Access authenticated them with; a service token's is its client id,
// a raw subject. The identity says which — on a request carrying the
// assertion and from a session — so that a grants member naming an
// email address can only ever match a person.
func TestProvider_SubjectKind(t *testing.T) {
	tests := []struct {
		name        string
		verifier    stubVerifier
		wantSubject string
		wantIsEmail bool
	}{
		{"a person", stubVerifier{email: "alice@example.com"}, "alice@example.com", true},
		{"a service token", stubVerifier{commonName: "ci-bot.access"}, "ci-bot.access", false},
		{"a service token whose id looks like an address", stubVerifier{commonName: "alice@example.com"}, "alice@example.com", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := newTestProvider(t, Config{VerifyJWT: true, TeamDomain: "team.test", AllowServiceTokens: true})
			p.SetVerifier(tc.verifier)

			ambient := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
			ambient.Header.Set(cfaccess.DefaultJWTHeader, "non-empty")
			out, err := p.Authenticate(context.Background(), ambient)
			if err != nil || out.Identity == nil {
				t.Fatalf("ambient: %v %+v", err, out)
			}
			if out.Identity.Subject != tc.wantSubject || out.Identity.SubjectIsEmail != tc.wantIsEmail {
				t.Errorf("ambient identity: %+v", out.Identity)
			}

			login := httptest.NewRequest(http.MethodGet, DefaultLoginPath, nil)
			login.Header.Set(cfaccess.DefaultJWTHeader, "non-empty")
			rr := httptest.NewRecorder()
			p.handleLogin(rr, login)
			cookies := rr.Result().Cookies()
			if rr.Code != http.StatusFound || len(cookies) != 1 {
				t.Fatalf("login: status %d cookies %v", rr.Code, cookies)
			}
			bare := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
			bare.AddCookie(cookies[0])
			out, err = p.Authenticate(context.Background(), bare)
			if err != nil || out.Identity == nil {
				t.Fatalf("session: %v %+v", err, out)
			}
			if out.Identity.Subject != tc.wantSubject || out.Identity.SubjectIsEmail != tc.wantIsEmail {
				t.Errorf("session identity: %+v", out.Identity)
			}
		})
	}
}

// TestProvider_LoginRefusedWhenSessionDoesNotFitACookie: see the oidc
// provider's test of the same name.
func TestProvider_LoginRefusedWhenSessionDoesNotFitACookie(t *testing.T) {
	p := newTestProvider(t, Config{VerifyJWT: true, TeamDomain: "team.test"})
	p.SetVerifier(stubVerifier{email: strings.Repeat("e", 4000) + "@example.com"})

	r := httptest.NewRequest(http.MethodGet, DefaultLoginPath, nil)
	r.Header.Set(cfaccess.DefaultJWTHeader, "non-empty")
	rr := httptest.NewRecorder()
	p.handleLogin(rr, r)
	if rr.Code != http.StatusForbidden || len(rr.Result().Cookies()) != 0 ||
		!strings.Contains(rr.Body.String(), "too long to be stored in a session cookie") {
		t.Errorf("status %d, cookies %v, body %q", rr.Code, rr.Result().Cookies(), rr.Body.String())
	}
}

// TestProvider_AmbientMatchesAreNotCutToACookie: an identity
// authenticated from the Access headers is stored nowhere, so every
// grants member it satisfies counts — also beyond what a session cookie
// could hold. At the login entry, where a cookie is written, the list
// is bounded and the log says so.
func TestProvider_AmbientMatchesAreNotCutToACookie(t *testing.T) {
	const n = 3 * protection.MaxMatches
	members := make([]protection.AttributeMember, 0, n)
	values := make([]string, 0, n)
	for i := range n {
		v := fmt.Sprintf("group-%03d", i)
		values = append(values, v)
		members = append(members, protection.AttributeMember{Attribute: "custom.groups", Value: v})
	}
	token := accessToken(t, map[string]any{"email": "alice@example.com", "custom": map[string]any{"groups": values}})

	log, hook := test.NewNullLogger()
	p := New(log, Config{VerifyJWT: true, TeamDomain: "team.test", SessionKey: testSessionKey, GrantMembers: members})
	p.SetVerifier(stubVerifier{email: "alice@example.com"})

	ambient := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
	ambient.Header.Set(cfaccess.DefaultJWTHeader, token)
	out, err := p.Authenticate(context.Background(), ambient)
	if err != nil || out.Identity == nil {
		t.Fatalf("ambient: %v %+v", err, out)
	}
	if len(out.Identity.Matches) != n {
		t.Errorf("ambient: %d of %d matches kept", len(out.Identity.Matches), n)
	}
	if len(hook.AllEntries()) != 0 {
		t.Errorf("the ambient path logged: %v", hook.AllEntries())
	}

	login := httptest.NewRequest(http.MethodGet, DefaultLoginPath, nil)
	login.Header.Set(cfaccess.DefaultJWTHeader, token)
	rr := httptest.NewRecorder()
	p.handleLogin(rr, login)
	if rr.Code != http.StatusFound || len(rr.Result().Cookies()) != 1 {
		t.Fatalf("login: status %d", rr.Code)
	}
	truncated := 0
	for _, e := range hook.AllEntries() {
		if e.Level == logrus.WarnLevel && strings.Contains(e.Message, "truncating") {
			truncated++
			if e.Data["dropped"] != n-protection.MaxMatches {
				t.Errorf("dropped: %v", e.Data["dropped"])
			}
		}
	}
	if truncated != 1 {
		t.Errorf("the login did not log the truncation once: %v", hook.AllEntries())
	}
	bare := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
	bare.AddCookie(rr.Result().Cookies()[0])
	out, err = p.Authenticate(context.Background(), bare)
	if err != nil || out.Identity == nil || len(out.Identity.Matches) != protection.MaxMatches {
		t.Errorf("session: %v %+v", err, out.Identity)
	}
}
