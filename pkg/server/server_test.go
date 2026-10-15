package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"

	"github.com/ethpandaops/service-authenticatoor/pkg/config"
	"github.com/ethpandaops/service-authenticatoor/pkg/issuer"
	"github.com/ethpandaops/service-authenticatoor/pkg/protection"
)

// fakeProvider is a minimal protection.Provider used by server tests. It
// reads an email out of a configurable header — same trust model as the
// CF Access provider with VerifyJWT disabled, but without the CF imports.
// VerifyHeader, when non-empty, must also be present (any non-empty
// value) for authentication to succeed; this lets tests exercise the
// "missing assertion" path that the real CF provider enforces via JWKS.
// A non-empty loginPath makes the unauthenticated outcome a redirect
// there (like the cookie-shaped providers) instead of a 401.
type fakeProvider struct {
	emailHeader  string
	verifyHeader string
	loginPath    string
	challenge    http.Header
}

func (p *fakeProvider) Name() string                  { return "fake" }
func (p *fakeProvider) Start(_ context.Context) error { return nil }
func (p *fakeProvider) Stop() error                   { return nil }
func (p *fakeProvider) RegisterRoutes(_ *mux.Router)  {}
func (p *fakeProvider) Logout(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"loggedOut":true}`))
}

func (p *fakeProvider) LoginURL(returnTo string) string {
	if p.loginPath == "" {
		return ""
	}
	return p.loginPath + "?" + url.Values{"return_to": {returnTo}}.Encode()
}

func (p *fakeProvider) Authenticate(_ context.Context, r *http.Request) (protection.Outcome, error) {
	if p.verifyHeader != "" && r.Header.Get(p.verifyHeader) == "" {
		return protection.Outcome{Status: http.StatusUnauthorized}, nil
	}
	email := r.Header.Get(p.emailHeader)
	if email == "" {
		if p.loginPath != "" {
			return protection.Outcome{RedirectTo: p.LoginURL(r.URL.RequestURI())}, nil
		}
		return protection.Outcome{Status: http.StatusUnauthorized, Challenge: p.challenge}, nil
	}
	return protection.Outcome{Identity: &protection.Identity{
		Subject: email,
		Email:   email,
	}}, nil
}

// newTestServer builds a Server with a fake provider that reads identity
// from X-Test-Email — the same trust model the previous CF-with-verify-off
// setup had, without any CF-specific machinery in tests.
func newTestServer(t *testing.T) (*Server, *issuer.RS256Issuer, *fakeProvider) {
	t.Helper()

	cfg := &config.Config{
		Listen:             ":0",
		Issuer:             "https://auth.test.example",
		ExternalURL:        "https://auth.test.example",
		AuthMode:           []string{config.AuthModeCloudflare},
		Audience:           []string{"test.example"},
		ScopePattern:       "*.test.example",
		TokenTTL:           30 * time.Minute,
		AllowedReturnHosts: []string{"*.test.example"},
		CORS: config.CORSConfig{
			AllowedOrigins: []string{"*.test.example"},
		},
		Signing: config.SigningConfig{Mode: "rs256"},
	}

	key, err := issuer.GenerateRSAKey()
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	iss, err := issuer.NewRS256Issuer(issuer.Config{
		ActiveKey:       key,
		Issuer:          cfg.Issuer,
		DefaultAudience: cfg.Audience,
		Scope:           cfg.ScopePattern,
		TTL:             cfg.TokenTTL,
	})
	if err != nil {
		t.Fatalf("newissuer: %v", err)
	}

	log := logrus.New()
	log.SetOutput(io.Discard)

	prov := &fakeProvider{emailHeader: "X-Test-Email"}
	s, err := New(Options{
		Config:    cfg,
		Issuer:    iss,
		Providers: []NamedProvider{{Name: "fake", Provider: prov}},
		Log:       log,
		Registry:  prometheus.NewRegistry(),
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	return s, iss, prov
}

func TestHandleHealth(t *testing.T) {
	s, _, _ := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status: got %d", rr.Code)
	}
	if !strings.HasPrefix(rr.Body.String(), "ok") {
		t.Errorf("body: got %q", rr.Body.String())
	}
}

func TestHandleJWKS(t *testing.T) {
	s, _, _ := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/jwks.json", nil)
	rr := httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status: %d", rr.Code)
	}
	var jwks issuer.JWKS
	if err := json.Unmarshal(rr.Body.Bytes(), &jwks); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(jwks.Keys) == 0 {
		t.Error("no keys in jwks")
	}
}

func TestHandleOIDCConfig(t *testing.T) {
	s, _, _ := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rr := httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status: %d", rr.Code)
	}
	var doc struct {
		Issuer  string   `json:"issuer"`
		JWKSURI string   `json:"jwks_uri"`
		Algs    []string `json:"id_token_signing_alg_values_supported"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if doc.Issuer != "https://auth.test.example" {
		t.Errorf("issuer: got %q", doc.Issuer)
	}
	if doc.JWKSURI != "https://auth.test.example/jwks.json" {
		t.Errorf("jwks_uri: got %q", doc.JWKSURI)
	}
	if len(doc.Algs) != 1 || doc.Algs[0] != "RS256" {
		t.Errorf("algs: got %v", doc.Algs)
	}
}

func TestHandleToken_Success(t *testing.T) {
	s, _, _ := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
	req.Header.Set("X-Test-Email", "alice@example.com")
	rr := httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status: %d, body: %s", rr.Code, rr.Body.String())
	}
	var resp tokenResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Token == "" {
		t.Error("empty token")
	}
	if resp.User != "alice@example.com" {
		t.Errorf("user: %q", resp.User)
	}
	if resp.Expr <= resp.Now {
		t.Errorf("expr (%d) should be after now (%d)", resp.Expr, resp.Now)
	}
}

func TestHandleToken_NoEmail(t *testing.T) {
	s, _, _ := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
	rr := httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want 401", rr.Code)
	}
}

func TestHandleToken_AudienceFiltering(t *testing.T) {
	s, _, _ := newTestServer(t)

	// Allowed audience
	req := httptest.NewRequest(http.MethodGet, "/auth/token?aud=test.example", nil)
	req.Header.Set("X-Test-Email", "alice@example.com")
	rr := httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("allowed aud got status %d", rr.Code)
	}

	// Disallowed audience
	req = httptest.NewRequest(http.MethodGet, "/auth/token?aud=evil.example", nil)
	req.Header.Set("X-Test-Email", "alice@example.com")
	rr = httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("disallowed aud got status %d, want 400", rr.Code)
	}
}

func TestHandleLogin_Success(t *testing.T) {
	s, _, _ := newTestServer(t)

	q := url.Values{"return_to": {"https://app.test.example/foo"}}
	req := httptest.NewRequest(http.MethodGet, "/auth/login?"+q.Encode(), nil)
	req.Header.Set("X-Test-Email", "alice@example.com")
	rr := httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("status: %d, body: %s", rr.Code, rr.Body.String())
	}
	loc := rr.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://app.test.example/foo#") {
		t.Errorf("location: got %q", loc)
	}
	if !strings.Contains(loc, "auth_token=") {
		t.Errorf("location missing auth_token: %q", loc)
	}
	if !strings.Contains(loc, "exp=") {
		t.Errorf("location missing exp: %q", loc)
	}
	if !strings.Contains(loc, "user=alice%40example.com") {
		t.Errorf("location missing user (URL-encoded): %q", loc)
	}
}

func TestHandleLogin_DisallowedReturnTo(t *testing.T) {
	s, _, _ := newTestServer(t)

	cases := []string{
		"https://evil.com/",
		"https://test.example.attacker.com/",
		"javascript:alert(1)",
		"https://attacker.com@victim.test.example/", // userinfo trick — this goes to victim, which IS allowed
	}

	for _, returnTo := range cases {
		t.Run(returnTo, func(t *testing.T) {
			q := url.Values{"return_to": {returnTo}}
			req := httptest.NewRequest(http.MethodGet, "/auth/login?"+q.Encode(), nil)
			req.Header.Set("X-Test-Email", "alice@example.com")
			rr := httptest.NewRecorder()
			s.routes().ServeHTTP(rr, req)

			// The userinfo trick produces an allowed host (victim.test.example) so 302 is fine for that one.
			if returnTo == "https://attacker.com@victim.test.example/" {
				if rr.Code != http.StatusFound {
					t.Errorf("expected 302 for userinfo trick (host extracts to allowed), got %d", rr.Code)
				}
				return
			}
			if rr.Code != http.StatusBadRequest {
				t.Errorf("status: got %d, want 400 for %q", rr.Code, returnTo)
			}
		})
	}
}

func TestHandleLogin_MissingReturnTo(t *testing.T) {
	s, _, _ := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	req.Header.Set("X-Test-Email", "alice@example.com")
	rr := httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status: got %d, want 400", rr.Code)
	}
}

func TestHandleUserinfo_Success(t *testing.T) {
	s, _, _ := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/auth/userinfo", nil)
	req.Header.Set("X-Test-Email", "alice@example.com")
	rr := httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status: %d", rr.Code)
	}
	var resp userinfoResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Email != "alice@example.com" {
		t.Errorf("email: %q", resp.Email)
	}
	if resp.Sub != "alice@example.com" {
		t.Errorf("sub: %q", resp.Sub)
	}
	if resp.Scope != "*.test.example" {
		t.Errorf("scope: %q", resp.Scope)
	}
}

// TestAuthMiddleware_ProviderRequiresExtraHeader exercises the path where
// a provider returns 401 even though identity is present in some other
// header — analogous to the real CF Access provider rejecting a request
// because the assertion JWT is missing.
func TestAuthMiddleware_ProviderRequiresExtraHeader(t *testing.T) {
	s, _, prov := newTestServer(t)
	prov.verifyHeader = "X-Test-Assertion"

	req := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
	req.Header.Set("X-Test-Email", "alice@example.com") // header present
	// X-Test-Assertion NOT present — provider rejects.
	rr := httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want 401 (provider rejected)", rr.Code)
	}

	// With the assertion header set, the same request succeeds.
	req = httptest.NewRequest(http.MethodGet, "/auth/token", nil)
	req.Header.Set("X-Test-Email", "alice@example.com")
	req.Header.Set("X-Test-Assertion", "anything-non-empty")
	rr = httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("status: got %d, want 200 with assertion present", rr.Code)
	}
}

// TestAuthMiddleware_ChallengeOnlyOnInteractiveRequests checks that the
// WWW-Authenticate challenge reaches top-level navigations and
// non-browser clients, but not background fetches or iframes — those
// would pop the browser's credential dialog on every page load.
func TestAuthMiddleware_ChallengeOnlyOnInteractiveRequests(t *testing.T) {
	s, _, prov := newTestServer(t)
	prov.challenge = http.Header{"Www-Authenticate": {`Basic realm="test"`}}

	tests := []struct {
		name      string
		path      string
		fetchDest string
		want      bool
	}{
		{"top-level login navigation", "/auth/login?return_to=x", "document", true},
		{"non-browser client", "/auth/token", "", true},
		{"frame token probe", "/auth/token", "empty", false},
		{"userinfo fetch", "/auth/userinfo", "empty", false},
		{"iframe navigation", "/auth/token", "iframe", false},
		{"embed without fetch metadata", "/auth/embed?target_origin=x", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			if tc.fetchDest != "" {
				req.Header.Set("Sec-Fetch-Dest", tc.fetchDest)
			}
			rr := httptest.NewRecorder()
			s.routes().ServeHTTP(rr, req)

			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("status: got %d, want 401", rr.Code)
			}
			got := rr.Header().Get("WWW-Authenticate") != ""
			if got != tc.want {
				t.Errorf("challenge present: got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCORS_PreflightAllowed(t *testing.T) {
	s, _, _ := newTestServer(t)

	req := httptest.NewRequest(http.MethodOptions, "/auth/token", nil)
	req.Header.Set("Origin", "https://app.test.example")
	req.Header.Set("Access-Control-Request-Method", "GET")
	rr := httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("status: got %d, want 204", rr.Code)
	}
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "https://app.test.example" {
		t.Errorf("ACAO: %q", got)
	}
	if got := rr.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Errorf("ACAC: %q", got)
	}
}

func TestCORS_PreflightDisallowedOrigin(t *testing.T) {
	s, _, _ := newTestServer(t)

	req := httptest.NewRequest(http.MethodOptions, "/auth/token", nil)
	req.Header.Set("Origin", "https://evil.com")
	req.Header.Set("Access-Control-Request-Method", "GET")
	rr := httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)

	// Preflight returns 204 either way; the security guarantee is that no
	// ACAO header is set for disallowed origins, so the browser blocks the
	// real request.
	if rr.Code != http.StatusNoContent {
		t.Errorf("status: got %d", rr.Code)
	}
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("ACAO leaked: %q", got)
	}
}

func TestHandleLogout_RunsWithoutIdentity(t *testing.T) {
	s, _, _ := newTestServer(t)

	// Logout endpoint must work even without authentication — fakeProvider
	// has a no-op Logout that writes 200, so we expect 200 with no email
	// header set.
	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	rr := httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status: got %d, want 200", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"loggedOut":true`) {
		t.Errorf("body: %q", rr.Body.String())
	}
}

func TestHandleLogout_CORSPreflightAllowed(t *testing.T) {
	s, _, _ := newTestServer(t)

	req := httptest.NewRequest(http.MethodOptions, "/auth/logout", nil)
	req.Header.Set("Origin", "https://app.test.example")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rr := httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("status: got %d, want 204", rr.Code)
	}
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "https://app.test.example" {
		t.Errorf("ACAO: %q", got)
	}
}

// ambientFakeProvider extends fakeProvider with the AmbientAuthenticator
// interface so tests can exercise the /<name>/token machine alias.
type ambientFakeProvider struct {
	fakeProvider
	ambientHeader string
}

func (p *ambientFakeProvider) AuthenticateAmbient(_ context.Context, r *http.Request) (protection.Outcome, error) {
	email := r.Header.Get(p.ambientHeader)
	if email == "" {
		return protection.Outcome{Status: http.StatusUnauthorized}, nil
	}
	return protection.Outcome{Identity: &protection.Identity{Subject: email, Email: email}}, nil
}

// newMultiProviderServer builds a Server with two providers: "first"
// (ambient-capable, reads X-First-Email / X-First-Ambient) and "second"
// (cookie-shaped with a login path, reads X-Second-Email).
func newMultiProviderServer(t *testing.T) (*Server, *ambientFakeProvider, *fakeProvider) {
	t.Helper()
	s, _, _ := newTestServer(t)

	first := &ambientFakeProvider{
		fakeProvider:  fakeProvider{emailHeader: "X-First-Email", loginPath: "/first/login"},
		ambientHeader: "X-First-Ambient",
	}
	second := &fakeProvider{emailHeader: "X-Second-Email", loginPath: "/second/login"}
	s.providers = []NamedProvider{
		{Name: "first", Provider: first},
		{Name: "second", Provider: second},
	}
	s.advertised = s.providers
	return s, first, second
}

func TestAuthChain_SecondProviderAuthenticates(t *testing.T) {
	s, _, _ := newMultiProviderServer(t)

	req := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
	req.Header.Set("X-Second-Email", "bob@example.com")
	rr := httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status: %d, body: %s", rr.Code, rr.Body.String())
	}
	var resp tokenResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.User != "bob@example.com" {
		t.Errorf("user: %q", resp.User)
	}
}

func TestAuthChain_NoProviderRedirectsToSelector(t *testing.T) {
	s, _, _ := newMultiProviderServer(t)

	req := httptest.NewRequest(http.MethodGet, "/auth/token?aud=test.example", nil)
	rr := httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("status: got %d, want 302", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.HasPrefix(loc, "/login?") {
		t.Errorf("location: got %q, want /login?...", loc)
	}
	if !strings.Contains(loc, "return_to=%2Fauth%2Ftoken%3Faud%3Dtest.example") {
		t.Errorf("location missing return_to: %q", loc)
	}
}

func TestLoginSelector_ListsProviders(t *testing.T) {
	s, _, _ := newMultiProviderServer(t)

	req := httptest.NewRequest(http.MethodGet, "/login?return_to=%2Fauth%2Ftoken", nil)
	rr := httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status: %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, `href="/first/login?return_to=%2Fauth%2Ftoken"`) {
		t.Errorf("selector missing first provider link: %s", body)
	}
	if !strings.Contains(body, `href="/second/login?return_to=%2Fauth%2Ftoken"`) {
		t.Errorf("selector missing second provider link: %s", body)
	}
}

func TestLoginSelector_SingleProviderForwards(t *testing.T) {
	s, _, prov := newTestServer(t)
	prov.loginPath = "/fake/login"

	req := httptest.NewRequest(http.MethodGet, "/login?return_to=%2Fauth%2Ftoken", nil)
	rr := httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("status: got %d, want 302", rr.Code)
	}
	if loc := rr.Header().Get("Location"); !strings.HasPrefix(loc, "/fake/login?") {
		t.Errorf("location: %q", loc)
	}
}

func TestLoginSelector_RejectsAbsoluteReturnTo(t *testing.T) {
	s, _, _ := newMultiProviderServer(t)

	req := httptest.NewRequest(http.MethodGet, "/login?return_to=https%3A%2F%2Fevil.example%2F", nil)
	rr := httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status: %d", rr.Code)
	}
	if strings.Contains(rr.Body.String(), "evil.example") {
		t.Error("absolute return_to leaked into selector links")
	}
}

func TestAmbientTokenAlias_IssuesToken(t *testing.T) {
	s, first, _ := newMultiProviderServer(t)
	_ = first

	req := httptest.NewRequest(http.MethodGet, "/first/token", nil)
	req.Header.Set("X-First-Ambient", "svc@example.com")
	rr := httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status: %d, body: %s", rr.Code, rr.Body.String())
	}
	var resp tokenResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Token == "" || resp.User != "svc@example.com" {
		t.Errorf("token=%q user=%q", resp.Token, resp.User)
	}
}

func TestAmbientTokenAlias_RejectsWithoutAmbientCredentials(t *testing.T) {
	s, _, _ := newMultiProviderServer(t)

	// Even the chain-authenticating header must not satisfy the alias.
	req := httptest.NewRequest(http.MethodGet, "/first/token", nil)
	req.Header.Set("X-First-Email", "user@example.com")
	rr := httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want 401", rr.Code)
	}
}

// TestUnadvertisedProviderStillAuthenticates pins the authMode contract:
// providers left out of authMode disappear from the selector and the
// fallback redirect, but keep authenticating in the passive chain.
func TestUnadvertisedProviderStillAuthenticates(t *testing.T) {
	s, _, _ := newMultiProviderServer(t)
	s.advertised = s.providers[:1] // only "first" is advertised

	// "second" still authenticates.
	req := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
	req.Header.Set("X-Second-Email", "bob@example.com")
	rr := httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("unadvertised provider auth: status %d", rr.Code)
	}

	// The selector only lists "first".
	req = httptest.NewRequest(http.MethodGet, "/login?return_to=%2Fauth%2Ftoken", nil)
	rr = httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("selector with one advertised provider: status %d, want 302", rr.Code)
	}
	if loc := rr.Header().Get("Location"); !strings.HasPrefix(loc, "/first/login?") {
		t.Errorf("selector redirect: %q", loc)
	}

	// The unauthenticated fallback goes straight to "first", no selector.
	req = httptest.NewRequest(http.MethodGet, "/auth/token", nil)
	rr = httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("fallback: status %d, want 302", rr.Code)
	}
	if loc := rr.Header().Get("Location"); !strings.HasPrefix(loc, "/first/login?") {
		t.Errorf("fallback redirect: %q", loc)
	}
}

func TestMultiProviderLogout_ClearsWithoutProviderDispatch(t *testing.T) {
	s, _, _ := newMultiProviderServer(t)

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	rr := httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status: %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"loggedOut":true`) {
		t.Errorf("body: %q", rr.Body.String())
	}
}

// TestServer_Lifecycle verifies the Start/Stop lifecycle.
func TestServer_Lifecycle(t *testing.T) {
	s, _, _ := newTestServer(t)
	s.cfg.Listen = "127.0.0.1:0" // ephemeral port
	// Rebuild s.main with the new addr.
	s.main.Addr = s.cfg.Listen

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Start(ctx) }()

	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after cancel")
	}
}
