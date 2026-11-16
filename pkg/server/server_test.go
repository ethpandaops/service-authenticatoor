package server

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"

	"github.com/ethpandaops/service-authenticatoor/pkg/auth"
	"github.com/ethpandaops/service-authenticatoor/pkg/cfaccess"
	"github.com/ethpandaops/service-authenticatoor/pkg/config"
	"github.com/ethpandaops/service-authenticatoor/pkg/issuer"
	"github.com/ethpandaops/service-authenticatoor/pkg/protection"
	"github.com/ethpandaops/service-authenticatoor/pkg/protection/basic"
	"github.com/ethpandaops/service-authenticatoor/pkg/protection/cloudflare"
	"github.com/ethpandaops/service-authenticatoor/pkg/protection/oidc"
	"github.com/ethpandaops/service-authenticatoor/pkg/protection/oidc/oidctest"
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

// plainIssuer implements issuer.Issuer as it was before the teams claim
// — no IssueFor.
type plainIssuer struct{ issuer.Issuer }

// TestNew_RequiresIdentityIssuer: Options.Issuer keeps its plain type
// for compatibility, but an issuer that cannot take the identity's
// teams is refused at construction rather than silently used.
func TestNew_RequiresIdentityIssuer(t *testing.T) {
	s, iss, prov := newTestServer(t)
	log := logrus.New()
	log.SetOutput(io.Discard)

	_, err := New(Options{
		Config:    s.cfg,
		Issuer:    plainIssuer{Issuer: iss},
		Providers: []NamedProvider{{Name: "fake", Provider: prov}},
		Log:       log,
	})
	if err == nil || !strings.Contains(err.Error(), "IdentityIssuer") {
		t.Fatalf("New: got %v, want an IdentityIssuer error", err)
	}
}

// noToken stands in tables for the services claim of an identity that
// no grants group names: there is no claim, because no token is issued.
const noToken = "(no token)"

// minted is what a token endpoint gave a user: the identity and the
// services claim of the token, or — with Services == noToken — the
// identity as /auth/userinfo reports it.
type minted struct {
	Subject  string
	Email    string
	Teams    []string
	Services string
}

// userinfo is the answer of /auth/userinfo as these tests read it.
type userinfo struct {
	Email   string   `json:"email"`
	Sub     string   `json:"sub"`
	Teams   []string `json:"teams"`
	Granted *bool    `json:"granted"`
}

// assertNotGranted checks the answer of a token endpoint (/auth/token,
// /<name>/token) to a user who is logged in but named by no group: 403
// in the form of the endpoint's other errors, and nothing that sends a
// client to a login.
func assertNotGranted(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403 (location %q, body %s)", rr.Code, rr.Header().Get("Location"), rr.Body.String())
	}
	if got := rr.Header().Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Errorf("Content-Type %q", got)
	}
	if got := strings.TrimSpace(rr.Body.String()); got != notGrantedMessage {
		t.Errorf("body %q", got)
	}
	if loc := rr.Header().Get("Location"); loc != "" {
		t.Errorf("redirected to %q", loc)
	}
	if got := rr.Header().Get("WWW-Authenticate"); got != "" {
		t.Errorf("challenge %q", got)
	}
	if got := rr.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control %q", got)
	}
	// The session stays: nothing is cleared.
	if cookies := rr.Result().Cookies(); len(cookies) != 0 {
		t.Errorf("cookies: %v", cookies)
	}
}

// userinfo calls /auth/userinfo with the credentials of req.
func (h *teamsHarness) userinfo(req *http.Request, cookies ...*http.Cookie) userinfo {
	h.t.Helper()
	probe := httptest.NewRequest(http.MethodGet, "/auth/userinfo", nil)
	probe.Header = req.Header.Clone()
	rr := h.do(probe, cookies...)
	if rr.Code != http.StatusOK {
		h.t.Fatalf("/auth/userinfo: status %d, body %s", rr.Code, rr.Body.String())
	}
	var info userinfo
	if err := json.Unmarshal(rr.Body.Bytes(), &info); err != nil {
		h.t.Fatalf("decode userinfo: %v", err)
	}
	if info.Granted == nil {
		h.t.Fatalf("userinfo has no granted field: %s", rr.Body.String())
	}
	return info
}

// mint calls /auth/token with req. It returns the claims of the token,
// or, when the answer is the refusal for want of a grant, the identity
// from /auth/userinfo with Services == noToken. Either way it checks
// that userinfo's "granted" agrees.
func (h *teamsHarness) mint(req *http.Request, cookies ...*http.Cookie) minted {
	h.t.Helper()
	info := h.userinfo(req, cookies...)
	if len(info.Teams) == 0 {
		info.Teams = nil
	}

	rr := h.do(req, cookies...)
	if rr.Code == http.StatusForbidden {
		assertNotGranted(h.t, rr)
		if *info.Granted {
			h.t.Errorf("no token, but userinfo says granted: true")
		}
		return minted{Subject: info.Sub, Email: info.Email, Teams: info.Teams, Services: noToken}
	}
	if rr.Code != http.StatusOK {
		h.t.Fatalf("/auth/token: status %d, location %q, body %s", rr.Code, rr.Header().Get("Location"), rr.Body.String())
	}
	var resp tokenResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		h.t.Fatalf("decode token response: %v", err)
	}
	claims := h.verify(resp.Token)
	if !*info.Granted {
		h.t.Errorf("a token, but userinfo says granted: false")
	}
	if info.Sub != claims.Subject || info.Email != claims.Email || !slices.Equal(info.Teams, claims.Teams) {
		h.t.Errorf("userinfo %+v and the token (sub %q email %q teams %v) disagree",
			info, claims.Subject, claims.Email, claims.Teams)
	}
	return minted{Subject: claims.Subject, Email: claims.Email, Teams: claims.Teams, Services: claims.Services}
}

// refusals returns the "no token issued" log lines since the last call.
func (h *teamsHarness) refusals() []*logrus.Entry {
	var out []*logrus.Entry
	for _, e := range h.logs.AllEntries() {
		if strings.HasPrefix(e.Message, "no token issued") {
			out = append(out, e)
		}
	}
	h.logs.Reset()
	return out
}

const (
	appURL    = "https://app.test.example/page?x=1"
	appOrigin = "https://app.test.example"
)

func loginRequest() *http.Request {
	return httptest.NewRequest(http.MethodGet, "/auth/login?return_to="+url.QueryEscape(appURL), nil)
}

func embedRequest() *http.Request {
	return httptest.NewRequest(http.MethodGet, "/auth/embed?target_origin="+url.QueryEscape(appOrigin), nil)
}

// notGrantedSection names the team "panda" at the given providers, and
// nobody else.
func notGrantedSection(providers ...string) *issuer.GrantsConfig {
	members := make([]string, 0, len(providers))
	for _, name := range providers {
		members = append(members, name+"/team:panda")
	}
	return &issuer.GrantsConfig{Groups: []issuer.GrantGroup{{
		Name: "staff", Members: members, Services: []string{"dora"},
	}}}
}

// TestNotGranted_EveryMintSite: with a grants section, a user who is
// logged in but named by no group gets no token from any endpoint that
// mints one, through any kind of provider — and the answer never sends
// them to a login. A user the section names gets a token from each of
// the same requests.
func TestNotGranted_EveryMintSite(t *testing.T) {
	type door struct {
		name     string
		provider string
		subject  string
		// credentials returns what authenticates a request at this
		// door: headers to set, and cookies to send.
		credentials func(t *testing.T, h *teamsHarness) (func(*http.Request), []*http.Cookie)
		providers   func(t *testing.T, teams ...string) []NamedProvider
	}
	idp := oidctest.New(t, oidctest.User{Subject: "u1", Email: "mallory@example.org", Groups: []string{"team:reth"}})
	oidcDoor := func(_ *testing.T, teams ...string) []NamedProvider {
		return []NamedProvider{newOIDCProvider(idp, "oidc", oidc.Config{Teams: teams, Bearer: bearerOn()})}
	}
	doors := []door{
		{
			"oidc browser session", "oidc", "mallory@example.org",
			func(_ *testing.T, h *teamsHarness) (func(*http.Request), []*http.Cookie) {
				return func(*http.Request) {}, []*http.Cookie{h.oidcLogin(idp, "oidc")}
			},
			oidcDoor,
		},
		{
			"cloudflare ambient header", "cfaccess", "mallory@example.org",
			func(*testing.T, *teamsHarness) (func(*http.Request), []*http.Cookie) {
				return func(r *http.Request) { r.Header.Set(cloudflare.DefaultUserHeader, "mallory@example.org") }, nil
			},
			func(_ *testing.T, teams ...string) []NamedProvider {
				return []NamedProvider{newCloudflareProvider("cfaccess", teams...)}
			},
		},
		{
			"basic credentials", "htpasswd", "alice",
			func(*testing.T, *teamsHarness) (func(*http.Request), []*http.Cookie) {
				return func(r *http.Request) { r.SetBasicAuth("alice", "hunter2") }, nil
			},
			func(t *testing.T, teams ...string) []NamedProvider {
				return []NamedProvider{newBasicProvider(t, "htpasswd", teams...)}
			},
		},
		{
			"basic session cookie", "htpasswd", "alice",
			func(t *testing.T, h *teamsHarness) (func(*http.Request), []*http.Cookie) {
				login := httptest.NewRequest(http.MethodGet, "/htpasswd/login?return_to=%2Fauth%2Ftoken", nil)
				login.SetBasicAuth("alice", "hunter2")
				cookies := liveCookies(h.do(login))
				if len(cookies) != 1 {
					t.Fatalf("login cookies: %v", cookies)
				}
				return func(*http.Request) {}, cookies
			},
			func(t *testing.T, teams ...string) []NamedProvider {
				return []NamedProvider{newBasicProvider(t, "htpasswd", teams...)}
			},
		},
	}

	for _, d := range doors {
		t.Run(d.name, func(t *testing.T) {
			h := newSectionHarness(t, notGrantedSection(d.provider), "", d.providers(t)...)
			authenticate, cookies := d.credentials(t, h)
			do := func(req *http.Request) *httptest.ResponseRecorder {
				authenticate(req)
				return h.do(req, cookies...)
			}
			h.refusals()

			t.Run("/auth/token", func(t *testing.T) {
				assertNotGranted(t, do(tokenRequest()))
				// As the v2 client frame asks: a background fetch.
				req := tokenRequest()
				req.Header.Set("Sec-Fetch-Dest", "empty")
				assertNotGranted(t, do(req))
			})

			t.Run("/auth/login", func(t *testing.T) {
				rr := do(loginRequest())
				if rr.Code != http.StatusForbidden || rr.Header().Get("Location") != "" {
					t.Fatalf("status %d, location %q", rr.Code, rr.Header().Get("Location"))
				}
				if got := rr.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
					t.Errorf("Content-Type %q", got)
				}
				if got := rr.Header().Get("Cache-Control"); got != "no-store" {
					t.Errorf("Cache-Control %q", got)
				}
				page := rr.Body.String()
				for _, want := range []string{
					"<b>" + d.subject + "</b>", "<b>" + d.provider + "</b>",
					"not permitted to use the services of this devnet", `href="/auth/logout"`,
				} {
					if !strings.Contains(page, want) {
						t.Errorf("the page lacks %q:\n%s", want, page)
					}
				}
				// Nothing on the page leads back into the round: its
				// one link is the logout, and it runs no script.
				if strings.Count(page, "href=") != 1 || strings.Contains(page, "<script") ||
					strings.Contains(page, "http-equiv") || strings.Contains(page, "app.test.example") {
					t.Errorf("the page links somewhere else, or acts on its own:\n%s", page)
				}
				if strings.Contains(page, "auth_token") || strings.Contains(page, "eyJ") {
					t.Errorf("the page carries a token:\n%s", page)
				}
				if cookies := rr.Result().Cookies(); len(cookies) != 0 {
					t.Errorf("cookies: %v", cookies)
				}
			})

			t.Run("/auth/embed", func(t *testing.T) {
				rr := do(embedRequest())
				assertNotGranted(t, rr)
				if body := rr.Body.String(); strings.Contains(body, "postMessage") || strings.Contains(body, "eyJ") {
					t.Errorf("the embed answer posts something: %s", body)
				}
			})

			t.Run("/auth/userinfo", func(t *testing.T) {
				req := httptest.NewRequest(http.MethodGet, "/auth/userinfo", nil)
				authenticate(req)
				info := h.userinfo(req, cookies...)
				if info.Sub != d.subject || *info.Granted {
					t.Errorf("userinfo: %+v granted=%t, want %q and granted false", info, *info.Granted, d.subject)
				}
			})

			t.Run("one Info line per refusal", func(t *testing.T) {
				// /auth/token twice, /auth/login, /auth/embed; userinfo
				// mints nothing and logs nothing.
				lines := h.refusals()
				if len(lines) != 4 {
					t.Fatalf("%d lines, want 4", len(lines))
				}
				endpoints := make([]string, 0, len(lines))
				for _, e := range lines {
					if e.Level != logrus.InfoLevel || e.Data["sub"] != d.subject || e.Data["provider"] != d.provider {
						t.Errorf("line %q: level %s, fields %v", e.Message, e.Level, e.Data)
					}
					endpoints = append(endpoints, e.Data["endpoint"].(string))
				}
				if !slices.Equal(endpoints, []string{"token", "token", "login", "embed"}) {
					t.Errorf("endpoints: %v", endpoints)
				}
			})

			// The control: the same requests of a user the section
			// names. Without it everything above would also pass on a
			// server that refuses everybody.
			t.Run("a named user gets a token from each", func(t *testing.T) {
				named := newSectionHarness(t, notGrantedSection(d.provider), "", d.providers(t, "panda")...)
				authenticate, cookies := d.credentials(t, named)
				do := func(req *http.Request) *httptest.ResponseRecorder {
					authenticate(req)
					return named.do(req, cookies...)
				}
				req := tokenRequest()
				authenticate(req)
				if got := named.mint(req, cookies...); got.Services != "-all,+dora" || got.Subject != d.subject {
					t.Errorf("/auth/token: %+v", got)
				}
				rr := do(loginRequest())
				if rr.Code != http.StatusFound || !strings.HasPrefix(rr.Header().Get("Location"), appURL+"#auth_token=") {
					t.Errorf("/auth/login: %d → %q", rr.Code, rr.Header().Get("Location"))
				}
				rr = do(embedRequest())
				if rr.Code != http.StatusOK || named.verify(embeddedToken(t, rr.Body.String())).Services != "-all,+dora" {
					t.Errorf("/auth/embed: %d", rr.Code)
				}
				if lines := named.refusals(); len(lines) != 0 {
					t.Errorf("refusals logged for a named user: %d", len(lines))
				}
			})
		})
	}
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

// teamsHarness is a Server built from real providers, the real issuer
// and a real pkg/auth verifier fed from the server's own /jwks.json — the
// same pieces a deployment and a resource server use.
type teamsHarness struct {
	t        *testing.T
	handler  http.Handler
	verifier *auth.JWKSVerifier
	jwksURL  string
	issuer   string
	// logs records what the server logged.
	logs *logtest.Hook
}

// identityIssuerOnly is the issuer of every harness: the real one, with
// a plain Issue that fails the test. Issue mints for an identity no
// grants group names; nothing that serves a user may reach it.
type identityIssuerOnly struct {
	issuer.IdentityIssuer
	t *testing.T
}

func (i identityIssuerOnly) Issue(subject, _ string, _ []string) (string, *auth.Claims, error) {
	i.t.Errorf("the server called the plain Issue for %q; it must mint through IssueFor only", subject)
	return "", nil, errors.New("plain Issue is not for the server")
}

// newTeamsHarness starts the given providers and wires them into a
// Server. Each provider gets its own session key, as in main.go.
func newTeamsHarness(t *testing.T, providers ...NamedProvider) *teamsHarness {
	t.Helper()
	return newGrantsHarness(t, nil, "", providers...)
}

// newGrantsHarness is newTeamsHarness with a table of team grants
// (nil: section absent) and an instance-wide services directive.
func newGrantsHarness(
	t *testing.T, teamServices map[string][]string, instanceWide string, providers ...NamedProvider,
) *teamsHarness {
	t.Helper()

	// These tables map a team to its grants. Each becomes a group whose
	// members are that team at every provider of the harness: the tests
	// using them are about the claim, not about which door a team came
	// through.
	var section *issuer.GrantsConfig
	if teamServices != nil {
		section = &issuer.GrantsConfig{}
		for _, team := range slices.Sorted(maps.Keys(teamServices)) {
			members := make([]string, 0, len(providers))
			for _, np := range providers {
				members = append(members, np.Name+"/team:"+team)
			}
			section.Groups = append(section.Groups, issuer.GrantGroup{Members: members, Services: teamServices[team]})
		}
	}
	return newSectionHarness(t, section, instanceWide, providers...)
}

// sectionGrants validates a grants section for providers of these names
// (each accepting any attribute).
func sectionGrants(t *testing.T, section issuer.GrantsConfig, providers ...string) *issuer.ServiceGrants {
	t.Helper()
	described := make([]issuer.Provider, 0, len(providers))
	for _, name := range providers {
		described = append(described, issuer.Provider{Name: name})
	}
	g, err := issuer.NewServiceGrants(section, described)
	if err != nil {
		t.Fatalf("grants: %v", err)
	}
	return g
}

// newSectionHarness is newTeamsHarness with a grants section (nil:
// absent) and an instance-wide services directive.
func newSectionHarness(
	t *testing.T, section *issuer.GrantsConfig, instanceWide string, providers ...NamedProvider,
) *teamsHarness {
	t.Helper()

	var grants *issuer.ServiceGrants
	if section != nil {
		names := make([]string, 0, len(providers))
		for _, np := range providers {
			names = append(names, np.Name)
		}
		grants = sectionGrants(t, *section, names...)
	}

	cfg := &config.Config{
		Listen:             ":0",
		Issuer:             "https://auth.test.example",
		ExternalURL:        "https://auth.test.example",
		Audience:           []string{"test.example"},
		ScopePattern:       "*.test.example",
		TokenTTL:           30 * time.Minute,
		AllowedReturnHosts: []string{"*.test.example"},
		CORS:               config.CORSConfig{AllowedOrigins: []string{"*.test.example"}},
		Signing:            config.SigningConfig{Mode: "rs256"},
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
		Services:        instanceWide,
		Grants:          grants,
		TTL:             cfg.TokenTTL,
	})
	if err != nil {
		t.Fatalf("newissuer: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	for _, np := range providers {
		if err := np.Provider.Start(ctx); err != nil {
			t.Fatalf("start provider %s: %v", np.Name, err)
		}
	}

	log := logrus.New()
	log.SetOutput(io.Discard)
	logs := logtest.NewLocal(log)
	s, err := New(Options{
		Config:    cfg,
		Issuer:    identityIssuerOnly{IdentityIssuer: iss, t: t},
		Providers: providers,
		Log:       log,
		Registry:  prometheus.NewRegistry(),
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	handler := s.routes()

	jwks := httptest.NewServer(handler)
	t.Cleanup(jwks.Close)
	verifier, err := auth.NewJWKSVerifier(ctx, auth.VerifierConfig{
		JWKSURL:          jwks.URL + "/jwks.json",
		ExpectedIssuer:   cfg.Issuer,
		ExpectedAudience: "test.example",
	})
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	return &teamsHarness{
		t: t, handler: handler, verifier: verifier,
		jwksURL: jwks.URL + "/jwks.json", issuer: cfg.Issuer, logs: logs,
	}
}

// rawToken calls /auth/token and returns the token string.
func (h *teamsHarness) rawToken(req *http.Request, cookies ...*http.Cookie) string {
	h.t.Helper()
	rr := h.do(req, cookies...)
	if rr.Code != http.StatusOK {
		h.t.Fatalf("/auth/token: status %d, body %s", rr.Code, rr.Body.String())
	}
	var resp tokenResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		h.t.Fatalf("decode token response: %v", err)
	}
	return resp.Token
}

// serviceVerifier builds the verifier of a resource server that gates on
// its own service name, as spamoor, assertoor and dora do.
func (h *teamsHarness) serviceVerifier(service string) *auth.JWKSVerifier {
	h.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	h.t.Cleanup(cancel)
	v, err := auth.NewJWKSVerifier(ctx, auth.VerifierConfig{
		JWKSURL:          h.jwksURL,
		ExpectedIssuer:   h.issuer,
		ExpectedAudience: "test.example",
		ExpectedService:  service,
	})
	if err != nil {
		h.t.Fatalf("new verifier for %s: %v", service, err)
	}
	return v
}

// do serves one request, carrying the given cookies.
func (h *teamsHarness) do(req *http.Request, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	h.t.Helper()
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	h.handler.ServeHTTP(rr, req)
	return rr
}

// verify checks a token the way a resource server does and returns its
// claims.
func (h *teamsHarness) verify(token string) *auth.Claims {
	h.t.Helper()
	claims, err := h.verifier.Verify(token)
	if err != nil {
		h.t.Fatalf("verify: %v", err)
	}
	return claims
}

// token calls /auth/token and returns the verified claims of the token
// it issued.
func (h *teamsHarness) token(req *http.Request, cookies ...*http.Cookie) *auth.Claims {
	h.t.Helper()
	rr := h.do(req, cookies...)
	if rr.Code != http.StatusOK {
		h.t.Fatalf("/auth/token: status %d, location %q, body %s", rr.Code, rr.Header().Get("Location"), rr.Body.String())
	}
	var resp tokenResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		h.t.Fatalf("decode token response: %v", err)
	}
	return h.verify(resp.Token)
}

func tokenRequest() *http.Request {
	return httptest.NewRequest(http.MethodGet, "/auth/token", nil)
}

// liveCookies returns the cookies a response sets (ignoring deletions).
func liveCookies(rr *httptest.ResponseRecorder) []*http.Cookie {
	var out []*http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.MaxAge >= 0 && c.Value != "" {
			out = append(out, c)
		}
	}
	return out
}

func quietLog() logrus.FieldLogger {
	log := logrus.New()
	log.SetOutput(io.Discard)
	return log
}

// testSessionKey derives a distinct per-provider key, as main.go does.
func testSessionKey(name string) []byte {
	return []byte((name + "-0123456789abcdef0123456789abcdef")[:32])
}

func newBasicProvider(t *testing.T, name string, teams ...string) NamedProvider {
	t.Helper()
	sum := sha1.Sum([]byte("hunter2"))
	file := filepath.Join(t.TempDir(), "htpasswd")
	body := "alice:{SHA}" + base64.StdEncoding.EncodeToString(sum[:]) + "\n"
	if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
		t.Fatalf("write htpasswd: %v", err)
	}
	return NamedProvider{Name: name, Provider: basic.New(quietLog(), basic.Config{
		HtpasswdFile:      file,
		LoginPath:         "/" + name + "/login",
		SessionKey:        testSessionKey(name),
		SessionCookieName: "authenticatoor_" + name + "_session",
		Teams:             teams,
	})}
}

func newCloudflareProvider(name string, teams ...string) NamedProvider {
	return NamedProvider{Name: name, Provider: cloudflare.New(quietLog(), cloudflare.Config{
		VerifyJWT:         false, // trust the header, as behind a trusted ingress
		LoginPath:         "/" + name + "/login",
		SessionKey:        testSessionKey(name),
		SessionCookieName: "authenticatoor_" + name + "_session",
		Teams:             teams,
	})}
}

// prefixRule is the rule the central IdP setup uses: every `team:<slug>`
// group is the team <slug>.
var prefixRule = protection.TeamRule{Claim: "groups", Prefix: "team:"}

// mapRule maps values of the groups claim to teams.
func mapRule(m map[string][]string) protection.TeamRule {
	return protection.TeamRule{Claim: "groups", Map: m}
}

func teamRules(rules ...protection.TeamRule) []protection.TeamRule { return rules }

func newOIDCProvider(idp *oidctest.IdP, name string, cfg oidc.Config) NamedProvider {
	cfg.IssuerURL = idp.URL
	cfg.PublicURL = "https://auth.test.example"
	cfg.CallbackURL = "https://auth.test.example/" + name + "/callback"
	cfg.ClientID = "authenticatoor"
	cfg.ClientSecret = "client-secret"
	cfg.SessionKey = testSessionKey(name)
	cfg.LoginPath = "/" + name + "/login"
	cfg.CallbackPath = "/" + name + "/callback"
	cfg.SessionCookieName = "authenticatoor_" + name + "_session"
	cfg.StateCookieName = "authenticatoor_" + name + "_state"
	return NamedProvider{Name: name, Provider: oidc.New(quietLog(), cfg)}
}

// oidcLogin walks the browser through /<name>/login → IdP → callback and
// returns the session cookie.
func (h *teamsHarness) oidcLogin(idp *oidctest.IdP, name string) *http.Cookie {
	h.t.Helper()
	rr := h.do(httptest.NewRequest(http.MethodGet, "/"+name+"/login?return_to=%2Fauth%2Ftoken", nil))
	if rr.Code != http.StatusFound {
		h.t.Fatalf("oidc login entry: status %d", rr.Code)
	}
	state := liveCookies(rr)
	if len(state) != 1 {
		h.t.Fatalf("oidc login entry cookies: %v", state)
	}
	back := idp.Authorize(h.t, rr.Header().Get("Location"))

	rr = h.do(httptest.NewRequest(http.MethodGet, "/"+name+"/callback?"+back.Encode(), nil), state[0])
	if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/auth/token" {
		h.t.Fatalf("oidc callback: status %d location %q body %s", rr.Code, rr.Header().Get("Location"), rr.Body.String())
	}
	session := liveCookies(rr)
	if len(session) != 1 {
		h.t.Fatalf("oidc callback cookies: %v", session)
	}
	return session[0]
}

// embeddedToken pulls the token out of the /auth/embed page's JSON blob.
func embeddedToken(t *testing.T, page string) string {
	t.Helper()
	const open = `<script id="d" type="application/json">`
	start := strings.Index(page, open)
	if start < 0 {
		t.Fatalf("embed page has no payload: %s", page)
	}
	rest := page[start+len(open):]
	end := strings.Index(rest, "</script>")
	if end < 0 {
		t.Fatalf("embed page payload is not closed: %s", page)
	}
	var payload struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal([]byte(rest[:end]), &payload); err != nil {
		t.Fatalf("decode embed payload: %v", err)
	}
	return payload.Token
}

// accessVerifier stands in for the Cloudflare JWKS check: it accepts any
// assertion and reports the identity the test put into it.
type accessVerifier struct{}

func (accessVerifier) Verify(_ context.Context, token string) (*cfaccess.Claims, error) {
	attrs, err := protection.TokenAttributes(token)
	if err != nil {
		return nil, err
	}
	claims := &cfaccess.Claims{}
	claims.Email, _ = attrs["email"].(string)
	claims.CommonName, _ = attrs["common_name"].(string)
	return claims, nil
}

// unstartedCloudflare is a Cloudflare provider whose Start does nothing:
// the real one fetches the team's JWKS, which the stub verifier
// replaces.
type unstartedCloudflare struct{ *cloudflare.Provider }

func (unstartedCloudflare) Start(context.Context) error { return nil }

// accessAssertion builds a Cf-Access-Jwt-Assertion value with the given
// claims.
func accessAssertion(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return "e30." + base64.RawURLEncoding.EncodeToString(payload) + ".c2ln"
}
