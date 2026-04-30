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

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"

	"github.com/ethpandaops/service-authenticatoor/pkg/cfaccess"
	"github.com/ethpandaops/service-authenticatoor/pkg/config"
	"github.com/ethpandaops/service-authenticatoor/pkg/issuer"
)

// newTestServer builds a Server with reasonable defaults for testing,
// including a fresh issuer key and CF JWT verification disabled.
func newTestServer(t *testing.T) (*Server, *issuer.RS256Issuer) {
	t.Helper()

	cfg := &config.Config{
		Listen:             ":0",
		Issuer:             "https://auth.test.example",
		ExternalURL:        "https://auth.test.example",
		Audience:           []string{"test.example"},
		ScopePattern:       "*.test.example",
		TokenTTL:           30 * time.Minute,
		UserHeader:         "X-Test-Email",
		AllowedReturnHosts: []string{"*.test.example"},
		CORS: config.CORSConfig{
			AllowedOrigins: []string{"*.test.example"},
		},
		CloudflareAccess: config.CloudflareAccessConfig{
			VerifyJWT: false,
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

	s, err := New(Options{
		Config:     cfg,
		Issuer:     iss,
		CFVerifier: cfaccess.NoopVerifier{},
		Log:        log,
		Registry:   prometheus.NewRegistry(),
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	return s, iss
}

func TestHandleHealth(t *testing.T) {
	s, _ := newTestServer(t)

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
	s, _ := newTestServer(t)

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
	s, _ := newTestServer(t)

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
	s, _ := newTestServer(t)

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
	s, _ := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
	rr := httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want 401", rr.Code)
	}
}

func TestHandleToken_AudienceFiltering(t *testing.T) {
	s, _ := newTestServer(t)

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
	s, _ := newTestServer(t)

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
	s, _ := newTestServer(t)

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
	s, _ := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	req.Header.Set("X-Test-Email", "alice@example.com")
	rr := httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status: got %d, want 400", rr.Code)
	}
}

func TestHandleUserinfo_Success(t *testing.T) {
	s, _ := newTestServer(t)

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

func TestCFAccessMiddleware_RejectsMissingJWT(t *testing.T) {
	s, _ := newTestServer(t)
	s.cfg.CloudflareAccess.VerifyJWT = true
	s.cfg.CloudflareAccess.JwtHeader = "Cf-Access-Jwt-Assertion"

	req := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
	req.Header.Set("X-Test-Email", "alice@example.com") // header present
	// CF JWT header NOT present
	rr := httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want 401 (CF JWT missing)", rr.Code)
	}
}

func TestCORS_PreflightAllowed(t *testing.T) {
	s, _ := newTestServer(t)

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
	s, _ := newTestServer(t)

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

// TestServer_Lifecycle verifies the Start/Stop lifecycle.
func TestServer_Lifecycle(t *testing.T) {
	s, _ := newTestServer(t)
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
