package cloudflare

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"

	"github.com/ethpandaops/service-authenticatoor/pkg/cfaccess"
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
