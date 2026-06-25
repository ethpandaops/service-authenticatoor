package cloudflare

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sirupsen/logrus"

	"github.com/ethpandaops/service-authenticatoor/pkg/cfaccess"
)

// stubVerifier lets tests substitute the JWT verifier without standing up a
// real CF JWKS endpoint.
type stubVerifier struct {
	email      string
	commonName string
	err        error
}

func (s stubVerifier) Verify(_ context.Context, _ string) (*cfaccess.Claims, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &cfaccess.Claims{Email: s.email, CommonName: s.commonName}, nil
}

func newTestProvider(t *testing.T, cfg Config) *Provider {
	t.Helper()
	log := logrus.New()
	log.SetOutput(io.Discard)
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

func TestProvider_VerifyOff_RejectsMissingHeader(t *testing.T) {
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
	if out.Status != http.StatusUnauthorized {
		t.Errorf("status: got %d, want 401", out.Status)
	}
}

func TestProvider_VerifyOn_RejectsMissingAssertion(t *testing.T) {
	p := newTestProvider(t, Config{VerifyJWT: true, TeamDomain: "team.test"})
	p.SetVerifier(stubVerifier{email: "alice@example.com"})

	r := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
	r.Header.Set(DefaultUserHeader, "alice@example.com") // header present, JWT missing
	out, err := p.Authenticate(context.Background(), r)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	if out.Identity != nil {
		t.Fatal("expected no identity (assertion missing)")
	}
	if out.Status != http.StatusUnauthorized {
		t.Errorf("status: got %d, want 401", out.Status)
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
	if out.Status != http.StatusUnauthorized {
		t.Errorf("status: got %d, want 401", out.Status)
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
