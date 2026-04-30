package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/ethpandaops/service-authenticatoor/pkg/auth"
	"github.com/ethpandaops/service-authenticatoor/pkg/issuer"
)

// servedIssuer spins up an issuer plus an httptest.Server that serves its
// JWKS at /jwks.json. Returns the issuer, the server URL, and a teardown.
func servedIssuer(t *testing.T) (*issuer.RS256Issuer, string, func()) {
	t.Helper()
	key, err := issuer.GenerateRSAKey()
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	iss, err := issuer.NewRS256Issuer(issuer.Config{
		ActiveKey:       key,
		Issuer:          "https://auth.test.example",
		DefaultAudience: []string{"test.example"},
		Scope:           "*.test.example",
		TTL:             30 * time.Minute,
	})
	if err != nil {
		t.Fatalf("newissuer: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		raw, _ := iss.JWKS()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
	})
	srv := httptest.NewServer(mux)
	return iss, srv.URL, srv.Close
}

func TestVerifier_RoundtripValid(t *testing.T) {
	iss, jwksBase, teardown := servedIssuer(t)
	defer teardown()

	tok, _, err := iss.Issue("alice@example.com", nil)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	v, err := auth.NewJWKSVerifier(context.Background(), auth.VerifierConfig{
		JWKSURL:          jwksBase + "/jwks.json",
		ExpectedIssuer:   "https://auth.test.example",
		ExpectedAudience: "test.example",
		ExpectedScope:    "*.test.example",
	})
	if err != nil {
		t.Fatalf("newverifier: %v", err)
	}

	claims, err := v.Verify(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Email != "alice@example.com" {
		t.Errorf("email: got %q", claims.Email)
	}
}

func TestVerifier_RejectsWrongIssuer(t *testing.T) {
	iss, jwksBase, teardown := servedIssuer(t)
	defer teardown()

	tok, _, err := iss.Issue("alice@example.com", nil)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	v, err := auth.NewJWKSVerifier(context.Background(), auth.VerifierConfig{
		JWKSURL:          jwksBase + "/jwks.json",
		ExpectedIssuer:   "https://auth.OTHER.example",
		ExpectedAudience: "test.example",
	})
	if err != nil {
		t.Fatalf("newverifier: %v", err)
	}
	if _, err := v.Verify(tok); err == nil {
		t.Error("expected wrong-issuer rejection")
	}
}

func TestVerifier_RejectsWrongAudience(t *testing.T) {
	iss, jwksBase, teardown := servedIssuer(t)
	defer teardown()

	tok, _, err := iss.Issue("alice@example.com", nil)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	v, err := auth.NewJWKSVerifier(context.Background(), auth.VerifierConfig{
		JWKSURL:          jwksBase + "/jwks.json",
		ExpectedIssuer:   "https://auth.test.example",
		ExpectedAudience: "other.example",
	})
	if err != nil {
		t.Fatalf("newverifier: %v", err)
	}
	if _, err := v.Verify(tok); err == nil {
		t.Error("expected wrong-audience rejection")
	}
}

func TestVerifier_RejectsExpired(t *testing.T) {
	// Build an issuer with a fixed clock, sign a token, then verify with a
	// clock far in the future.
	key, err := issuer.GenerateRSAKey()
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	fixedNow := time.Unix(1_700_000_000, 0).UTC()
	iss, err := issuer.NewRS256Issuer(issuer.Config{
		ActiveKey:       key,
		Issuer:          "https://auth.test.example",
		DefaultAudience: []string{"test.example"},
		TTL:             1 * time.Minute,
		Now:             func() time.Time { return fixedNow },
	})
	if err != nil {
		t.Fatalf("newissuer: %v", err)
	}

	tok, _, err := iss.Issue("alice@example.com", nil)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		raw, _ := iss.JWKS()
		_, _ = w.Write(raw)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	v, err := auth.NewJWKSVerifier(context.Background(), auth.VerifierConfig{
		JWKSURL:          srv.URL + "/jwks.json",
		ExpectedIssuer:   "https://auth.test.example",
		ExpectedAudience: "test.example",
		Now:              func() time.Time { return fixedNow.Add(time.Hour) },
	})
	if err != nil {
		t.Fatalf("newverifier: %v", err)
	}
	if _, err := v.Verify(tok); err == nil {
		t.Error("expected expired rejection")
	}
}

func TestVerifier_RejectsHS256(t *testing.T) {
	// A token signed with a non-RS256 algorithm must be rejected even if a
	// secret matches; the verifier explicitly restricts methods to RS256.
	_, jwksBase, teardown := servedIssuer(t)
	defer teardown()

	hsTok := jwt.NewWithClaims(jwt.SigningMethodHS256, &auth.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://auth.test.example",
			Audience:  jwt.ClaimStrings{"test.example"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		Email: "alice@example.com",
	})
	signed, err := hsTok.SignedString([]byte("supersecret"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	v, err := auth.NewJWKSVerifier(context.Background(), auth.VerifierConfig{
		JWKSURL:          jwksBase + "/jwks.json",
		ExpectedIssuer:   "https://auth.test.example",
		ExpectedAudience: "test.example",
	})
	if err != nil {
		t.Fatalf("newverifier: %v", err)
	}
	if _, err := v.Verify(signed); err == nil {
		t.Error("expected HS256 rejection")
	}
}
