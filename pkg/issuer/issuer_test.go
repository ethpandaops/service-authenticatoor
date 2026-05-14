package issuer

import (
	"crypto/rsa"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/ethpandaops/service-authenticatoor/pkg/auth"
)

func newTestIssuer(t *testing.T, ttl time.Duration) (*RS256Issuer, *rsa.PrivateKey) {
	t.Helper()
	key, err := GenerateRSAKey()
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	iss, err := NewRS256Issuer(Config{
		ActiveKey:       key,
		Issuer:          "https://auth.test.example",
		DefaultAudience: []string{"test.example"},
		Scope:           "*.test.example",
		TTL:             ttl,
		Now:             func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
	})
	if err != nil {
		t.Fatalf("newissuer: %v", err)
	}
	return iss, key
}

func TestIssuer_IssueAndParse(t *testing.T) {
	iss, key := newTestIssuer(t, 30*time.Minute)

	tok, claims, err := iss.Issue("alice@example.com", "alice@example.com", nil)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if tok == "" {
		t.Fatal("empty token")
	}

	if claims.Email != "alice@example.com" {
		t.Errorf("email: got %q", claims.Email)
	}
	if claims.Subject != "alice@example.com" {
		t.Errorf("sub: got %q", claims.Subject)
	}
	if claims.Issuer != "https://auth.test.example" {
		t.Errorf("iss: got %q", claims.Issuer)
	}
	if !slices.Contains(claims.Audience, "test.example") {
		t.Errorf("aud: %v", claims.Audience)
	}
	if claims.Scope != "*.test.example" {
		t.Errorf("scope: %q", claims.Scope)
	}
	if claims.ID == "" {
		t.Error("jti empty")
	}

	parsed, err := jwt.ParseWithClaims(tok, &auth.Claims{}, func(t *jwt.Token) (any, error) {
		return &key.PublicKey, nil
	}, jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithTimeFunc(func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !parsed.Valid {
		t.Error("not valid")
	}
}

func TestIssuer_AudienceOverride(t *testing.T) {
	iss, _ := newTestIssuer(t, 30*time.Minute)
	_, claims, err := iss.Issue("alice@example.com", "alice@example.com", []string{"app.test.example"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if !slices.Contains(claims.Audience, "app.test.example") {
		t.Errorf("expected explicit aud, got %v", claims.Audience)
	}
	if slices.Contains(claims.Audience, "test.example") {
		t.Errorf("default aud leaked into override: %v", claims.Audience)
	}
}

func TestIssuer_KidInHeader(t *testing.T) {
	iss, _ := newTestIssuer(t, 30*time.Minute)

	tok, _, err := iss.Issue("alice@example.com", "alice@example.com", nil)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("malformed token: %d segments", len(parts))
	}
	parser := jwt.NewParser()
	parsed, _, err := parser.ParseUnverified(tok, &auth.Claims{})
	if err != nil {
		t.Fatalf("parseunverified: %v", err)
	}
	kid, ok := parsed.Header["kid"].(string)
	if !ok || kid == "" {
		t.Error("kid missing from header")
	}
	if kid != iss.ActiveKeyID() {
		t.Errorf("kid mismatch: token=%q issuer=%q", kid, iss.ActiveKeyID())
	}
}

func TestIssuer_JWKSContainsActiveAndPrevious(t *testing.T) {
	active, err := GenerateRSAKey()
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	prev, err := GenerateRSAKey()
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	iss, err := NewRS256Issuer(Config{
		ActiveKey:       active,
		ActiveKeyID:     "active",
		Previous:        []PreviousKey{{KeyID: "prev", Public: &prev.PublicKey}},
		Issuer:          "https://auth.test.example",
		DefaultAudience: []string{"test.example"},
		Scope:           "*.test.example",
		TTL:             time.Hour,
	})
	if err != nil {
		t.Fatalf("newissuer: %v", err)
	}

	raw, err := iss.JWKS()
	if err != nil {
		t.Fatalf("jwks: %v", err)
	}

	var jwks JWKS
	if err := json.Unmarshal(raw, &jwks); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(jwks.Keys) != 2 {
		t.Fatalf("want 2 keys, got %d", len(jwks.Keys))
	}

	got := map[string]bool{}
	for _, k := range jwks.Keys {
		got[k.Kid] = true
	}
	if !got["active"] || !got["prev"] {
		t.Errorf("missing kids: %v", got)
	}
}

func TestIssuer_RejectsZeroTTL(t *testing.T) {
	key, _ := GenerateRSAKey()
	_, err := NewRS256Issuer(Config{
		ActiveKey: key,
		Issuer:    "https://auth.test.example",
		TTL:       0,
	})
	if err == nil {
		t.Error("expected error for zero TTL")
	}
}

func TestIssuer_RejectsEmptySubject(t *testing.T) {
	iss, _ := newTestIssuer(t, time.Hour)
	_, _, err := iss.Issue("", "", nil)
	if err == nil {
		t.Error("expected error for empty subject")
	}
}
