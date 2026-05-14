// Package issuer mints RS256-signed JWTs and publishes the matching JWKS.
//
// The issuer is the private side of the auth service; downstream verifiers
// only need the public JWKS exposed by JWKS().
package issuer

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/ethpandaops/service-authenticatoor/pkg/auth"
)

// Issuer mints signed JWTs and exposes the public key material verifiers
// need to validate them.
type Issuer interface {
	// Issue mints a token for the supplied subject and email. If audience
	// is non-nil it overrides the issuer's default audience for this
	// token. Subject and email are kept separate so providers like the
	// GitHub OAuth provider can put a stable login in "sub" while still
	// emitting a "email" claim — downstream services pick whichever
	// fits their model.
	Issue(subject, email string, audience []string) (token string, claims *auth.Claims, err error)
	// JWKS returns the set of public keys (active + previous) as serialized
	// JSON.
	JWKS() ([]byte, error)
	// ActiveKeyID returns the kid currently used for signing.
	ActiveKeyID() string
}

// PreviousKey is a public-only key kept in the JWKS during rotation so
// already-issued tokens still verify until they expire.
type PreviousKey struct {
	KeyID  string
	Public *rsa.PublicKey
}

// Config is the static configuration of an RS256Issuer.
type Config struct {
	// ActiveKey is the RSA private key currently used for signing.
	ActiveKey *rsa.PrivateKey
	// ActiveKeyID is the kid put in the JWT header. If empty, derived from
	// the active public key.
	ActiveKeyID string
	// Previous holds public keys retained in JWKS during rotation.
	Previous []PreviousKey
	// Issuer is the canonical URL of the auth service ("iss" claim).
	Issuer string
	// DefaultAudience is the "aud" claim when the caller doesn't override it.
	DefaultAudience []string
	// Scope is the "scope" claim — a host wildcard pattern.
	Scope string
	// Services is the default "services" claim — a comma-separated
	// allow/deny directive list (see auth.ServiceAllowed). Empty means
	// no constraint is encoded into the token, and downstream verifiers
	// will accept it for any service.
	Services string
	// TTL is how long issued tokens are valid for.
	TTL time.Duration
	// Now is overridable for tests; defaults to time.Now.
	Now func() time.Time
}

// RS256Issuer signs JWTs with RS256.
type RS256Issuer struct {
	cfg       Config
	jwks      []byte
	activeKid string
}

// NewRS256Issuer builds an RS256Issuer. It derives the active kid if not
// configured and pre-marshals the JWKS.
func NewRS256Issuer(cfg Config) (*RS256Issuer, error) {
	if cfg.ActiveKey == nil {
		return nil, fmt.Errorf("issuer: active key is required")
	}
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("issuer: issuer URL is required")
	}
	if cfg.TTL <= 0 {
		return nil, fmt.Errorf("issuer: TTL must be positive")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}

	kid := cfg.ActiveKeyID
	if kid == "" {
		kid = DeriveKeyID(&cfg.ActiveKey.PublicKey)
	}

	jwks := JWKS{Keys: make([]JWK, 0, 1+len(cfg.Previous))}
	jwks.Keys = append(jwks.Keys, PublicKeyToJWK(&cfg.ActiveKey.PublicKey, kid))
	for _, p := range cfg.Previous {
		jwks.Keys = append(jwks.Keys, PublicKeyToJWK(p.Public, p.KeyID))
	}
	out, err := json.Marshal(jwks)
	if err != nil {
		return nil, fmt.Errorf("marshal JWKS: %w", err)
	}

	return &RS256Issuer{cfg: cfg, jwks: out, activeKid: kid}, nil
}

// Issue mints and signs a JWT for the supplied subject and email.
func (i *RS256Issuer) Issue(subject, email string, audience []string) (string, *auth.Claims, error) {
	if subject == "" {
		return "", nil, fmt.Errorf("issuer: subject is required")
	}

	aud := audience
	if len(aud) == 0 {
		aud = i.cfg.DefaultAudience
	}

	now := i.cfg.Now()
	jti, err := randomJTI()
	if err != nil {
		return "", nil, fmt.Errorf("issuer: jti: %w", err)
	}

	claims := &auth.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    i.cfg.Issuer,
			Subject:   subject,
			Audience:  jwt.ClaimStrings(aud),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(i.cfg.TTL)),
			ID:        jti,
		},
		Email:    email,
		Scope:    i.cfg.Scope,
		Services: i.cfg.Services,
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = i.activeKid

	signed, err := tok.SignedString(i.cfg.ActiveKey)
	if err != nil {
		return "", nil, fmt.Errorf("issuer: sign: %w", err)
	}
	return signed, claims, nil
}

// JWKS returns a copy of the pre-marshaled JWKS bytes.
func (i *RS256Issuer) JWKS() ([]byte, error) {
	out := make([]byte, len(i.jwks))
	copy(out, i.jwks)
	return out, nil
}

// ActiveKeyID returns the kid used for new tokens.
func (i *RS256Issuer) ActiveKeyID() string {
	return i.activeKid
}

// randomJTI returns a 128-bit random base64url-encoded value.
func randomJTI() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
