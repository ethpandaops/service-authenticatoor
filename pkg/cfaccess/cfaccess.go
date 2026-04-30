// Package cfaccess verifies Cloudflare Access assertion JWTs
// (Cf-Access-Jwt-Assertion) against the team's JWKS endpoint.
//
// Cloudflare Access signs an assertion JWT for every authenticated request
// and forwards it as a header. Verifying it server-side is defense in
// depth: an attacker who reaches the service outside the trusted ingress
// still cannot forge a valid assertion.
package cfaccess

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"
)

// DefaultJWTHeader is the header CF Access uses by default to forward its
// assertion JWT.
const DefaultJWTHeader = "Cf-Access-Jwt-Assertion"

// Claims is a subset of the CF Access assertion claims we care about.
type Claims struct {
	jwt.RegisteredClaims

	Email string `json:"email,omitempty"`
	// Identity URL is sometimes useful for debugging, kept for completeness.
	Identity string `json:"identity_nonce,omitempty"`
}

// Verifier validates Cloudflare Access assertion JWTs. Implementations are
// safe for concurrent use.
type Verifier interface {
	Verify(ctx context.Context, jwtString string) (*Claims, error)
}

// Config configures a Verifier.
type Config struct {
	// TeamDomain is the Cloudflare team's domain (e.g.
	// "<team>.cloudflareaccess.com"). The JWKS URL is derived from this:
	//   https://<team>/cdn-cgi/access/certs
	TeamDomain string
	// AudTag is the AUD tag of the CF Access application (set per-app in
	// the CF zero-trust dashboard). Tokens whose aud doesn't match this are
	// rejected.
	AudTag string
	// Now is overridable for tests; defaults to time.Now.
	Now func() time.Time
}

// JWKSVerifier verifies CF Access JWTs by fetching keys from the team's
// JWKS endpoint.
type JWKSVerifier struct {
	cfg Config
	kf  keyfunc.Keyfunc
	log logrus.FieldLogger
}

// NewJWKSVerifier constructs a JWKSVerifier. The CF JWKS is fetched eagerly
// so configuration errors (bad team domain, network down) surface at startup
// rather than on the first request.
func NewJWKSVerifier(ctx context.Context, log logrus.FieldLogger, cfg Config) (*JWKSVerifier, error) {
	if cfg.TeamDomain == "" {
		return nil, errors.New("cfaccess: TeamDomain is required")
	}
	if cfg.AudTag == "" {
		return nil, errors.New("cfaccess: AudTag is required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}

	url := jwksURL(cfg.TeamDomain)
	kf, err := keyfunc.NewDefaultCtx(ctx, []string{url})
	if err != nil {
		return nil, fmt.Errorf("cfaccess: jwks init at %s: %w", url, err)
	}

	return &JWKSVerifier{
		cfg: cfg,
		kf:  kf,
		log: log.WithField("package", "cfaccess"),
	}, nil
}

// Verify parses and validates the supplied CF Access assertion. Returns a
// claims object on success; non-nil error on any failure.
func (v *JWKSVerifier) Verify(ctx context.Context, tokenString string) (*Claims, error) {
	if tokenString == "" {
		return nil, errors.New("cfaccess: empty token")
	}

	claims := &Claims{}
	parser := jwt.NewParser(
		// CF uses RS256 with rotating keys.
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		jwt.WithIssuer("https://"+strings.TrimSuffix(v.cfg.TeamDomain, "/")),
		jwt.WithAudience(v.cfg.AudTag),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(v.cfg.Now),
	)
	tok, err := parser.ParseWithClaims(tokenString, claims, v.kf.Keyfunc)
	if err != nil {
		return nil, fmt.Errorf("cfaccess: parse: %w", err)
	}
	if !tok.Valid {
		return nil, errors.New("cfaccess: token not valid")
	}
	if claims.Email == "" {
		return nil, errors.New("cfaccess: assertion missing email claim")
	}
	return claims, nil
}

// jwksURL returns the standard JWKS URL for a CF Access team.
func jwksURL(team string) string {
	team = strings.TrimSuffix(team, "/")
	if !strings.HasPrefix(team, "https://") && !strings.HasPrefix(team, "http://") {
		team = "https://" + team
	}
	return team + "/cdn-cgi/access/certs"
}

// NoopVerifier always accepts tokens and returns empty claims. Used when
// CF Access JWT verification is disabled (development only).
type NoopVerifier struct{}

// Verify always returns empty claims and nil error.
func (NoopVerifier) Verify(_ context.Context, _ string) (*Claims, error) {
	return &Claims{}, nil
}
