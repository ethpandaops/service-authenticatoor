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
	// CommonName is set by Cloudflare Access for non-identity service-token
	// requests and carries the service token's client ID. Such assertions
	// have no email, so it is the only identity signal available for them.
	CommonName string `json:"common_name,omitempty"`
	// Identity URL is sometimes useful for debugging, kept for completeness.
	Identity string `json:"identity_nonce,omitempty"`
}

// MetaClaims is the subset of claims carried by the "meta" token that
// Cloudflare Access embeds in its login redirect
// (https://<team>/cdn-cgi/access/login/<host>?kid=<aud>&meta=<jwt>). It
// is signed with the team's keys and names the protected application
// (aud) and the requested hostname, which lets an instance learn its own
// application AUD tag without configuration.
type MetaClaims struct {
	jwt.RegisteredClaims

	Type     string `json:"type"`
	Hostname string `json:"hostname"`
}

// MetaVerifier validates Cloudflare Access login-redirect meta tokens.
type MetaVerifier interface {
	VerifyMeta(ctx context.Context, jwtString string) (*MetaClaims, error)
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
	// AudTag is the AUD tag of the CF Access application. When non-empty,
	// the verifier rejects assertions whose aud doesn't match. When empty,
	// the audience claim is not checked — assertions from any application
	// in the same CF Access team will be accepted (signature + issuer
	// still pin them to the team).
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
	opts := []jwt.ParserOption{
		// CF uses RS256 with rotating keys.
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		jwt.WithIssuer("https://" + strings.TrimSuffix(v.cfg.TeamDomain, "/")),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(v.cfg.Now),
	}
	if v.cfg.AudTag != "" {
		opts = append(opts, jwt.WithAudience(v.cfg.AudTag))
	}
	parser := jwt.NewParser(opts...)
	tok, err := parser.ParseWithClaims(tokenString, claims, v.kf.Keyfunc)
	if err != nil {
		return nil, fmt.Errorf("cfaccess: parse: %w", err)
	}
	if !tok.Valid {
		return nil, errors.New("cfaccess: token not valid")
	}
	// A normal identity assertion carries an email; a service-token
	// (non-identity) assertion carries a common_name instead. Require at
	// least one — the provider decides whether a service token is allowed.
	if claims.Email == "" && claims.CommonName == "" {
		return nil, errors.New("cfaccess: assertion missing both email and common_name claims")
	}
	return claims, nil
}

// VerifyMeta parses and validates a login-redirect meta token: RS256
// signature against the team's JWKS, unexpired, and type "meta". Meta
// tokens carry no issuer claim, so the team key is the only anchor; the
// caller must check Hostname. Returns an error on any failure.
func (v *JWKSVerifier) VerifyMeta(_ context.Context, tokenString string) (*MetaClaims, error) {
	if tokenString == "" {
		return nil, errors.New("cfaccess: empty meta token")
	}
	claims := &MetaClaims{}
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(v.cfg.Now),
	)
	tok, err := parser.ParseWithClaims(tokenString, claims, v.kf.Keyfunc)
	if err != nil {
		return nil, fmt.Errorf("cfaccess: parse meta: %w", err)
	}
	if !tok.Valid {
		return nil, errors.New("cfaccess: meta token not valid")
	}
	if claims.Type != "meta" {
		return nil, fmt.Errorf("cfaccess: unexpected meta token type %q", claims.Type)
	}
	if len(claims.Audience) != 1 || claims.Audience[0] == "" {
		return nil, errors.New("cfaccess: meta token must name exactly one audience")
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
