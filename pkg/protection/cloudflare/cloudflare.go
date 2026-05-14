// Package cloudflare implements protection.Provider for Cloudflare Access.
//
// Cloudflare Access is a reverse-proxy SSO that intercepts unauthenticated
// requests before they reach this service: it serves its own login UI,
// sets a session cookie, and forwards every authenticated request with
// two headers — Cf-Access-Authenticated-User-Email (the identity) and
// Cf-Access-Jwt-Assertion (a signed assertion). This provider trusts the
// email header and, when configured, additionally verifies the assertion
// against Cloudflare's JWKS as defense in depth.
package cloudflare

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"

	"github.com/ethpandaops/service-authenticatoor/pkg/cfaccess"
	"github.com/ethpandaops/service-authenticatoor/pkg/protection"
)

// CloudflareLogoutPath is the path Cloudflare Access intercepts on every
// protected origin to clear the local CF_Authorization cookie. We 302 to
// the relative form so the request stays on the current host and CF's
// edge handles the actual session teardown.
const CloudflareLogoutPath = "/cdn-cgi/access/logout"

// DefaultUserHeader is the header CF Access uses by default to forward
// the authenticated user's email.
const DefaultUserHeader = "Cf-Access-Authenticated-User-Email"

// Config configures the cloudflare provider.
type Config struct {
	// VerifyJWT enables Cf-Access-Jwt-Assertion verification against the
	// team's JWKS. Strongly recommended for production.
	VerifyJWT bool
	// TeamDomain is the Cloudflare team domain (e.g.
	// "acme.cloudflareaccess.com"). Required when VerifyJWT is true.
	TeamDomain string
	// AudTag is the AUD tag of the CF Access application. When set, the
	// verifier rejects assertions whose aud claim doesn't match. When
	// empty, only signature + issuer are verified.
	AudTag string
	// JwtHeader is the header carrying the assertion. Defaults to
	// "Cf-Access-Jwt-Assertion".
	JwtHeader string
	// UserHeader is the header carrying the authenticated email.
	// Defaults to "Cf-Access-Authenticated-User-Email".
	UserHeader string
}

// Provider implements protection.Provider for Cloudflare Access.
type Provider struct {
	cfg      Config
	log      logrus.FieldLogger
	verifier cfaccess.Verifier
}

var _ protection.Provider = (*Provider)(nil)

// New constructs a Provider. Header defaults are applied; verifier
// construction is deferred to Start.
func New(log logrus.FieldLogger, cfg Config) *Provider {
	if cfg.JwtHeader == "" {
		cfg.JwtHeader = cfaccess.DefaultJWTHeader
	}
	if cfg.UserHeader == "" {
		cfg.UserHeader = DefaultUserHeader
	}
	return &Provider{
		cfg: cfg,
		log: log.WithField("package", "protection/cloudflare"),
	}
}

// Name returns "cloudflare".
func (p *Provider) Name() string { return "cloudflare" }

// Start fetches the CF JWKS when VerifyJWT is enabled. When disabled, a
// no-op verifier is wired in and Start logs a defense-in-depth warning.
func (p *Provider) Start(ctx context.Context) error {
	if !p.cfg.VerifyJWT {
		p.log.Warn("CF Access JWT verification is DISABLED — only safe when the service is unreachable outside the trusted ingress")
		p.verifier = cfaccess.NoopVerifier{}
		return nil
	}
	if p.cfg.TeamDomain == "" {
		return errors.New("cloudflare: TeamDomain required when VerifyJWT is enabled")
	}
	v, err := cfaccess.NewJWKSVerifier(ctx, p.log, cfaccess.Config{
		TeamDomain: p.cfg.TeamDomain,
		AudTag:     p.cfg.AudTag,
	})
	if err != nil {
		return fmt.Errorf("cloudflare: build verifier: %w", err)
	}
	p.verifier = v
	entry := p.log.WithField("team", p.cfg.TeamDomain)
	if p.cfg.AudTag == "" {
		entry.Warn("cf access verifier ready — audTag not set, accepting assertions from any application in the team")
	} else {
		entry.WithField("aud", p.cfg.AudTag).Info("cf access verifier ready")
	}
	return nil
}

// Stop is a no-op.
func (p *Provider) Stop() error { return nil }

// RegisterRoutes is a no-op; CF Access has no service-side flow routes.
func (p *Provider) RegisterRoutes(_ *mux.Router) {}

// Logout 302s to /cdn-cgi/access/logout, which the Cloudflare Access
// edge intercepts on the protected origin and uses to clear the local
// CF_Authorization cookie before bouncing through the team's logout
// flow. The client library calls /auth/logout from a hidden iframe; the
// iframe follows the redirect, the CF edge clears the session, and the
// next /auth/* request will trigger a fresh CF Access login.
func (p *Provider) Logout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, CloudflareLogoutPath, http.StatusFound)
}

// Authenticate inspects the CF Access headers on the incoming request.
// When VerifyJWT is enabled the email is taken from the verified
// assertion (the trust-the-header value is overridden), otherwise the
// header is trusted directly — the latter path is only safe behind a
// properly enforcing CF Access ingress.
func (p *Provider) Authenticate(ctx context.Context, r *http.Request) (protection.Outcome, error) {
	email := r.Header.Get(p.cfg.UserHeader)

	if p.cfg.VerifyJWT {
		cfJWT := r.Header.Get(p.cfg.JwtHeader)
		if cfJWT == "" {
			return protection.Outcome{Status: http.StatusUnauthorized}, nil
		}
		claims, err := p.verifier.Verify(ctx, cfJWT)
		if err != nil {
			p.log.WithError(err).Debug("cf access verification failed")
			return protection.Outcome{Status: http.StatusUnauthorized}, nil
		}
		email = claims.Email
	}

	if email == "" {
		return protection.Outcome{Status: http.StatusUnauthorized}, nil
	}
	return protection.Outcome{Identity: &protection.Identity{
		Subject: email,
		Email:   email,
	}}, nil
}

// SetVerifier overrides the JWT verifier; intended for tests.
func (p *Provider) SetVerifier(v cfaccess.Verifier) { p.verifier = v }
