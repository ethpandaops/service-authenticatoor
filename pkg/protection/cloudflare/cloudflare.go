// Package cloudflare implements protection.Provider for Cloudflare Access.
//
// Cloudflare Access is a reverse-proxy SSO that intercepts unauthenticated
// requests before they reach this service: it serves its own login UI,
// sets a session cookie, and forwards every authenticated request with
// two headers — Cf-Access-Authenticated-User-Email (the identity) and
// Cf-Access-Jwt-Assertion (a signed assertion). This provider trusts the
// email header and, when configured, additionally verifies the assertion
// against Cloudflare's JWKS as defense in depth.
//
// Two deployment topologies are supported simultaneously:
//
//   - Edge covers /auth/*: every /auth/* request arrives with the CF
//     headers and authenticates ambiently — the login path is never used.
//   - Edge covers only the login prefix (e.g. /cfaccess/*): /auth/* is
//     publicly reachable; unauthenticated browsers are redirected to
//     LoginPath, which sits behind CF Access, converts the ambient
//     identity into a signed session cookie, and bounces back. Machines
//     holding CF Access service tokens use the server-mounted token alias
//     (/<name>/token) on the same protected prefix.
package cloudflare

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"

	"github.com/ethpandaops/service-authenticatoor/pkg/cfaccess"
	"github.com/ethpandaops/service-authenticatoor/pkg/protection"
	"github.com/ethpandaops/service-authenticatoor/pkg/session"
)

// CloudflareLogoutPath is the path Cloudflare Access intercepts on every
// protected origin to clear the local CF_Authorization cookie. We 302 to
// the relative form so the request stays on the current host and CF's
// edge handles the actual session teardown.
const CloudflareLogoutPath = "/cdn-cgi/access/logout"

// DefaultUserHeader is the header CF Access uses by default to forward
// the authenticated user's email.
const DefaultUserHeader = "Cf-Access-Authenticated-User-Email"

// Defaults applied when corresponding Config fields are empty.
const (
	DefaultLoginPath         = "/cfaccess/login"
	DefaultSessionCookieName = "authenticatoor_cfaccess_session"
	DefaultSessionTTL        = 12 * time.Hour
)

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
	// AllowServiceTokens permits non-identity Cloudflare Access service
	// tokens to authenticate. Such requests carry no email; the service
	// token's common_name (its client ID) is used as the identity subject.
	// Requires VerifyJWT, since common_name is only available from the
	// verified assertion, not the trust-the-header path. Defaults to false.
	AllowServiceTokens bool

	// LoginPath is the interactive login entry. It must sit behind the CF
	// Access application: the handler reads the ambient CF headers there,
	// mints the session cookie, and redirects back. Defaults to
	// "/cfaccess/login".
	LoginPath string
	// SessionKey is the HMAC key for the session cookie. Derived in
	// main.go from the JWT signing key via issuer.DeriveHMACKey so
	// there's no separate secret to manage. Must be at least 16 bytes.
	// Required.
	SessionKey []byte
	// SessionCookieName is the name of the session cookie. Defaults to
	// "authenticatoor_cfaccess_session".
	SessionCookieName string
	// SessionTTL is the session cookie lifetime. Defaults to 12h. The CF
	// Access policy is only re-checked when the cookie expires and the
	// user passes through LoginPath again.
	SessionTTL time.Duration

	// Now overrides time.Now for deterministic tests.
	Now func() time.Time
}

// Provider implements protection.Provider for Cloudflare Access.
type Provider struct {
	cfg      Config
	log      logrus.FieldLogger
	verifier cfaccess.Verifier
}

var (
	_ protection.Provider             = (*Provider)(nil)
	_ protection.AmbientAuthenticator = (*Provider)(nil)
	_ protection.SessionClearer       = (*Provider)(nil)
)

// New constructs a Provider. Header and cookie defaults are applied;
// verifier construction is deferred to Start.
func New(log logrus.FieldLogger, cfg Config) *Provider {
	if cfg.JwtHeader == "" {
		cfg.JwtHeader = cfaccess.DefaultJWTHeader
	}
	if cfg.UserHeader == "" {
		cfg.UserHeader = DefaultUserHeader
	}
	if cfg.LoginPath == "" {
		cfg.LoginPath = DefaultLoginPath
	}
	if cfg.SessionCookieName == "" {
		cfg.SessionCookieName = DefaultSessionCookieName
	}
	if cfg.SessionTTL == 0 {
		cfg.SessionTTL = DefaultSessionTTL
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
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
	if len(p.cfg.SessionKey) < 16 {
		return errors.New("cloudflare: SessionKey must be at least 16 bytes")
	}
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

// RegisterRoutes attaches the login entry. It runs on the parent router
// (bypassing the auth middleware) because the request is the act of
// authenticating — the CF Access edge in front of LoginPath supplies the
// ambient identity.
func (p *Provider) RegisterRoutes(r *mux.Router) {
	r.HandleFunc(p.cfg.LoginPath, p.handleLogin).Methods(http.MethodGet)
}

// LoginURL returns the login entry path carrying returnTo.
func (p *Provider) LoginURL(returnTo string) string {
	v := url.Values{}
	v.Set("return_to", returnTo)
	return p.cfg.LoginPath + "?" + v.Encode()
}

// Logout clears the local session cookie and 302s to
// /cdn-cgi/access/logout, which the Cloudflare Access edge intercepts on
// the protected origin and uses to clear the local CF_Authorization
// cookie before bouncing through the team's logout flow. The client
// library calls /auth/logout from a hidden iframe; the iframe follows
// the redirect, the CF edge clears the session, and the next /auth/*
// request will trigger a fresh CF Access login.
func (p *Provider) Logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, p.ClearSessionCookie())
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, CloudflareLogoutPath, http.StatusFound)
}

// Authenticate inspects the CF Access headers on the incoming request,
// falling back to the session cookie minted by LoginPath. When neither
// is present the outcome redirects to LoginPath — on a deployment whose
// edge still covers /auth/* that fallback is never reached, so legacy
// topologies behave exactly as before.
//
// A present-but-invalid assertion fails hard with 401 (it signals
// misconfiguration or forgery, not an unauthenticated browser).
func (p *Provider) Authenticate(ctx context.Context, r *http.Request) (protection.Outcome, error) {
	out, hardFail := p.ambient(ctx, r)
	if out.Identity != nil || hardFail {
		return out, nil
	}

	if c, err := r.Cookie(p.cfg.SessionCookieName); err == nil {
		sub, email, perr := session.Parse(p.cfg.SessionKey, c.Value, p.cfg.Now())
		if perr == nil {
			return protection.Outcome{Identity: &protection.Identity{
				Subject: sub,
				Email:   email,
			}}, nil
		}
		p.log.WithError(perr).Debug("session cookie invalid; redirecting to login")
	}

	return protection.Outcome{RedirectTo: p.LoginURL(r.URL.RequestURI())}, nil
}

// AuthenticateAmbient inspects only the ambient CF Access headers — no
// session cookie, no redirects. The server mounts the machine token
// alias (/<name>/token) on top of this so CF Access service tokens keep
// a direct JSON endpoint behind the edge-protected prefix.
func (p *Provider) AuthenticateAmbient(ctx context.Context, r *http.Request) (protection.Outcome, error) {
	out, _ := p.ambient(ctx, r)
	if out.Identity == nil && out.Status == 0 {
		out.Status = http.StatusUnauthorized
	}
	return out, nil
}

// ambient runs the CF Access header check. hardFail reports that the
// request carried an assertion that failed verification — callers must
// not fall through to weaker checks in that case.
func (p *Provider) ambient(ctx context.Context, r *http.Request) (out protection.Outcome, hardFail bool) {
	email := r.Header.Get(p.cfg.UserHeader)
	commonName := ""

	if p.cfg.VerifyJWT {
		cfJWT := r.Header.Get(p.cfg.JwtHeader)
		if cfJWT == "" {
			return protection.Outcome{}, false
		}
		claims, err := p.verifier.Verify(ctx, cfJWT)
		if err != nil {
			p.log.WithError(err).Debug("cf access verification failed")
			return protection.Outcome{Status: http.StatusUnauthorized}, true
		}
		email = claims.Email
		commonName = claims.CommonName
	}

	if email != "" {
		return protection.Outcome{Identity: &protection.Identity{
			Subject: email,
			Email:   email,
		}}, false
	}

	// No email means a Cloudflare Access service token (non-identity)
	// request. When opted in, authenticate it using the token's common_name
	// (its client ID) as the subject; there is no email to populate.
	if p.cfg.AllowServiceTokens && commonName != "" {
		return protection.Outcome{Identity: &protection.Identity{
			Subject: commonName,
		}}, false
	}

	return protection.Outcome{}, false
}

// handleLogin converts the ambient CF Access identity into a signed
// session cookie and redirects to return_to. The path must be covered by
// the CF Access application — an unauthenticated request landing here
// means the edge configuration is wrong, so the response says so.
func (p *Provider) handleLogin(w http.ResponseWriter, r *http.Request) {
	out, err := p.AuthenticateAmbient(r.Context(), r)
	if err != nil {
		p.log.WithError(err).Error("cf login ambient check")
		http.Error(w, "auth provider error", http.StatusInternalServerError)
		return
	}
	if out.Identity == nil {
		http.Error(w,
			"no Cloudflare Access identity on this request — the CF Access application must cover this path",
			http.StatusForbidden)
		return
	}

	signed, err := session.Sign(p.cfg.SessionKey, out.Identity.Subject, out.Identity.Email,
		p.cfg.SessionTTL, p.cfg.Now())
	if err != nil {
		p.log.WithError(err).Error("session cookie signing failed")
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, p.sessionCookie(signed))

	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, protection.SafeReturnTo(r.URL.Query().Get("return_to")), http.StatusFound)
}

// sessionCookie wraps the signed session payload.
//
// SameSite=None + Secure is required so the cross-site iframe flows
// (`/auth/embed` for silent token, `/auth/logout` for clearing) can
// read and overwrite the cookie. Browsers treat *.localhost as a
// secure context, so Secure=true works for HTTP local dev too —
// non-localhost plain HTTP isn't a supported deployment.
func (p *Provider) sessionCookie(value string) *http.Cookie {
	return &http.Cookie{
		Name:     p.cfg.SessionCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   int(p.cfg.SessionTTL.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	}
}

// ClearSessionCookie returns a cookie that clears the session. Attributes
// must match sessionCookie so the browser overwrites the live session.
func (p *Provider) ClearSessionCookie() *http.Cookie {
	return &http.Cookie{
		Name:     p.cfg.SessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	}
}

// SetVerifier overrides the JWT verifier; intended for tests.
func (p *Provider) SetVerifier(v cfaccess.Verifier) { p.verifier = v }
