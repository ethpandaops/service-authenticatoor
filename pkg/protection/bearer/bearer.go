// Package bearer implements protection.Provider for OAuth 2.0 bearer
// tokens (RFC 6750) issued by a trusted OIDC provider.
//
// The provider is for non-interactive clients that already hold an IdP
// token: a request carrying "Authorization: Bearer <jwt>" authenticates
// when the JWT verifies against the issuer's published JWKS and names one
// of the configured audiences. There is no login flow, session cookie, or
// redirect — the token itself is the credential on every request.
//
// Like the cloudflare provider it is an AmbientAuthenticator, so the
// server mounts a machine token alias at /<name>/token. That path is
// outside /auth/*, so it stays reachable while an edge proxy (Cloudflare
// Access) still covers /auth/* for browser users.
//
// Trust the narrowest issuer/audience pair available: ideally an IdP
// application that exists only to authorize this service, whose own
// access policy decides who may obtain a token. Accepting the audience of
// a general-purpose application lets every holder of such a token — and
// every other service that receives one — mint tokens here.
package bearer

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"

	"github.com/ethpandaops/service-authenticatoor/pkg/auth"
	"github.com/ethpandaops/service-authenticatoor/pkg/protection"
)

// signingMethods are the asymmetric algorithms accepted for IdP tokens.
// HMAC and "none" are excluded: a JWKS-published key must never be usable
// as a shared secret.
var signingMethods = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}

// Config configures the bearer provider.
type Config struct {
	// IssuerURL is the IdP issuer. The provider fetches
	// <IssuerURL>/.well-known/openid-configuration at Start and requires
	// the document's issuer to match. Required.
	IssuerURL string
	// Audiences lists accepted "aud" values; a token must name at least
	// one. Required.
	Audiences []string
	// AllowedGroups narrows access to members of these groups (the
	// token's "groups" claim; matching rules as protection.GroupSet).
	// When empty, every token the issuer mints for the audiences is
	// accepted — the IdP application's own access policy is then the
	// authority.
	AllowedGroups []string
	// HTTPClient is used for the discovery fetch. Defaults to a
	// 10s-timeout client.
	HTTPClient *http.Client
	// Now overrides time.Now for deterministic tests.
	Now func() time.Time
}

// Provider implements protection.Provider for IdP bearer tokens.
type Provider struct {
	cfg           Config
	log           logrus.FieldLogger
	allowedGroups protection.GroupSet
	issuer        string
	kf            keyfunc.Keyfunc
}

var (
	_ protection.Provider             = (*Provider)(nil)
	_ protection.AmbientAuthenticator = (*Provider)(nil)
)

// claims is the subset of the IdP token the provider reads.
type claims struct {
	jwt.RegisteredClaims

	Email             string   `json:"email,omitempty"`
	PreferredUsername string   `json:"preferred_username,omitempty"`
	Groups            []string `json:"groups,omitempty"`
}

// New constructs a Provider. Discovery and the JWKS load happen in Start.
func New(log logrus.FieldLogger, cfg Config) *Provider {
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Provider{
		cfg:           cfg,
		log:           log.WithField("package", "protection/bearer"),
		allowedGroups: protection.NewGroupSet(cfg.AllowedGroups),
	}
}

// Name returns "bearer".
func (p *Provider) Name() string { return "bearer" }

// Start resolves the issuer's JWKS through OIDC discovery and primes the
// background-refreshing key cache.
func (p *Provider) Start(ctx context.Context) error {
	if p.cfg.IssuerURL == "" {
		return errors.New("bearer: IssuerURL is required")
	}
	if len(p.cfg.Audiences) == 0 {
		return errors.New("bearer: at least one audience is required")
	}

	doc, err := auth.FetchDiscovery(ctx, p.cfg.HTTPClient, p.cfg.IssuerURL)
	if err != nil {
		return fmt.Errorf("bearer: %w", err)
	}
	// Compare modulo a trailing slash (Authentik advertises one), but
	// verify "iss" against the document's exact spelling, which is what
	// the IdP puts into its tokens.
	if strings.TrimRight(doc.Issuer, "/") != strings.TrimRight(p.cfg.IssuerURL, "/") {
		return fmt.Errorf("bearer: discovery issuer mismatch: configured %q, document %q", p.cfg.IssuerURL, doc.Issuer)
	}
	p.issuer = doc.Issuer

	kf, err := keyfunc.NewDefaultCtx(ctx, []string{doc.JWKSURI})
	if err != nil {
		return fmt.Errorf("bearer: jwks load %s: %w", doc.JWKSURI, err)
	}
	p.kf = kf

	p.log.WithFields(logrus.Fields{
		"issuer":    p.issuer,
		"audiences": p.cfg.Audiences,
		"groups":    p.cfg.AllowedGroups,
	}).Info("bearer provider ready")
	return nil
}

// Stop is a no-op; the JWKS refresher stops with the Start context.
func (p *Provider) Stop() error { return nil }

// RegisterRoutes is a no-op: the provider has no interactive routes. Its
// machine token alias (/<name>/token) is mounted by the server.
func (p *Provider) RegisterRoutes(_ *mux.Router) {}

// LoginURL is empty: there is no interactive login entry, so the
// provider never appears on the selector page.
func (p *Provider) LoginURL(_ string) string { return "" }

// Logout has nothing to clear — the client simply stops sending the token.
func (p *Provider) Logout(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"loggedOut":true}` + "\n"))
}

// Authenticate checks the request's bearer token.
func (p *Provider) Authenticate(_ context.Context, r *http.Request) (protection.Outcome, error) {
	return p.authenticate(r), nil
}

// AuthenticateAmbient is Authenticate: the bearer token is the only
// credential the provider knows, and it never redirects.
func (p *Provider) AuthenticateAmbient(_ context.Context, r *http.Request) (protection.Outcome, error) {
	return p.authenticate(r), nil
}

// authenticate returns an Identity for a valid token, 401 for a missing or
// invalid one, and 403 for a valid token whose groups are not allowed.
func (p *Provider) authenticate(r *http.Request) protection.Outcome {
	raw, ok := bearerToken(r)
	if !ok {
		return unauthenticated(http.StatusUnauthorized, "")
	}

	c, err := p.verify(raw)
	if err != nil {
		p.log.WithError(err).Debug("bearer token rejected")
		return unauthenticated(http.StatusUnauthorized, "invalid_token")
	}

	if !p.allowedGroups.Allows(c.Groups) {
		p.log.WithFields(logrus.Fields{
			"sub":    c.Subject,
			"groups": strings.Join(c.Groups, ", "),
		}).Info("bearer token holder not in any allowed group")
		return unauthenticated(http.StatusForbidden, "insufficient_scope")
	}

	subject := c.Email
	if subject == "" {
		subject = c.PreferredUsername
	}
	if subject == "" {
		subject = c.Subject
	}
	return protection.Outcome{Identity: &protection.Identity{Subject: subject, Email: c.Email}}
}

// verify checks signature, issuer, audience, and expiry.
func (p *Provider) verify(raw string) (*claims, error) {
	parser := jwt.NewParser(
		jwt.WithValidMethods(signingMethods),
		jwt.WithIssuer(p.issuer),
		jwt.WithAudience(p.cfg.Audiences...),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(p.cfg.Now),
	)
	c := &claims{}
	if _, err := parser.ParseWithClaims(raw, c, p.kf.Keyfunc); err != nil {
		return nil, err
	}
	if c.Subject == "" {
		return nil, errors.New("token has no sub claim")
	}
	return c, nil
}

// bearerToken extracts the RFC 6750 bearer credential. The scheme is
// case-insensitive; any other scheme (e.g. Basic) is not ours.
func bearerToken(r *http.Request) (string, bool) {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)
	return token, token != ""
}

// unauthenticated builds an RFC 6750 §3 challenge outcome.
func unauthenticated(status int, errCode string) protection.Outcome {
	challenge := `Bearer realm="authenticatoor"`
	if errCode != "" {
		challenge += `, error="` + errCode + `"`
	}
	return protection.Outcome{
		Status:    status,
		Challenge: http.Header{"Www-Authenticate": {challenge}},
	}
}
