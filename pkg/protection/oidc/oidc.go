// Package oidc implements protection.Provider for an OpenID Connect IdP.
//
// Designed against the central ethpandaops dex deployment + the
// oidc-relay ingress (see platform/applications/oidc-relay): a single
// shared dex staticClient registers one redirect URI (the relay), and the
// relay forwards each callback to the originating authenticatoor based on
// the host encoded in the OAuth `state` parameter. That lets per-devnet
// authenticatoor deployments come online without any dex config change.
//
// The provider also works without a relay — set CallbackURL to
// <PublicURL><CallbackPath> and register that with the IdP directly.
//
// State encoding contract (matches the relay's regex):
//
//	state = "<public-url>~<random-nonce>"
//
// where <public-url> is the originating authenticatoor's externally-
// visible URL prefix (scheme + host + optional port; the relay's regex
// constrains it to *.ethpandaops.io / *.localhost / 127.0.0.1) and
// <random-nonce> is a 128-bit base64url value. The nonce is also stored
// in the HMAC-signed state cookie alongside the original returnTo URL;
// the callback compares the URL nonce to the cookie's nonce to bind the
// flow to this browser (CSRF defense), and feeds the nonce to the OIDC
// id_token `nonce` claim check (replay defense).
package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"

	"github.com/ethpandaops/service-authenticatoor/pkg/protection"
	"github.com/ethpandaops/service-authenticatoor/pkg/session"
)

// Defaults applied when corresponding Config fields are empty.
const (
	DefaultCallbackPath      = "/auth/oidc/callback"
	DefaultSessionCookieName = "authenticatoor_oidc_session"
	DefaultStateCookieName   = "authenticatoor_oidc_state"
	DefaultSessionTTL        = 12 * time.Hour
	DefaultStateTTL          = 10 * time.Minute
)

// stateDelimiter separates the public URL from the nonce in the state
// parameter. Chosen because it doesn't require URL-encoding and is not
// part of base64url's alphabet, so it never collides with the nonce.
const stateDelimiter = "~"

// Config configures the oidc provider.
type Config struct {
	// IssuerURL is the IdP issuer (e.g. dex's external URL). The provider
	// fetches <IssuerURL>/.well-known/openid-configuration at Start to
	// resolve the authorize / token / jwks endpoints. Required.
	IssuerURL string
	// CallbackURL is the absolute URL registered at the IdP as this
	// client's redirect_uri. Required.
	//
	// Two deployment shapes:
	//   - With a callback relay (the standard ethpandaops setup):
	//     CallbackURL is the relay's URL (shared across every
	//     authenticatoor instance using the same IdP client). The relay
	//     forwards the callback back here based on the host encoded in
	//     the state parameter.
	//   - Direct, no relay: CallbackURL is <PublicURL><CallbackPath>.
	//     Useful for single-instance deployments where you control the
	//     IdP client config and don't need to share it.
	CallbackURL string
	// PublicURL is the externally-visible base URL of this authenticatoor
	// instance (scheme + host + optional port, no path). Encoded into
	// every authorize request's state parameter so the relay can route
	// the callback back here. Must match the relay's allow-list regex.
	// Required.
	PublicURL string

	// ClientID is the OAuth client_id registered at the IdP. Required.
	ClientID string
	// ClientSecret takes precedence when set; otherwise ClientSecretFile
	// is read at Start. Either must be supplied (the shared client is a
	// confidential client at dex, not public).
	ClientSecret     string
	ClientSecretFile string

	// SessionKey is the HMAC key for the session and state cookies. Derived
	// in main.go from the JWT signing key via issuer.DeriveHMACKey so
	// there's no separate secret to manage. Must be at least 16 bytes.
	// Required.
	SessionKey []byte

	// CallbackPath is the local path that handles the OIDC callback.
	// In a relay-fronted deployment, the IdP only ever sees CallbackURL
	// (the relay's URL) and the relay forwards to <PublicURL><CallbackPath>.
	// In a direct deployment, CallbackURL should equal
	// <PublicURL><CallbackPath>. Default "/auth/oidc/callback".
	CallbackPath string
	// SessionCookieName is the name of the session cookie. Default
	// "authenticatoor_oidc_session".
	SessionCookieName string
	// StateCookieName is the name of the OAuth state cookie. Default
	// "authenticatoor_oidc_state".
	StateCookieName string
	// SessionTTL is the session cookie lifetime. Default 12h.
	SessionTTL time.Duration

	// AllowedGroups lists groups (as emitted by the IdP) whose members may
	// authenticate. For dex's GitHub connector each group is either a bare
	// org name (e.g. "ethpandaops") or "<org>:<team>" (e.g.
	// "EthDevOpsAccess:validatorops"). Comparison is case-insensitive.
	//
	// Matching:
	//   - Exact match: an entry "foo:bar" matches the token group
	//     "foo:bar" only.
	//   - Org-prefix match: an entry "foo" (no colon) matches "foo" AND
	//     "foo:<any-team>". Useful because dex's github connector emits
	//     `<org>:<team>` even for orgs configured without a `teams:`
	//     filter, so a bare org in the allow-list would otherwise never
	//     match.
	//
	// When empty, every user the IdP authenticates is accepted — the
	// upstream connector's allow-list is treated as authoritative. The
	// ethpandaops dex connector's `orgs:` field gates auth before any
	// token is issued, so an empty AllowedGroups means "inherit dex's
	// allow-list verbatim". Use the field to narrow further per-instance.
	AllowedGroups []string
	// Scopes overrides the OIDC scopes requested. Defaults to
	// ["openid", "email", "groups"]. `openid` is required.
	Scopes []string

	// HTTPClient is the http.Client used for discovery / token endpoint
	// calls. Defaults to a 10s-timeout client.
	HTTPClient *http.Client
	// Now overrides time.Now for deterministic tests.
	Now func() time.Time
}

// Provider implements protection.Provider for OIDC.
type Provider struct {
	cfg           Config
	log           logrus.FieldLogger
	clientSecret  []byte
	sessionSecret []byte
	httpClient    *http.Client
	disco         *discovery
	verifier      *idTokenVerifier
	allowedGroups map[string]struct{}
	scopeList     string
	cookieSecure  bool
}

var _ protection.Provider = (*Provider)(nil)

// New constructs a Provider. Defaults are filled in here; secret material,
// discovery fetch, and JWKS load happen in Start.
func New(log logrus.FieldLogger, cfg Config) *Provider {
	if cfg.CallbackPath == "" {
		cfg.CallbackPath = DefaultCallbackPath
	}
	if cfg.SessionCookieName == "" {
		cfg.SessionCookieName = DefaultSessionCookieName
	}
	if cfg.StateCookieName == "" {
		cfg.StateCookieName = DefaultStateCookieName
	}
	if cfg.SessionTTL == 0 {
		cfg.SessionTTL = DefaultSessionTTL
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}

	return &Provider{
		cfg:           cfg,
		log:           log.WithField("package", "protection/oidc"),
		httpClient:    cfg.HTTPClient,
		allowedGroups: allowedGroupsSet(cfg.AllowedGroups),
		scopeList:     strings.Join(scopes(cfg.Scopes), " "),
		cookieSecure:  strings.HasPrefix(cfg.PublicURL, "https://"),
	}
}

// Name returns "oidc".
func (p *Provider) Name() string { return "oidc" }

// Start validates required fields, loads secret material, fetches the
// IdP's discovery document, and primes the JWKS verifier.
func (p *Provider) Start(ctx context.Context) error {
	if p.cfg.IssuerURL == "" {
		return errors.New("oidc: IssuerURL is required")
	}
	if p.cfg.CallbackURL == "" {
		return errors.New("oidc: CallbackURL is required")
	}
	if p.cfg.PublicURL == "" {
		return errors.New("oidc: PublicURL is required")
	}
	if p.cfg.ClientID == "" {
		return errors.New("oidc: ClientID is required")
	}

	cs, err := session.LoadSecret(p.cfg.ClientSecret, p.cfg.ClientSecretFile, "ClientSecret")
	if err != nil {
		return err
	}
	p.clientSecret = cs

	if len(p.cfg.SessionKey) < 16 {
		return errors.New("oidc: SessionKey must be at least 16 bytes")
	}
	p.sessionSecret = p.cfg.SessionKey

	disco, err := fetchDiscovery(ctx, p.httpClient, p.cfg.IssuerURL)
	if err != nil {
		return err
	}
	p.disco = disco

	verifier, err := newIDTokenVerifier(ctx, disco.JWKSURI, disco.Issuer, p.cfg.ClientID, p.cfg.Now)
	if err != nil {
		return err
	}
	p.verifier = verifier

	p.log.WithFields(logrus.Fields{
		"issuer":       disco.Issuer,
		"callbackURL":  p.cfg.CallbackURL,
		"callbackPath": p.cfg.CallbackPath,
		"clientID":     p.cfg.ClientID,
		"groups":       p.cfg.AllowedGroups,
		"scopes":       p.scopeList,
	}).Info("oidc provider ready")
	return nil
}

// Stop is a no-op.
func (p *Provider) Stop() error { return nil }

// RegisterRoutes attaches the OIDC callback handler. It runs on the
// parent router (not the /auth/* subrouter) so the auth middleware is
// bypassed — the request IS the act of authenticating.
func (p *Provider) RegisterRoutes(r *mux.Router) {
	r.HandleFunc(p.cfg.CallbackPath, p.handleCallback).Methods(http.MethodGet)
}

// Authenticate looks for a valid session cookie. When absent or stale the
// provider returns a redirect to the IdP's authorize endpoint, with a
// signed state cookie that carries the OIDC nonce + the original request
// URL so the callback can complete the round-trip.
func (p *Provider) Authenticate(_ context.Context, r *http.Request) (protection.Outcome, error) {
	if c, err := r.Cookie(p.cfg.SessionCookieName); err == nil {
		sub, email, perr := session.Parse(p.sessionSecret, c.Value, p.cfg.Now())
		if perr == nil {
			return protection.Outcome{Identity: &protection.Identity{
				Subject: sub,
				Email:   email,
			}}, nil
		}
		p.log.WithError(perr).Debug("session cookie invalid; redirecting to IdP")
	}

	nonce, err := session.NewNonce()
	if err != nil {
		return protection.Outcome{}, fmt.Errorf("oidc: nonce: %w", err)
	}
	stateBlob, err := session.SignState(p.sessionSecret, nonce, r.URL.RequestURI(), p.cfg.Now(), DefaultStateTTL)
	if err != nil {
		return protection.Outcome{}, fmt.Errorf("oidc: sign state: %w", err)
	}
	stateCookie := &http.Cookie{
		Name:     p.cfg.StateCookieName,
		Value:    stateBlob,
		Path:     p.cfg.CallbackPath,
		MaxAge:   int(DefaultStateTTL.Seconds()),
		HttpOnly: true,
		Secure:   p.cookieSecure,
		SameSite: http.SameSiteLaxMode,
	}

	return protection.Outcome{
		RedirectTo: p.authorizeRedirect(nonce),
		SetCookies: []*http.Cookie{stateCookie},
	}, nil
}

// authorizeRedirect builds the IdP authorize URL. The state parameter
// is "<publicURL>~<nonce>" — the prefix lets the relay route the
// callback back to this instance, and the nonce binds the URL to the
// state cookie on this browser (CSRF defense; the cookie carries the
// full signed payload including returnTo).
func (p *Provider) authorizeRedirect(nonce string) string {
	v := url.Values{}
	v.Set("client_id", p.cfg.ClientID)
	v.Set("redirect_uri", p.cfg.CallbackURL)
	v.Set("response_type", "code")
	v.Set("scope", p.scopeList)
	v.Set("nonce", nonce)
	v.Set("state", strings.TrimRight(p.cfg.PublicURL, "/")+stateDelimiter+nonce)
	return p.disco.AuthorizationEndpoint + "?" + v.Encode()
}

// handleCallback completes the OIDC dance: verify the state cookie matches
// the URL state, exchange the code for tokens at the IdP, verify the
// id_token (signature + iss + aud + nonce), gate on allowedGroups, set
// the session cookie, and 302 back to the originally-requested URL.
func (p *Provider) handleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if errCode := q.Get("error"); errCode != "" {
		desc := q.Get("error_description")
		p.log.WithFields(logrus.Fields{"error": errCode, "desc": desc}).Warn("idp returned error")
		http.Error(w, fmt.Sprintf("idp error: %s: %s", errCode, desc), http.StatusBadGateway)
		return
	}

	code := q.Get("code")
	stateParam := q.Get("state")
	if code == "" || stateParam == "" {
		http.Error(w, "missing code or state", http.StatusBadRequest)
		return
	}

	// State value shape: "<public-url>~<nonce>". Use LastIndex defensively
	// in case the public URL ever contains `~` (it shouldn't).
	idx := strings.LastIndex(stateParam, stateDelimiter)
	if idx < 0 {
		http.Error(w, "malformed state", http.StatusBadRequest)
		return
	}
	urlStatePrefix := stateParam[:idx]
	urlStateNonce := stateParam[idx+len(stateDelimiter):]

	// Anchor: the state must claim THIS instance. A flow that landed
	// here with a different public URL is either misrouted by the relay
	// (allow-list regex too loose) or crafted by an attacker.
	if urlStatePrefix != strings.TrimRight(p.cfg.PublicURL, "/") {
		p.log.WithFields(logrus.Fields{
			"got":      urlStatePrefix,
			"expected": p.cfg.PublicURL,
		}).Warn("state prefix mismatch — flow originated elsewhere")
		http.Error(w, "state prefix mismatch", http.StatusBadRequest)
		return
	}

	stateCookie, err := r.Cookie(p.cfg.StateCookieName)
	if err != nil {
		http.Error(w, "missing state cookie", http.StatusBadRequest)
		return
	}
	nonce, returnTo, err := session.ParseState(p.sessionSecret, stateCookie.Value, p.cfg.Now())
	if err != nil {
		http.Error(w, "invalid state cookie", http.StatusBadRequest)
		return
	}
	// CSRF defense: the nonce in the URL must equal the nonce embedded
	// in the (HMAC-signed) cookie. The cookie alone proves we issued
	// the flow; the comparison proves this *callback's URL* belongs to
	// the flow this browser initiated.
	if urlStateNonce != nonce {
		http.Error(w, "state nonce mismatch", http.StatusBadRequest)
		return
	}

	// Clear the now-consumed state cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     p.cfg.StateCookieName,
		Value:    "",
		Path:     p.cfg.CallbackPath,
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	idToken, err := p.exchangeCode(r.Context(), code)
	if err != nil {
		p.log.WithError(err).Warn("oidc code exchange failed")
		http.Error(w, "code exchange failed", http.StatusBadGateway)
		return
	}

	claims, err := p.verifier.verify(idToken, nonce)
	if err != nil {
		p.log.WithError(err).Warn("id_token verification failed")
		http.Error(w, "id_token invalid", http.StatusForbidden)
		return
	}

	if !groupAllowed(claims.Groups, p.allowedGroups) {
		p.log.WithFields(logrus.Fields{
			"sub":           claims.Subject,
			"email":         claims.Email,
			"groups":        strings.Join(claims.Groups, ", "),
			"allowedGroups": strings.Join(p.cfg.AllowedGroups, ", "),
		}).Warn("user not in any allowed group")
		http.Error(w, fmt.Sprintf(
			"your account %q is not in any allowed group.\n"+
				"  allowed: [%s]\n"+
				"  your groups: [%s]",
			claims.Email,
			strings.Join(p.cfg.AllowedGroups, ", "),
			strings.Join(claims.Groups, ", "),
		), http.StatusForbidden)
		return
	}

	subject := claims.Email
	if subject == "" {
		subject = claims.Subject
	}
	cookie, err := p.signSessionCookie(subject, claims.Email)
	if err != nil {
		p.log.WithError(err).Error("session cookie signing failed")
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, cookie)

	if returnTo == "" || !strings.HasPrefix(returnTo, "/") {
		returnTo = "/"
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, returnTo, http.StatusFound)
}

// signSessionCookie builds the HttpOnly session cookie for the
// authenticated user.
//
// SameSite=None + Secure is required so the cross-site iframe flows
// (`/auth/embed` for silent token, `/auth/logout` for clearing) can
// read and overwrite the cookie. Browsers treat *.localhost as a
// secure context, so Secure=true works for HTTP local dev too —
// non-localhost plain HTTP isn't a supported deployment.
func (p *Provider) signSessionCookie(sub, email string) (*http.Cookie, error) {
	signed, err := session.Sign(p.sessionSecret, sub, email, p.cfg.SessionTTL, p.cfg.Now())
	if err != nil {
		return nil, err
	}
	return &http.Cookie{
		Name:     p.cfg.SessionCookieName,
		Value:    signed,
		Path:     "/",
		MaxAge:   int(p.cfg.SessionTTL.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	}, nil
}

// ClearSessionCookie returns a cookie that clears the session. Used by
// the logout endpoint. Path / Secure / SameSite must match
// signSessionCookie so the browser treats the two as the same cookie
// and overwrites the live session.
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

// Logout clears the session cookie. Subsequent /auth/* requests redirect
// through the OIDC flow again. The IdP session itself is left intact —
// dex 2.x has no robust RP-initiated logout, and clearing only the local
// cookie matches the github provider's behavior.
func (p *Provider) Logout(w http.ResponseWriter, _ *http.Request) {
	http.SetCookie(w, p.ClearSessionCookie())
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"loggedOut": true})
}

// tokenResponse is the subset of the OIDC token endpoint response we read.
type tokenResponse struct {
	IDToken     string `json:"id_token"`
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

// exchangeCode posts the authorization_code grant to the IdP token
// endpoint. The redirect_uri MUST equal the one used in the authorize
// request (the relay URL), per RFC 6749 §4.1.3 — otherwise the IdP
// rejects the exchange.
func (p *Provider) exchangeCode(ctx context.Context, code string) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", p.cfg.ClientID)
	form.Set("client_secret", string(p.clientSecret))
	form.Set("code", code)
	form.Set("redirect_uri", p.cfg.CallbackURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.disco.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("token request: status %d: %s", resp.StatusCode, body)
	}
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", fmt.Errorf("token decode: %w (body=%s)", err, body)
	}
	if tr.Error != "" {
		return "", fmt.Errorf("token error: %s: %s", tr.Error, tr.ErrorDesc)
	}
	if tr.IDToken == "" {
		return "", errors.New("token response missing id_token")
	}
	return tr.IDToken, nil
}
