// Package github implements protection.Provider for GitHub OAuth with
// organization-membership gating.
//
// Authenticated users are tracked via a signed session cookie issued by
// this service; unauthenticated requests to /auth/* are redirected to
// GitHub's authorize endpoint and bounce back through /auth/oauth/callback
// to set the cookie. Membership in any of the configured allowedOrgs is
// required; users outside the allow-list get a 403 from the callback.
//
// The JWT issued downstream uses the GitHub login as "sub" and the
// primary verified email as "email"; downstream applications choose
// which fits their model.
package github

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"

	"github.com/ethpandaops/service-authenticatoor/pkg/protection"
)

// Defaults applied when corresponding Config fields are empty.
const (
	DefaultCallbackPath      = "/auth/oauth/callback"
	DefaultSessionCookieName = "authenticatoor_session"
	DefaultStateCookieName   = "authenticatoor_oauth_state"
	DefaultSessionTTL        = 12 * time.Hour
	DefaultStateTTL          = 10 * time.Minute

	githubAuthorizeURL = "https://github.com/login/oauth/authorize"
	githubTokenURL     = "https://github.com/login/oauth/access_token"
	githubAPIBase      = "https://api.github.com"
)

// Config configures the github provider.
type Config struct {
	// ClientID is the OAuth app's client_id. Required.
	ClientID string
	// ClientSecret takes precedence when set; otherwise ClientSecretFile
	// is read at Start. Either must be supplied.
	ClientSecret     string
	ClientSecretFile string
	// SessionSecret takes precedence when set; otherwise SessionSecretFile
	// is read at Start. The secret signs the session cookie and (with a
	// derived subkey) the OAuth state cookie.
	SessionSecret     string
	SessionSecretFile string
	// CallbackPath is the path of the OAuth redirect URI, registered on
	// the public router. Defaults to "/auth/oauth/callback". Must match
	// the redirect_uri configured in the GitHub OAuth app.
	CallbackPath string
	// PublicURL is the externally-visible base URL of the auth service.
	// Used to build the absolute redirect_uri sent to GitHub. Required.
	PublicURL string
	// SessionCookieName is the name of the session cookie. Defaults to
	// "authenticatoor_session".
	SessionCookieName string
	// StateCookieName is the name of the OAuth state cookie. Defaults to
	// "authenticatoor_oauth_state".
	StateCookieName string
	// SessionTTL is the session cookie lifetime. Defaults to 12h.
	SessionTTL time.Duration
	// AllowedOrgs is the GitHub orgs whose members may authenticate.
	// At least one must be supplied.
	AllowedOrgs []string

	// HTTPClient is the http.Client used for GitHub API calls. Defaults
	// to a sensible client; tests inject httptest.NewServer here.
	HTTPClient *http.Client
	// APIBaseURL overrides the GitHub API base URL. Default
	// "https://api.github.com". Tests point this at an httptest server.
	APIBaseURL string
	// AuthorizeURL overrides the GitHub authorize URL. Default
	// "https://github.com/login/oauth/authorize". Tests point this at an
	// httptest server.
	AuthorizeURL string
	// TokenURL overrides the GitHub token URL. Default
	// "https://github.com/login/oauth/access_token". Tests point this at
	// an httptest server.
	TokenURL string
	// Now overrides time.Now for deterministic tests.
	Now func() time.Time
}

// Provider implements protection.Provider for GitHub OAuth.
type Provider struct {
	cfg            Config
	log            logrus.FieldLogger
	clientSecret   []byte
	sessionSecret  []byte
	httpClient     *http.Client
	authorizeURL   string
	tokenURL       string
	apiBase        string
	allowedOrgsSet map[string]struct{}
}

var _ protection.Provider = (*Provider)(nil)

// New constructs a Provider. Defaults are filled in here; secret material
// and reachability checks happen in Start.
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
	if cfg.AuthorizeURL == "" {
		cfg.AuthorizeURL = githubAuthorizeURL
	}
	if cfg.TokenURL == "" {
		cfg.TokenURL = githubTokenURL
	}
	if cfg.APIBaseURL == "" {
		cfg.APIBaseURL = githubAPIBase
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}

	allowed := make(map[string]struct{}, len(cfg.AllowedOrgs))
	for _, o := range cfg.AllowedOrgs {
		allowed[strings.ToLower(o)] = struct{}{}
	}

	return &Provider{
		cfg:            cfg,
		log:            log.WithField("package", "protection/github"),
		httpClient:     cfg.HTTPClient,
		authorizeURL:   cfg.AuthorizeURL,
		tokenURL:       cfg.TokenURL,
		apiBase:        cfg.APIBaseURL,
		allowedOrgsSet: allowed,
	}
}

// Name returns "github".
func (p *Provider) Name() string { return "github" }

// Start validates required fields and loads secret material.
func (p *Provider) Start(_ context.Context) error {
	if p.cfg.ClientID == "" {
		return errors.New("github: ClientID is required")
	}
	if p.cfg.PublicURL == "" {
		return errors.New("github: PublicURL is required")
	}
	if len(p.allowedOrgsSet) == 0 {
		return errors.New("github: AllowedOrgs must list at least one org")
	}
	cs, err := loadSecret(p.cfg.ClientSecret, p.cfg.ClientSecretFile, "ClientSecret")
	if err != nil {
		return err
	}
	p.clientSecret = cs

	ss, err := loadSecret(p.cfg.SessionSecret, p.cfg.SessionSecretFile, "SessionSecret")
	if err != nil {
		return err
	}
	if len(ss) < 16 {
		return errors.New("github: SessionSecret must be at least 16 bytes")
	}
	p.sessionSecret = ss

	p.log.WithField("orgs", p.cfg.AllowedOrgs).
		WithField("callback", p.cfg.CallbackPath).
		Info("github oauth provider ready")
	return nil
}

// Stop is a no-op.
func (p *Provider) Stop() error { return nil }

// RegisterRoutes attaches the OAuth callback handler. It runs on the
// parent router (not the /auth/* subrouter) so the auth middleware is
// bypassed — the request IS the act of authenticating.
func (p *Provider) RegisterRoutes(r *mux.Router) {
	r.HandleFunc(p.cfg.CallbackPath, p.handleCallback).Methods(http.MethodGet)
}

// Authenticate looks for a valid session cookie. When absent or stale the
// provider returns a redirect to GitHub's authorize endpoint, with a
// signed state cookie that carries the original request URL so the
// callback can complete the round-trip.
func (p *Provider) Authenticate(_ context.Context, r *http.Request) (protection.Outcome, error) {
	if c, err := r.Cookie(p.cfg.SessionCookieName); err == nil {
		login, email, perr := parseSession(p.sessionSecret, c.Value, p.cfg.Now())
		if perr == nil {
			return protection.Outcome{Identity: &protection.Identity{
				Subject: login,
				Email:   email,
			}}, nil
		}
		p.log.WithError(perr).Debug("session cookie invalid; redirecting to github")
	}

	state, err := newState()
	if err != nil {
		return protection.Outcome{}, fmt.Errorf("github: state: %w", err)
	}
	stateCookie := p.signedStateCookie(state, r.URL.RequestURI())

	redirect := p.authorizeRedirect(state)
	return protection.Outcome{
		RedirectTo: redirect,
		SetCookies: []*http.Cookie{stateCookie},
	}, nil
}

// authorizeRedirect builds the GitHub authorize URL.
func (p *Provider) authorizeRedirect(state string) string {
	v := url.Values{}
	v.Set("client_id", p.cfg.ClientID)
	v.Set("redirect_uri", p.redirectURI())
	v.Set("scope", "read:org user:email")
	v.Set("state", state)
	return p.authorizeURL + "?" + v.Encode()
}

func (p *Provider) redirectURI() string {
	return strings.TrimRight(p.cfg.PublicURL, "/") + p.cfg.CallbackPath
}

// signedStateCookie packs the random state nonce + the original request
// URL into a signed JWT and returns it as a short-lived cookie scoped to
// the callback path.
func (p *Provider) signedStateCookie(state, returnTo string) *http.Cookie {
	tok, err := signState(p.sessionSecret, state, returnTo, p.cfg.Now(), DefaultStateTTL)
	if err != nil {
		// signing only fails on a misconfigured secret which Start would
		// have rejected; falling back to plain state means the callback
		// will reject the cookie which fails closed.
		tok = ""
	}
	return &http.Cookie{
		Name:     p.cfg.StateCookieName,
		Value:    tok,
		Path:     p.cfg.CallbackPath,
		MaxAge:   int(DefaultStateTTL.Seconds()),
		HttpOnly: true,
		Secure:   strings.HasPrefix(p.cfg.PublicURL, "https://"),
		SameSite: http.SameSiteLaxMode,
	}
}

// handleCallback completes the OAuth dance: verify state cookie, exchange
// code for an access token, fetch user/email/orgs, gate on allowedOrgs,
// set the session cookie, and 302 back to the original URL.
func (p *Provider) handleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	code := q.Get("code")
	stateParam := q.Get("state")
	if code == "" || stateParam == "" {
		http.Error(w, "missing code or state", http.StatusBadRequest)
		return
	}

	stateCookie, err := r.Cookie(p.cfg.StateCookieName)
	if err != nil {
		http.Error(w, "missing state cookie", http.StatusBadRequest)
		return
	}
	expectedState, returnTo, err := parseState(p.sessionSecret, stateCookie.Value, p.cfg.Now())
	if err != nil {
		http.Error(w, "invalid state cookie", http.StatusBadRequest)
		return
	}
	if expectedState != stateParam {
		http.Error(w, "state mismatch", http.StatusBadRequest)
		return
	}

	// Clear the now-consumed state cookie.
	http.SetCookie(w, &http.Cookie{
		Name: p.cfg.StateCookieName, Value: "", Path: p.cfg.CallbackPath,
		MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})

	token, err := p.exchangeCode(r.Context(), code)
	if err != nil {
		p.log.WithError(err).Warn("oauth code exchange failed")
		http.Error(w, "code exchange failed", http.StatusBadGateway)
		return
	}

	user, err := p.fetchUser(r.Context(), token)
	if err != nil {
		p.log.WithError(err).Warn("github user fetch failed")
		http.Error(w, "user lookup failed", http.StatusBadGateway)
		return
	}

	orgs, err := p.fetchOrgs(r.Context(), token)
	if err != nil {
		p.log.WithError(err).Warn("github orgs fetch failed")
		http.Error(w, "orgs lookup failed", http.StatusBadGateway)
		return
	}
	if !p.orgAllowed(orgs) {
		p.log.WithField("login", user.Login).Warn("user not in any allowed org")
		http.Error(w, "your GitHub account is not a member of any allowed org", http.StatusForbidden)
		return
	}

	email := user.Email
	if email == "" {
		// Fall back to the verified primary from /user/emails.
		email, _ = p.fetchPrimaryEmail(r.Context(), token)
	}

	cookie, err := p.signSessionCookie(user.Login, email)
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

// orgAllowed reports whether any of the supplied orgs is in the allow-list.
// Comparison is case-insensitive.
func (p *Provider) orgAllowed(orgs []githubOrg) bool {
	for _, o := range orgs {
		if _, ok := p.allowedOrgsSet[strings.ToLower(o.Login)]; ok {
			return true
		}
	}
	return false
}

// signSessionCookie builds the HttpOnly session cookie for the
// authenticated user.
func (p *Provider) signSessionCookie(login, email string) (*http.Cookie, error) {
	signed, err := signSession(p.sessionSecret, login, email, p.cfg.SessionTTL, p.cfg.Now())
	if err != nil {
		return nil, err
	}
	return &http.Cookie{
		Name:     p.cfg.SessionCookieName,
		Value:    signed,
		Path:     "/",
		MaxAge:   int(p.cfg.SessionTTL.Seconds()),
		HttpOnly: true,
		Secure:   strings.HasPrefix(p.cfg.PublicURL, "https://"),
		SameSite: http.SameSiteLaxMode,
	}, nil
}

// ClearSessionCookie returns a cookie that clears the session. Used by
// the logout endpoint.
func (p *Provider) ClearSessionCookie() *http.Cookie {
	return &http.Cookie{
		Name:     p.cfg.SessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   strings.HasPrefix(p.cfg.PublicURL, "https://"),
		SameSite: http.SameSiteLaxMode,
	}
}

// Logout clears the session cookie. Subsequent /auth/* requests redirect
// through the OAuth flow again.
func (p *Provider) Logout(w http.ResponseWriter, _ *http.Request) {
	http.SetCookie(w, p.ClearSessionCookie())
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"loggedOut": true})
}

// ─── github API calls ────────────────────────────────────────────────────────

type githubUser struct {
	Login string `json:"login"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

type githubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

type githubOrg struct {
	Login string `json:"login"`
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

func (p *Provider) exchangeCode(ctx context.Context, code string) (string, error) {
	form := url.Values{}
	form.Set("client_id", p.cfg.ClientID)
	form.Set("client_secret", string(p.clientSecret))
	form.Set("code", code)
	form.Set("redirect_uri", p.redirectURI())

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.tokenURL, strings.NewReader(form.Encode()))
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
	if tr.AccessToken == "" {
		return "", errors.New("token response missing access_token")
	}
	return tr.AccessToken, nil
}

func (p *Provider) fetchUser(ctx context.Context, token string) (*githubUser, error) {
	var u githubUser
	if err := p.apiGet(ctx, token, "/user", &u); err != nil {
		return nil, err
	}
	if u.Login == "" {
		return nil, errors.New("github user missing login")
	}
	return &u, nil
}

func (p *Provider) fetchPrimaryEmail(ctx context.Context, token string) (string, error) {
	var emails []githubEmail
	if err := p.apiGet(ctx, token, "/user/emails", &emails); err != nil {
		return "", err
	}
	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email, nil
		}
	}
	return "", nil
}

func (p *Provider) fetchOrgs(ctx context.Context, token string) ([]githubOrg, error) {
	var orgs []githubOrg
	if err := p.apiGet(ctx, token, "/user/orgs", &orgs); err != nil {
		return nil, err
	}
	return orgs, nil
}

// apiGet issues an authenticated GET to the GitHub API and decodes a JSON
// response into out.
func (p *Provider) apiGet(ctx context.Context, token, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.apiBase+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("github api %s: %w", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("github api %s: status %d: %s", path, resp.StatusCode, body)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("github api %s decode: %w", path, err)
	}
	return nil
}

// ─── helpers ─────────────────────────────────────────────────────────────────

// loadSecret returns inline if non-empty, else reads the file. One of the
// two must be supplied.
func loadSecret(inline, file, name string) ([]byte, error) {
	if inline != "" {
		return []byte(inline), nil
	}
	if file == "" {
		return nil, fmt.Errorf("github: %s or %sFile is required", name, name)
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("github: read %s: %w", file, err)
	}
	return []byte(strings.TrimSpace(string(data))), nil
}

// newState returns a 128-bit random base64url-encoded value.
func newState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
