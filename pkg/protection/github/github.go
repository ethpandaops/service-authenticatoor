// Package github implements protection.Provider for GitHub OAuth with
// organization-membership gating.
//
// Authenticated users are tracked via a signed session cookie issued by
// this service; unauthenticated requests to /auth/* are redirected to
// GitHub's authorize endpoint and bounce back through /github/callback
// to set the cookie. Membership in any of the configured allowedOrgs is
// required; users outside the allow-list get a 403 from the callback.
//
// The JWT issued downstream uses the GitHub login as "sub" and the
// primary verified email as "email"; downstream applications choose
// which fits their model.
package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"

	"github.com/ethpandaops/service-authenticatoor/pkg/protection"
	"github.com/ethpandaops/service-authenticatoor/pkg/session"
)

// Defaults applied when corresponding Config fields are empty.
const (
	DefaultLoginPath         = "/github/login"
	DefaultCallbackPath      = "/github/callback"
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
	// SessionKey is the HMAC key for the session and state cookies. Derived
	// in main.go from the JWT signing key via issuer.DeriveHMACKey so
	// there's no separate secret to manage. Must be at least 16 bytes.
	// Required.
	SessionKey []byte
	// LoginPath is the interactive login entry: it sets the state cookie
	// and redirects to GitHub's authorize endpoint. Defaults to
	// "/github/login".
	LoginPath string
	// CallbackPath is the path of the OAuth redirect URI, registered on
	// the public router. Defaults to "/github/callback". Must match the
	// redirect_uri configured in the GitHub OAuth app.
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

	// Teams are the static teams given to every identity this provider
	// authenticates (normalized at New; invalid names fail Start).
	Teams []string
	// TeamRules derive further teams from the attributes this provider
	// verified about the user (see the package documentation of each
	// provider for its attributes).
	TeamRules []protection.TeamRule
	// GrantMembers are the attribute members the grants section names
	// for this provider ("<provider>/<attribute>:<value>"). The provider
	// reports which of them an identity satisfies.
	GrantMembers []protection.AttributeMember

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
	teams          protection.Teams
	members        protection.Members
	door           session.Door
}

var (
	_ protection.Provider       = (*Provider)(nil)
	_ protection.SessionClearer = (*Provider)(nil)
)

// New constructs a Provider. Defaults are filled in here; secret material
// and reachability checks happen in Start.
func New(log logrus.FieldLogger, cfg Config) *Provider {
	if cfg.LoginPath == "" {
		cfg.LoginPath = DefaultLoginPath
	}
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
		teams:          protection.NewTeams(cfg.Teams, cfg.TeamRules),
		members:        protection.NewMembers(cfg.GrantMembers),
		door:           session.NewDoor("github", cfg.APIBaseURL),
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
	if err := p.teams.Err(); err != nil {
		return fmt.Errorf("github: %w", err)
	}
	cs, err := session.LoadSecret(p.cfg.ClientSecret, p.cfg.ClientSecretFile, "ClientSecret")
	if err != nil {
		return fmt.Errorf("github: %w", err)
	}
	p.clientSecret = cs

	if len(p.cfg.SessionKey) < 16 {
		return errors.New("github: SessionKey must be at least 16 bytes")
	}
	p.sessionSecret = p.cfg.SessionKey

	p.log.WithField("orgs", p.cfg.AllowedOrgs).
		WithField("callback", p.cfg.CallbackPath).
		WithField("teams", p.teams.Static()).
		WithField("teamRules", p.teams.Rules()).
		Info("github oauth provider ready")
	return nil
}

// Stop is a no-op.
func (p *Provider) Stop() error { return nil }

// RegisterRoutes attaches the login entry and the OAuth callback
// handler. They run on the parent router (not the /auth/* subrouter) so
// the auth middleware is bypassed — the request IS the act of
// authenticating.
func (p *Provider) RegisterRoutes(r *mux.Router) {
	r.HandleFunc(p.cfg.LoginPath, p.handleLoginStart).Methods(http.MethodGet)
	r.HandleFunc(p.cfg.CallbackPath, p.handleCallback).Methods(http.MethodGet)
}

// LoginURL returns the login entry path carrying returnTo.
func (p *Provider) LoginURL(returnTo string) string {
	v := url.Values{}
	v.Set("return_to", returnTo)
	return p.cfg.LoginPath + "?" + v.Encode()
}

// Authenticate looks for a valid session cookie. When absent or stale the
// outcome redirects to the login entry, which starts the OAuth flow.
func (p *Provider) Authenticate(_ context.Context, r *http.Request) (protection.Outcome, error) {
	if c, err := r.Cookie(p.cfg.SessionCookieName); err == nil {
		sess, perr := session.Parse(p.sessionSecret, p.door, c.Value, p.cfg.Now())
		if perr == nil {
			return protection.Outcome{Identity: &protection.Identity{
				Subject:        sess.Subject,
				Email:          sess.Email,
				SubjectIsEmail: sess.SubjectIsEmail,
				Teams:          p.teams.With(sess.Teams),
				Matches:        sess.Matches,
			}}, nil
		}
		p.log.WithError(perr).Debug("session cookie invalid; redirecting to login")
	}

	return protection.Outcome{RedirectTo: p.LoginURL(r.URL.RequestURI())}, nil
}

// handleLoginStart begins the OAuth dance: mint the state nonce, bind it
// to the (sanitized) return_to in the signed state cookie, and redirect
// to GitHub's authorize endpoint.
func (p *Provider) handleLoginStart(w http.ResponseWriter, r *http.Request) {
	state, err := session.NewNonce()
	if err != nil {
		p.log.WithError(err).Error("state nonce generation failed")
		http.Error(w, "state error", http.StatusInternalServerError)
		return
	}
	returnTo := protection.SafeReturnTo(r.URL.Query().Get("return_to"))
	http.SetCookie(w, p.signedStateCookie(state, returnTo))
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, p.authorizeRedirect(state), http.StatusFound)
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
	tok, err := session.SignState(p.sessionSecret, state, returnTo, p.cfg.Now(), DefaultStateTTL)
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
	expectedState, returnTo, err := session.ParseState(p.sessionSecret, stateCookie.Value, p.cfg.Now())
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

	token, scope, err := p.exchangeCode(r.Context(), code)
	if err != nil {
		p.log.WithError(err).Warn("oauth code exchange failed")
		http.Error(w, "code exchange failed", http.StatusBadGateway)
		return
	}
	p.log.WithField("scope", scope).Debug("github oauth code exchanged")

	profile, err := p.fetchProfile(r.Context(), token)
	if err != nil {
		p.log.WithError(err).Warn("github profile fetch failed")
		http.Error(w, "profile lookup failed", http.StatusBadGateway)
		return
	}

	if !p.orgAllowed(profile.Orgs) {
		p.log.WithFields(logrus.Fields{
			"login":       profile.Login,
			"orgs":        strings.Join(profile.Orgs, ", "),
			"allowedOrgs": strings.Join(p.cfg.AllowedOrgs, ", "),
			"scope":       scope,
		}).Warn("user not in any allowed org")
		http.Error(w, fmt.Sprintf(
			"your GitHub account %q is not in any allowed org.\n"+
				"  allowed: [%s]\n"+
				"  your visible memberships: [%s]\n"+
				"  granted oauth scopes: [%s]\n"+
				"if an expected org is missing, the OAuth App may not have been granted access to it — review at https://github.com/settings/connections/applications/%s",
			profile.Login,
			strings.Join(p.cfg.AllowedOrgs, ", "),
			strings.Join(profile.Orgs, ", "),
			scope,
			p.cfg.ClientID,
		), http.StatusForbidden)
		return
	}

	// Teams derived by the team rules are captured now and travel in the
	// session; the static teams are applied per request.
	attrs := profile.attributes()
	loginLog := p.log.WithField("login", profile.Login)
	teams := p.teams.Capture(loginLog, attrs)
	// So are the grant members the profile satisfies: only which ones,
	// never the profile itself.
	matches := p.members.Capture(loginLog, attrs, teams)
	p.log.WithFields(logrus.Fields{
		"login": profile.Login,
		"teams": p.teams.With(teams),
	}).Debug("github login resolved teams")

	cookie, err := p.signSessionCookie(profile.Login, profile.Email, teams, matches)
	if errors.Is(err, session.ErrTooLarge) {
		loginLog.WithError(err).Warn("login refused: the session does not fit a cookie")
		http.Error(w, protection.SessionTooLargeMessage, http.StatusForbidden)
		return
	}
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

// orgAllowed reports whether any of the supplied org logins is in the
// allow-list. Comparison is case-insensitive.
func (p *Provider) orgAllowed(orgs []string) bool {
	for _, o := range orgs {
		if _, ok := p.allowedOrgsSet[strings.ToLower(o)]; ok {
			return true
		}
	}
	return false
}

// userProfile is the merged view of a GitHub user fetched in handleCallback.
// Orgs unions /user/orgs (private memberships) and /users/{login}/orgs
// (public memberships), case-insensitively deduplicated.
type userProfile struct {
	Login string
	Email string
	Orgs  []string
}

// attributes are what this provider knows about an authenticated user,
// all of it from the API calls the org gate already makes:
//
//	login   the GitHub login
//	email   an email GitHub reports as verified (the public one if it
//	        is verified, else the primary verified one); absent when
//	        there is none or it cannot be told
//	orgs    the logins of the user's organizations (a list)
func (u *userProfile) attributes() protection.Attributes {
	orgs := make([]any, 0, len(u.Orgs))
	for _, o := range u.Orgs {
		orgs = append(orgs, o)
	}
	attrs := protection.Attributes{"login": u.Login, "orgs": orgs}
	if u.Email != "" {
		attrs["email"] = u.Email
	}
	return attrs
}

// fetchProfile fans out the four GitHub API calls needed to gate the
// session: /user (login + maybe email), /user/orgs (private memberships,
// requires the OAuth App to be approved by the org if it has third-party
// app restrictions), /users/{login}/orgs (public memberships, never
// subject to those restrictions — same data anyone could see), and
// /user/emails (fallback when the user keeps their primary email
// private). The public-orgs call depends on the login returned by /user,
// so it's chained off a 1-buffered channel; the other three start
// immediately.
//
// Only /user is fatal — if either orgs source fails we proceed with what
// we got, which is what makes the public/private union valuable: a
// transient failure of one endpoint doesn't lock everyone out as long as
// the other succeeds.
func (p *Provider) fetchProfile(ctx context.Context, token string) (*userProfile, error) {
	var (
		user        *githubUser
		userErr     error
		privateOrgs []githubOrg
		privateErr  error
		publicOrgs  []githubOrg
		publicErr   error
		emails      []githubEmail
		emailsErr   error
	)

	loginCh := make(chan string, 1)

	var wg sync.WaitGroup
	wg.Add(4)

	go func() {
		defer wg.Done()
		defer close(loginCh)
		user, userErr = p.fetchUser(ctx, token)
		if userErr == nil && user != nil {
			loginCh <- user.Login
		}
	}()

	go func() {
		defer wg.Done()
		privateOrgs, privateErr = p.fetchOrgs(ctx, token)
	}()

	go func() {
		defer wg.Done()
		emails, emailsErr = p.fetchEmails(ctx, token)
	}()

	go func() {
		defer wg.Done()
		login, ok := <-loginCh
		if !ok {
			return
		}
		publicOrgs, publicErr = p.fetchPublicOrgs(ctx, token, login)
	}()

	wg.Wait()

	if userErr != nil {
		return nil, fmt.Errorf("github user fetch: %w", userErr)
	}
	if user == nil {
		return nil, errors.New("github user fetch: empty response")
	}

	if privateErr != nil {
		p.log.WithError(privateErr).Warn("/user/orgs fetch failed; falling back to public memberships only")
	}
	if publicErr != nil {
		p.log.WithError(publicErr).Warn("/users/{login}/orgs fetch failed; falling back to private memberships only")
	}
	if privateErr != nil && publicErr != nil {
		return nil, fmt.Errorf("github orgs fetch: private=%v public=%w", privateErr, publicErr)
	}
	if emailsErr != nil {
		p.log.WithError(emailsErr).Warn("/user/emails fetch failed; the user gets no email, since none can be shown to be verified")
	}

	return &userProfile{
		Login: user.Login,
		Email: verifiedEmail(user.Email, emails),
		Orgs:  mergeOrgLogins(privateOrgs, publicOrgs),
	}, nil
}

// verifiedEmail picks the email to use for a user: only one GitHub
// reports as verified in /user/emails. The profile's public email
// (/user) is used when it is among the verified ones; otherwise the
// primary verified address. Without the list — the call failed — there
// is nothing to show an address is verified, and the user has no email:
// it is then not put into tokens and not shown to team rules or grant
// members.
func verifiedEmail(public string, emails []githubEmail) string {
	primary := ""
	for _, e := range emails {
		if !e.Verified {
			continue
		}
		if public != "" && strings.EqualFold(e.Email, public) {
			return e.Email
		}
		if e.Primary {
			primary = e.Email
		}
	}
	return primary
}

// mergeOrgLogins concatenates org-login slices and deduplicates
// case-insensitively while preserving original casing of the first
// occurrence (which lets diagnostic logs render the same casing GitHub
// returned).
func mergeOrgLogins(lists ...[]githubOrg) []string {
	total := 0
	for _, l := range lists {
		total += len(l)
	}
	seen := make(map[string]struct{}, total)
	out := make([]string, 0, total)
	for _, l := range lists {
		for _, o := range l {
			key := strings.ToLower(o.Login)
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, o.Login)
		}
	}
	return out
}

// signSessionCookie builds the HttpOnly session cookie for the
// authenticated user.
//
// SameSite=None + Secure is required so the cross-site iframe flows
// (`/auth/embed` for silent token, `/auth/logout` for clearing) can
// read and overwrite the cookie. Browsers treat *.localhost as a
// secure context, so Secure=true works for HTTP local dev too —
// non-localhost plain HTTP isn't a supported deployment.
func (p *Provider) signSessionCookie(login, email string, teams, matches []string) (*http.Cookie, error) {
	// The subject is the GitHub login — a raw provider subject, never an
	// email address.
	signed, err := session.SignCookie(p.cfg.SessionCookieName, p.sessionSecret, p.door,
		session.Payload{Subject: login, Email: email, Teams: teams, Matches: matches},
		p.cfg.SessionTTL, p.cfg.Now())
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

// exchangeCode swaps the authorization code for an access token, returning
// both the token and the granted scope (so callers can surface it for
// diagnostics — e.g. when the org check fails for what looks like a
// missing read:org grant).
func (p *Provider) exchangeCode(ctx context.Context, code string) (accessToken, scope string, err error) {
	form := url.Values{}
	form.Set("client_id", p.cfg.ClientID)
	form.Set("client_secret", string(p.clientSecret))
	form.Set("code", code)
	form.Set("redirect_uri", p.redirectURI())

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return "", "", fmt.Errorf("token request: status %d: %s", resp.StatusCode, body)
	}
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", "", fmt.Errorf("token decode: %w (body=%s)", err, body)
	}
	if tr.Error != "" {
		return "", "", fmt.Errorf("token error: %s: %s", tr.Error, tr.ErrorDesc)
	}
	if tr.AccessToken == "" {
		return "", "", errors.New("token response missing access_token")
	}
	return tr.AccessToken, tr.Scope, nil
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

func (p *Provider) fetchEmails(ctx context.Context, token string) ([]githubEmail, error) {
	var emails []githubEmail
	if err := p.apiGet(ctx, token, "/user/emails", &emails); err != nil {
		return nil, err
	}
	return emails, nil
}

func (p *Provider) fetchOrgs(ctx context.Context, token string) ([]githubOrg, error) {
	var orgs []githubOrg
	if err := p.apiGet(ctx, token, "/user/orgs", &orgs); err != nil {
		return nil, err
	}
	return orgs, nil
}

// fetchPublicOrgs returns the user's publicly-visible org memberships via
// /users/{login}/orgs. This endpoint exposes the same data anyone can see
// on the user's profile page and is therefore *not* subject to per-org
// "third-party OAuth App access" restrictions — which means an org that
// hides itself from /user/orgs (because this OAuth App hasn't been
// approved there) still shows up here, provided the user has publicized
// their membership. Used as a complement to fetchOrgs so that public
// membership is sufficient to pass the allow-list check.
func (p *Provider) fetchPublicOrgs(ctx context.Context, token, login string) ([]githubOrg, error) {
	var orgs []githubOrg
	if err := p.apiGet(ctx, token, "/users/"+url.PathEscape(login)+"/orgs", &orgs); err != nil {
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
