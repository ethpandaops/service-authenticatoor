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
//	state = "<public-url><callback-dir>~<random-nonce>"
//
// where <public-url> is the originating authenticatoor's externally-
// visible URL prefix (scheme + host + optional port; the relay's regex
// constrains it to *.ethpandaops.io / *.localhost / 127.0.0.1),
// <callback-dir> is the callback path minus its trailing "/callback"
// (e.g. "/oidc"; the relay redirects to <public-url><callback-dir>/callback)
// and <random-nonce> is a 128-bit base64url value. The nonce is also stored
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
	DefaultLoginPath         = "/oidc/login"
	DefaultCallbackPath      = "/oidc/callback"
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

	// LoginPath is the interactive login entry: it sets the state cookie
	// and redirects to the IdP's authorize endpoint. Defaults to
	// "/oidc/login".
	LoginPath string
	// CallbackPath is the local path that handles the OIDC callback.
	// In a relay-fronted deployment, the IdP only ever sees CallbackURL
	// (the relay's URL) and the relay forwards to <PublicURL><CallbackPath>.
	// In a direct deployment, CallbackURL should equal
	// <PublicURL><CallbackPath>. Default "/oidc/callback".
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
	// TrustUnverifiedEmail makes the provider use the id_token's email
	// although the token does not say email_verified: true. Off by
	// default: an unverified email is whatever its user typed, so
	// using it as the identity, in team rules or in grants lets a user
	// of an IdP that does not confirm addresses become someone else.
	// Only for an IdP that verifies emails without saying so.
	TrustUnverifiedEmail bool

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

	// Bearer lets non-browser clients authenticate with a JWT of the
	// IdP in an Authorization header (see bearer.go). Nil: off.
	Bearer *BearerConfig

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
	// bearer verifies the tokens of non-browser clients; nil unless
	// Config.Bearer is set.
	bearer        *idTokenVerifier
	allowedGroups map[string]struct{}
	teams         protection.Teams
	members       protection.Members
	door          session.Door
	scopeList     string
	cookieSecure  bool
}

var (
	_ protection.Provider             = (*Provider)(nil)
	_ protection.SessionClearer       = (*Provider)(nil)
	_ protection.AmbientAuthenticator = (*Provider)(nil)
	_ protection.AmbientSwitch        = (*Provider)(nil)
)

// New constructs a Provider. Defaults are filled in here; secret material
// and the discovery fetch happen in Start, which also starts the JWKS
// load.
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
	if cfg.Now == nil {
		cfg.Now = time.Now
	}

	return &Provider{
		cfg:           cfg,
		log:           log.WithField("package", "protection/oidc"),
		httpClient:    cfg.HTTPClient,
		allowedGroups: allowedGroupsSet(cfg.AllowedGroups),
		teams:         protection.NewTeams(cfg.Teams, cfg.TeamRules),
		members:       protection.NewMembers(cfg.GrantMembers),
		// Another IdP, or another client at it, is another door.
		door:         session.NewDoor("oidc", strings.TrimRight(cfg.IssuerURL, "/"), cfg.ClientID),
		scopeList:    strings.Join(scopes(cfg.Scopes), " "),
		cookieSecure: strings.HasPrefix(cfg.PublicURL, "https://"),
	}
}

// Name returns "oidc".
func (p *Provider) Name() string { return "oidc" }

// Start validates required fields, loads secret material, fetches the
// IdP's discovery document, and sets up the JWKS verifier. A discovery
// document that cannot be fetched fails Start; a JWKS that cannot does
// not — the keys are loaded in the background, and until they are
// there no token verifies (see newIDTokenVerifier).
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
	if err := p.teams.Err(); err != nil {
		return fmt.Errorf("oidc: %w", err)
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

	verifier, err := newIDTokenVerifier(ctx, disco.JWKSURI, disco.Issuer, []string{p.cfg.ClientID}, p.cfg.Now)
	if err != nil {
		return err
	}
	p.verifier = verifier

	if err := p.startBearer(ctx); err != nil {
		return err
	}

	if p.cfg.TrustUnverifiedEmail {
		p.log.Warn("trustUnverifiedEmail is on: emails are used as identity, in team rules and in grants " +
			"even when the id_token does not mark them email_verified")
	}
	p.log.WithFields(logrus.Fields{
		"issuer":       disco.Issuer,
		"callbackURL":  p.cfg.CallbackURL,
		"callbackPath": p.cfg.CallbackPath,
		"clientID":     p.cfg.ClientID,
		"groups":       p.cfg.AllowedGroups,
		"scopes":       p.scopeList,
		"teams":        p.teams.Static(),
		"teamRules":    p.teams.Rules(),
	}).Info("oidc provider ready")
	return nil
}

// Stop is a no-op.
func (p *Provider) Stop() error { return nil }

// RegisterRoutes attaches the login entry and the OIDC callback handler.
// They run on the parent router (not the /auth/* subrouter) so the auth
// middleware is bypassed — the request IS the act of authenticating.
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
// outcome redirects to the login entry, which starts the OIDC flow.
//
// An Authorization header is not looked at, with or without
// Config.Bearer: bearer tokens are accepted on the token alias only
// (AuthenticateAmbient). On /auth/* every provider gets a look at the
// request and the first identity wins, so a header read here would be
// judged or passed over depending on the order of the providers.
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

// handleLoginStart begins the OIDC dance: mint the nonce, bind it to the
// (sanitized) return_to in the signed state cookie, and redirect to the
// IdP's authorize endpoint. The nonce doubles as the id_token `nonce`
// claim (replay defense) — see the package comment for the state
// encoding contract.
func (p *Provider) handleLoginStart(w http.ResponseWriter, r *http.Request) {
	nonce, err := session.NewNonce()
	if err != nil {
		p.log.WithError(err).Error("nonce generation failed")
		http.Error(w, "state error", http.StatusInternalServerError)
		return
	}
	returnTo := protection.SafeReturnTo(r.URL.Query().Get("return_to"))
	stateBlob, err := session.SignState(p.sessionSecret, nonce, returnTo, p.cfg.Now(), DefaultStateTTL)
	if err != nil {
		p.log.WithError(err).Error("state signing failed")
		http.Error(w, "state error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     p.cfg.StateCookieName,
		Value:    stateBlob,
		Path:     p.cfg.CallbackPath,
		MaxAge:   int(DefaultStateTTL.Seconds()),
		HttpOnly: true,
		Secure:   p.cookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, p.authorizeRedirect(nonce), http.StatusFound)
}

// statePrefix is the routing prefix carried in the state parameter: the
// public URL plus the callback path minus its trailing "/callback"
// segment (e.g. "https://auth.example/oidc"). The relay appends
// "/callback" to it, so callback paths are expected to end in
// "/callback".
func (p *Provider) statePrefix() string {
	return strings.TrimRight(p.cfg.PublicURL, "/") +
		strings.TrimSuffix(p.cfg.CallbackPath, "/callback")
}

// authorizeRedirect builds the IdP authorize URL. The state parameter
// is "<statePrefix>~<nonce>" — the prefix lets the relay route the
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
	v.Set("state", p.statePrefix()+stateDelimiter+nonce)
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

	// State value shape: "<statePrefix>~<nonce>". Use LastIndex defensively
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
	if urlStatePrefix != p.statePrefix() {
		p.log.WithFields(logrus.Fields{
			"got":      urlStatePrefix,
			"expected": p.statePrefix(),
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

	id, refusal := p.identify(claims, idToken, false)
	if refusal != "" {
		http.Error(w, refusal, http.StatusForbidden)
		return
	}
	subject, email := id.subject, id.email
	// Teams derived by the team rules from the id_token are captured now
	// and travel in the session; the static teams are applied per
	// request.
	loginLog := p.log.WithField("sub", subject)
	teams := p.teams.Capture(loginLog, id.attrs)
	// The grant members the id_token satisfies are captured the same
	// way: which members matched, not the claims.
	matches := p.members.Capture(loginLog, id.attrs, teams)
	p.log.WithFields(logrus.Fields{
		"sub":   subject,
		"teams": p.teams.With(teams),
	}).Debug("oidc login resolved teams")

	cookie, err := p.signSessionCookie(subject, email, teams, matches)
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

// claimIdentity is what a verified token of the IdP says about its
// user, after the rules of this provider were applied to it.
type claimIdentity struct {
	// subject is the verified email, or the IdP's "sub" without one.
	subject string
	// email is the verified email; empty without one.
	email string
	// attrs are the token's claims as team rules and grant members see
	// them (without "email" when it is not verified).
	attrs protection.Attributes
}

// identify turns the claims of a verified token into the identity of
// its user. It is the one place that does so: the login callback runs
// it on the id_token and the bearer path on the token a client
// presented, so that the same user gets the same subject, teams and
// grant members through both.
//
// It applies allowedGroups — refusal is then the message for the user
// and the identity is not to be used — and the verified-email rule, and
// picks the subject. token is the verified JWT the claims came from.
//
// perRequest says that the caller runs it on every request (the bearer
// path) rather than once per login: what it has to say about the user —
// not in an allowed group, email not verified, a subject that looks
// like an email — is then logged at debug level instead of repeating
// at its own level with every token a client fetches.
func (p *Provider) identify(
	claims *idTokenClaims, token string, perRequest bool,
) (id claimIdentity, refusal string) {
	// What a login reports once, a bearer client would repeat with
	// every request.
	at := func(level logrus.Level) logrus.Level {
		if perRequest {
			return logrus.DebugLevel
		}
		return level
	}
	if !groupAllowed(claims.Groups, p.allowedGroups) {
		logAt(p.log.WithFields(logrus.Fields{
			"sub":           claims.Subject,
			"email":         claims.Email,
			"groups":        strings.Join(claims.Groups, ", "),
			"allowedGroups": strings.Join(p.cfg.AllowedGroups, ", "),
		}), at(logrus.WarnLevel), "user not in any allowed group")
		return claimIdentity{}, fmt.Sprintf(
			"your account %q is not in any allowed group.\n"+
				"  allowed: [%s]\n"+
				"  your groups: [%s]",
			claims.Email,
			strings.Join(p.cfg.AllowedGroups, ", "),
			strings.Join(claims.Groups, ", "),
		)
	}

	// The email counts only when the IdP vouches for it. An unverified
	// one is not the identity, is not put into tokens and is not shown
	// to team rules or grant members; the subject then is the IdP's
	// own "sub".
	email := claims.Email
	if email != "" && !bool(claims.EmailVerified) && !p.cfg.TrustUnverifiedEmail {
		logAt(p.log.WithField("sub", claims.Subject), at(logrus.InfoLevel),
			"id_token email is not marked email_verified: the email is dropped and the user is "+
				"identified by the IdP subject (oidc.trustUnverifiedEmail is off)")
		email = ""
	}
	subject := email
	if subject == "" {
		// A raw IdP subject. It is marked as such on the identity
		// (SubjectIsEmail false), so a grants member that names an
		// email address never matches it — some IdPs can be set up to
		// use the user's address as "sub", verified or not. The token's
		// "sub" claim has no such mark, hence the warning: a tool that
		// reads "sub" as an email would take this one for verified.
		subject = claims.Subject
		if strings.Contains(subject, "@") {
			logAt(p.log.WithField("sub", subject), at(logrus.WarnLevel),
				"the IdP subject looks like an email address but is not a verified email; it becomes "+
					"the token's sub as it is and matches no user: member of a grants group")
		}
	}
	// The attributes are the claims of the token that was just verified
	// — every claim, by its name ("groups", "email", "sub", nested ones
	// by dotted path) — and nothing else: no userinfo call is made.
	attrs, err := protection.TokenAttributes(token)
	if err != nil {
		p.log.WithError(err).Warn("id_token claims unreadable for team rules; none applied")
	}
	if email == "" {
		delete(attrs, "email")
	}
	return claimIdentity{subject: subject, email: email, attrs: attrs}, ""
}

// logAt logs msg at the given level. logrus.FieldLogger has a method
// per level and none that takes one.
func logAt(log logrus.FieldLogger, level logrus.Level, msg string) {
	switch level {
	case logrus.DebugLevel:
		log.Debug(msg)
	case logrus.InfoLevel:
		log.Info(msg)
	default:
		log.Warn(msg)
	}
}

// signSessionCookie builds the HttpOnly session cookie for the
// authenticated user.
//
// SameSite=None + Secure is required so the cross-site iframe flows
// (`/auth/embed` for silent token, `/auth/logout` for clearing) can
// read and overwrite the cookie. Browsers treat *.localhost as a
// secure context, so Secure=true works for HTTP local dev too —
// non-localhost plain HTTP isn't a supported deployment.
func (p *Provider) signSessionCookie(sub, email string, teams, matches []string) (*http.Cookie, error) {
	// The subject is the email exactly when there is one (see
	// handleCallback); otherwise it is the IdP's raw "sub".
	signed, err := session.SignCookie(p.cfg.SessionCookieName, p.sessionSecret, p.door,
		session.Payload{
			Subject: sub, Email: email, SubjectIsEmail: email != "" && sub == email,
			Teams: teams, Matches: matches,
		},
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
