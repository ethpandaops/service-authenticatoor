// Package basic implements protection.Provider for HTTP Basic auth backed
// by an htpasswd file.
//
// This provider is self-contained — it does not depend on any upstream
// proxy. The browser's built-in credential dialog handles the login UI,
// and credentials are cached per (origin, realm) until the tab closes or
// the browser is cleared. The htpasswd file format supports bcrypt,
// crypt(), SHA-1, and MD5; bcrypt is recommended.
//
// Two entry points exist: /auth/* requests carrying an Authorization
// header authenticate ambiently (the legacy single-provider behavior,
// where the middleware's 401 challenge triggers the browser dialog), and
// the login entry path (default /htpasswd/login) challenges, converts
// valid credentials into a signed session cookie, and redirects back —
// the path used when several providers share the instance.
//
// The htpasswd file is read once at Start. Changes on disk require a
// restart. Hot-reload may be added later if needed; in the meantime, an
// operator who rotates a password redeploys.
package basic

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/tg123/go-htpasswd"

	"github.com/ethpandaops/service-authenticatoor/pkg/protection"
	"github.com/ethpandaops/service-authenticatoor/pkg/session"
)

// DefaultRealm is the realm sent in the WWW-Authenticate challenge when
// none is configured.
const DefaultRealm = "authenticatoor"

// Defaults applied when corresponding Config fields are empty.
const (
	DefaultLoginPath         = "/htpasswd/login"
	DefaultSessionCookieName = "authenticatoor_htpasswd_session"
	DefaultSessionTTL        = 12 * time.Hour
)

// Config configures the basic provider.
type Config struct {
	// HtpasswdFile is the path to the htpasswd-format password file.
	// Required.
	HtpasswdFile string
	// Realm is the value sent in WWW-Authenticate: Basic realm="...".
	// Defaults to "authenticatoor".
	Realm string

	// LoginPath is the interactive login entry: it 401-challenges until
	// valid credentials arrive, then mints the session cookie and
	// redirects back. Defaults to "/htpasswd/login".
	LoginPath string
	// SessionKey is the HMAC key for the session cookie. Derived in
	// main.go from the JWT signing key via issuer.DeriveHMACKey so
	// there's no separate secret to manage. Must be at least 16 bytes.
	// Required.
	SessionKey []byte
	// SessionCookieName is the name of the session cookie. Defaults to
	// "authenticatoor_htpasswd_session".
	SessionCookieName string
	// SessionTTL is the session cookie lifetime. Defaults to 12h.
	SessionTTL time.Duration

	// Now overrides time.Now for deterministic tests.
	Now func() time.Time
}

// Provider implements protection.Provider for HTTP Basic auth.
type Provider struct {
	cfg  Config
	log  logrus.FieldLogger
	file *htpasswd.File
}

var (
	_ protection.Provider       = (*Provider)(nil)
	_ protection.SessionClearer = (*Provider)(nil)
)

// New constructs a Provider. The htpasswd file is loaded in Start; a
// missing or malformed file surfaces there, not here.
func New(log logrus.FieldLogger, cfg Config) *Provider {
	if cfg.Realm == "" {
		cfg.Realm = DefaultRealm
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
		log: log.WithField("package", "protection/basic"),
	}
}

// Name returns "basic".
func (p *Provider) Name() string { return "basic" }

// Start loads the htpasswd file. Bad-line handler logs at WARN so
// operators see typos without the load itself failing.
func (p *Provider) Start(_ context.Context) error {
	if p.cfg.HtpasswdFile == "" {
		return errors.New("basic: HtpasswdFile is required")
	}
	if len(p.cfg.SessionKey) < 16 {
		return errors.New("basic: SessionKey must be at least 16 bytes")
	}
	f, err := htpasswd.New(p.cfg.HtpasswdFile, htpasswd.DefaultSystems, func(err error) {
		p.log.WithError(err).Warn("htpasswd: malformed line ignored")
	})
	if err != nil {
		return fmt.Errorf("basic: load %s: %w", p.cfg.HtpasswdFile, err)
	}
	p.file = f
	p.log.WithField("file", p.cfg.HtpasswdFile).Info("htpasswd loaded")
	return nil
}

// Stop is a no-op.
func (p *Provider) Stop() error { return nil }

// RegisterRoutes attaches the login entry on the parent router.
func (p *Provider) RegisterRoutes(r *mux.Router) {
	r.HandleFunc(p.cfg.LoginPath, p.handleLogin).Methods(http.MethodGet)
}

// LoginURL returns the login entry path carrying returnTo.
func (p *Provider) LoginURL(returnTo string) string {
	v := url.Values{}
	v.Set("return_to", returnTo)
	return p.cfg.LoginPath + "?" + v.Encode()
}

// Logout clears the session cookie and hints at the browser credential
// cache. HTTP Basic credentials are cached by the browser per (origin,
// realm) until the tab closes or the user clears them; the server has no
// reliable way to invalidate them, so an /auth/* request carrying them
// re-authenticates ambiently. The endpoint deliberately does NOT issue a
// WWW-Authenticate challenge — the client library calls /auth/logout
// from a hidden iframe, and a 401 challenge there would pop an
// invisible credential dialog.
func (p *Provider) Logout(w http.ResponseWriter, _ *http.Request) {
	http.SetCookie(w, p.ClearSessionCookie())
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"loggedOut": true,
		"message":   "session cleared; cached HTTP Basic credentials may re-authenticate until the tab closes.",
	})
}

// Authenticate checks the session cookie minted by the login entry, then
// the request's ambient Basic credentials against the htpasswd file. The
// browser's cached credentials act as the session on the ambient path,
// so silent (iframe) auth works as long as the user has logged in once.
func (p *Provider) Authenticate(_ context.Context, r *http.Request) (protection.Outcome, error) {
	if c, err := r.Cookie(p.cfg.SessionCookieName); err == nil {
		sub, email, perr := session.Parse(p.cfg.SessionKey, c.Value, p.cfg.Now())
		if perr == nil {
			return protection.Outcome{Identity: &protection.Identity{
				Subject: sub,
				Email:   email,
			}}, nil
		}
		p.log.WithError(perr).Debug("session cookie invalid; falling back to basic credentials")
	}

	if user, pass, ok := r.BasicAuth(); ok && user != "" && p.file.Match(user, pass) {
		return protection.Outcome{Identity: &protection.Identity{
			Subject: user,
			Email:   user,
		}}, nil
	}

	return protection.Outcome{
		Status:    http.StatusUnauthorized,
		Challenge: basicChallenge(p.cfg.Realm),
	}, nil
}

// handleLogin challenges for Basic credentials, converts a valid pair
// into a signed session cookie, and redirects to return_to. Unlike the
// ambient path this persists the login in a cookie, so /auth/* requests
// authenticate without the browser re-sending credentials — required
// when several providers share the instance and the middleware can't
// challenge for one specific provider.
func (p *Provider) handleLogin(w http.ResponseWriter, r *http.Request) {
	user, pass, ok := r.BasicAuth()
	if !ok || user == "" || !p.file.Match(user, pass) {
		for k, vs := range basicChallenge(p.cfg.Realm) {
			w.Header()[k] = vs
		}
		w.Header().Set("Cache-Control", "no-store")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	signed, err := session.Sign(p.cfg.SessionKey, user, user, p.cfg.SessionTTL, p.cfg.Now())
	if err != nil {
		p.log.WithError(err).Error("session cookie signing failed")
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, p.sessionCookie(signed))

	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, protection.SafeReturnTo(r.URL.Query().Get("return_to")), http.StatusFound)
}

// sessionCookie wraps the signed session payload. SameSite=None + Secure
// for the cross-site iframe flows; see the github provider for details.
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

// basicChallenge builds the WWW-Authenticate header for a Basic-auth realm.
func basicChallenge(realm string) http.Header {
	h := http.Header{}
	h.Set("WWW-Authenticate", `Basic realm="`+realm+`", charset="UTF-8"`)
	return h
}
