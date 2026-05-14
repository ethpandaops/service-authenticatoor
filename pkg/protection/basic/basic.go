// Package basic implements protection.Provider for HTTP Basic auth backed
// by an htpasswd file.
//
// This provider is self-contained — it does not depend on any upstream
// proxy. The browser's built-in credential dialog handles the login UI,
// and credentials are cached per (origin, realm) until the tab closes or
// the browser is cleared. The htpasswd file format supports bcrypt,
// crypt(), SHA-1, and MD5; bcrypt is recommended.
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

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/tg123/go-htpasswd"

	"github.com/ethpandaops/service-authenticatoor/pkg/protection"
)

// DefaultRealm is the realm sent in the WWW-Authenticate challenge when
// none is configured.
const DefaultRealm = "authenticatoor"

// Config configures the basic provider.
type Config struct {
	// HtpasswdFile is the path to the htpasswd-format password file.
	// Required.
	HtpasswdFile string
	// Realm is the value sent in WWW-Authenticate: Basic realm="...".
	// Defaults to "authenticatoor".
	Realm string
}

// Provider implements protection.Provider for HTTP Basic auth.
type Provider struct {
	cfg  Config
	log  logrus.FieldLogger
	file *htpasswd.File
}

var _ protection.Provider = (*Provider)(nil)

// New constructs a Provider. The htpasswd file is loaded in Start; a
// missing or malformed file surfaces there, not here.
func New(log logrus.FieldLogger, cfg Config) *Provider {
	if cfg.Realm == "" {
		cfg.Realm = DefaultRealm
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

// RegisterRoutes is a no-op.
func (p *Provider) RegisterRoutes(_ *mux.Router) {}

// Logout responds 200 with a "close the tab" hint. HTTP Basic
// credentials are cached by the browser per (origin, realm) until the
// tab closes or the user clears them; the server has no reliable way
// to invalidate them. The endpoint deliberately does NOT issue a
// WWW-Authenticate challenge — the client library calls /auth/logout
// from a hidden iframe, and a 401 challenge there would pop an
// invisible credential dialog.
func (p *Provider) Logout(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"loggedOut": false,
		"message":   "HTTP Basic credentials are cached by the browser; close the tab to clear them.",
	})
}

// Authenticate checks the request's Basic credentials against the
// htpasswd file. The browser's cached credentials act as the session,
// so silent (iframe) auth works as long as the user has logged in once.
func (p *Provider) Authenticate(_ context.Context, r *http.Request) (protection.Outcome, error) {
	user, pass, ok := r.BasicAuth()
	if !ok || user == "" || !p.file.Match(user, pass) {
		return protection.Outcome{
			Status:    http.StatusUnauthorized,
			Challenge: basicChallenge(p.cfg.Realm),
		}, nil
	}
	return protection.Outcome{Identity: &protection.Identity{
		Subject: user,
		Email:   user,
	}}, nil
}

// basicChallenge builds the WWW-Authenticate header for a Basic-auth realm.
func basicChallenge(realm string) http.Header {
	h := http.Header{}
	h.Set("WWW-Authenticate", `Basic realm="`+realm+`", charset="UTF-8"`)
	return h
}
