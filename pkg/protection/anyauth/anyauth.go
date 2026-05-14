// Package anyauth implements protection.Provider as a development-only
// passthrough. The user picks an arbitrary username on a simple form;
// that username is stored in a plain (unsigned) cookie and reused as the
// identity for subsequent /auth/* requests. Logout clears the cookie, so
// switching users is just /auth/logout + pick a new name.
//
// DO NOT use this provider in production — anyone who can reach the
// service can mint a token under any identity. The provider logs a loud
// warning at startup so operators don't enable it by accident.
package anyauth

import (
	"context"
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"

	"github.com/ethpandaops/service-authenticatoor/pkg/protection"
)

// Defaults applied when the corresponding Config field is empty.
const (
	DefaultCookieName = "authenticatoor_anyauth_user"
	DefaultLoginPath  = "/auth/anyauth/login"
	DefaultCookieTTL  = 12 * time.Hour

	// maxUsernameLen caps an accepted username. Keeps the cookie short
	// and well within net/http's cookie-value limits.
	maxUsernameLen = 64
)

// Config configures the anyauth provider.
type Config struct {
	// CookieName is the name of the username cookie. Defaults to
	// "authenticatoor_anyauth_user".
	CookieName string
	// LoginPath is the path of the login form, registered on the parent
	// router so it bypasses the auth middleware. Defaults to
	// "/auth/anyauth/login".
	LoginPath string
	// CookieTTL is the cookie lifetime. Defaults to 12h.
	CookieTTL time.Duration
	// Secure marks the cookie as Secure (HTTPS-only). Set true when the
	// service is served over HTTPS.
	Secure bool
}

// Provider implements protection.Provider as a username-only passthrough
// backed by a clearable cookie.
type Provider struct {
	cfg  Config
	log  logrus.FieldLogger
	tmpl *template.Template
}

var _ protection.Provider = (*Provider)(nil)

// New constructs a Provider.
func New(log logrus.FieldLogger, cfg Config) *Provider {
	if cfg.CookieName == "" {
		cfg.CookieName = DefaultCookieName
	}
	if cfg.LoginPath == "" {
		cfg.LoginPath = DefaultLoginPath
	}
	if cfg.CookieTTL == 0 {
		cfg.CookieTTL = DefaultCookieTTL
	}
	return &Provider{
		cfg:  cfg,
		log:  log.WithField("package", "protection/anyauth"),
		tmpl: template.Must(template.New("login").Parse(loginFormTmpl)),
	}
}

// Name returns "any".
func (p *Provider) Name() string { return "any" }

// Start logs the warning and returns.
func (p *Provider) Start(_ context.Context) error {
	p.log.Warn("ANYAUTH ENABLED — ANY USERNAME GRANTS ACCESS, DO NOT USE IN PRODUCTION")
	return nil
}

// Stop is a no-op.
func (p *Provider) Stop() error { return nil }

// RegisterRoutes attaches the login form (GET) and submission (POST). They
// run on the parent router — bypassing the auth middleware — because the
// request is the act of authenticating.
func (p *Provider) RegisterRoutes(r *mux.Router) {
	r.HandleFunc(p.cfg.LoginPath, p.handleLoginForm).Methods(http.MethodGet)
	r.HandleFunc(p.cfg.LoginPath, p.handleLoginSubmit).Methods(http.MethodPost)
}

// Logout clears the username cookie. Subsequent /auth/* requests redirect
// to the login form.
func (p *Provider) Logout(w http.ResponseWriter, _ *http.Request) {
	http.SetCookie(w, p.clearCookie())
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"loggedOut": true})
}

// Authenticate looks for a non-empty username cookie. When absent or
// invalid the provider returns a redirect to the login form, carrying the
// original request URI as return_to.
func (p *Provider) Authenticate(_ context.Context, r *http.Request) (protection.Outcome, error) {
	if c, err := r.Cookie(p.cfg.CookieName); err == nil {
		if user := sanitizeUsername(c.Value); user != "" {
			return protection.Outcome{Identity: &protection.Identity{
				Subject: user,
				Email:   user,
			}}, nil
		}
	}
	v := url.Values{}
	v.Set("return_to", r.URL.RequestURI())
	return protection.Outcome{
		RedirectTo: p.cfg.LoginPath + "?" + v.Encode(),
	}, nil
}

// handleLoginForm renders the username form. The return_to query param is
// echoed back into a hidden field so the POST handler knows where to send
// the user.
func (p *Provider) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	returnTo := r.URL.Query().Get("return_to")
	if !isSafeReturnTo(returnTo) {
		returnTo = "/"
	}
	p.renderForm(w, http.StatusOK, formData{
		Action:   p.cfg.LoginPath,
		ReturnTo: returnTo,
	})
}

// handleLoginSubmit validates the username, sets the cookie, and 302s to
// the (sanitized) return_to. On a bad username the form is re-rendered
// with a 400 and the offending input echoed back so the user can fix it.
func (p *Provider) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	rawUser := r.PostForm.Get("user")
	returnTo := r.PostForm.Get("return_to")
	if !isSafeReturnTo(returnTo) {
		returnTo = "/"
	}

	user := sanitizeUsername(rawUser)
	if user == "" {
		p.renderForm(w, http.StatusBadRequest, formData{
			Action:   p.cfg.LoginPath,
			User:     rawUser,
			ReturnTo: returnTo,
			Error:    "Username must be 1–64 printable ASCII characters (no quotes, semicolons, or backslashes).",
		})
		return
	}

	http.SetCookie(w, p.userCookie(user))
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, returnTo, http.StatusFound)
}

// userCookie packs the chosen username into the session cookie.
func (p *Provider) userCookie(user string) *http.Cookie {
	return &http.Cookie{
		Name:     p.cfg.CookieName,
		Value:    user,
		Path:     "/",
		MaxAge:   int(p.cfg.CookieTTL.Seconds()),
		HttpOnly: true,
		Secure:   p.cfg.Secure,
		SameSite: http.SameSiteLaxMode,
	}
}

// clearCookie returns a cookie that deletes the session cookie.
func (p *Provider) clearCookie() *http.Cookie {
	return &http.Cookie{
		Name:     p.cfg.CookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   p.cfg.Secure,
		SameSite: http.SameSiteLaxMode,
	}
}

type formData struct {
	Action   string
	User     string
	ReturnTo string
	Error    string
}

func (p *Provider) renderForm(w http.ResponseWriter, status int, data formData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := p.tmpl.Execute(w, data); err != nil {
		p.log.WithError(err).Warn("render login form")
	}
}

// sanitizeUsername trims whitespace and rejects empty / overly long /
// non-printable values. Allowed bytes are 0x20-0x7E except `"`, `;`, `\`
// — the same set net/http accepts inside cookie values without quoting.
func sanitizeUsername(in string) string {
	s := strings.TrimSpace(in)
	if s == "" || len(s) > maxUsernameLen {
		return ""
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b < 0x20 || b > 0x7E || b == '"' || b == ';' || b == '\\' {
			return ""
		}
	}
	return s
}

// isSafeReturnTo accepts only relative paths that don't trigger a
// protocol-relative redirect (// or /\). Empty values are rejected so the
// caller can fall back to "/".
func isSafeReturnTo(s string) bool {
	if s == "" || !strings.HasPrefix(s, "/") {
		return false
	}
	if strings.HasPrefix(s, "//") || strings.HasPrefix(s, "/\\") {
		return false
	}
	return true
}

const loginFormTmpl = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>authenticatoor — dev login</title>
<style>
body { font-family: system-ui, -apple-system, sans-serif; background: #f5f5f5; margin: 0; padding: 2rem; color: #222; }
.box { max-width: 26rem; margin: 4rem auto; background: #fff; padding: 2rem; border-radius: .5rem; box-shadow: 0 1px 3px rgba(0,0,0,.1); }
h1 { margin: 0 0 1rem; font-size: 1.25rem; }
.warn { background: #fef3c7; border-left: 3px solid #f59e0b; padding: .5rem .75rem; margin-bottom: 1rem; font-size: .875rem; }
label { display: block; margin-bottom: .5rem; font-size: .875rem; color: #555; }
input[type=text] { width: 100%; box-sizing: border-box; padding: .5rem .75rem; border: 1px solid #ccc; border-radius: .25rem; font-size: 1rem; }
button { margin-top: 1rem; padding: .5rem 1rem; background: #2563eb; color: #fff; border: 0; border-radius: .25rem; font-size: 1rem; cursor: pointer; }
button:hover { background: #1d4ed8; }
.err { color: #b91c1c; font-size: .875rem; margin-top: .5rem; }
</style>
</head>
<body>
<div class="box">
<h1>authenticatoor — dev login</h1>
<div class="warn">Development mode: any username will be accepted.</div>
<form method="POST" action="{{.Action}}">
  <label for="user">Username</label>
  <input id="user" name="user" type="text" autofocus required maxlength="64" autocomplete="off" value="{{.User}}">
  {{if .Error}}<div class="err">{{.Error}}</div>{{end}}
  <input type="hidden" name="return_to" value="{{.ReturnTo}}">
  <button type="submit">Continue</button>
</form>
</div>
</body>
</html>
`
