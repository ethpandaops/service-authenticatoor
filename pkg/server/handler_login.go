package server

import (
	"html/template"
	"net/http"
	"net/url"
	"strconv"

	"github.com/ethpandaops/service-authenticatoor/pkg/auth"
	"github.com/ethpandaops/service-authenticatoor/pkg/protection"
)

// handleLogin mints a JWT and 302s the user to return_to with the token in
// the URL fragment. Fragments aren't sent on subsequent requests, so the
// token stays out of access logs and Referer headers on the receiving end.
//
// The return_to host is validated against AllowedReturnHosts via net/url
// hostname extraction (not substring/regex) — this rejects spoofs like
// https://victim.example.com.attacker.com and userinfo-tricks like
// https://victim.example.com@attacker.com.
//
// A user who is logged in but named by no grants group is not sent back:
// the answer is a 403 page that names the identity and offers the
// logout. Redirecting — back to the app without a token, or to the
// login — would only bring the browser here again.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	id := identityFromContext(r.Context())
	if id == nil || id.Subject == "" {
		http.Error(w, "no authenticated user", http.StatusUnauthorized)
		return
	}

	returnTo := r.URL.Query().Get("return_to")
	if returnTo == "" {
		http.Error(w, "missing return_to", http.StatusBadRequest)
		return
	}

	dest, host, ok := parseReturnTo(returnTo)
	if !ok || !auth.MatchAnyHost(s.cfg.AllowedReturnHosts, host) {
		s.log.WithField("return_host", host).Warn("return_to rejected")
		http.Error(w, "return_to host not allowed", http.StatusBadRequest)
		return
	}

	tok, claims, err := s.issuer.IssueFor(tokenIdentity(id), nil)
	if s.notGranted(err, id, "login") {
		s.renderNotGranted(w, id)
		return
	}
	if err != nil {
		s.tokenIssueErrors.WithLabelValues("issue").Inc()
		s.log.WithError(err).Error("issue token")
		http.Error(w, "issue failed", http.StatusInternalServerError)
		return
	}
	s.tokensIssued.Inc()
	s.loginRedirects.Inc()
	s.log.WithField("sub", id.Subject).WithField("jti", claims.ID).Info("login redirect")

	user := id.Email
	if user == "" {
		user = id.Subject
	}

	// Build the redirect URL manually rather than going through
	// dest.Fragment / dest.RawFragment — url.URL.String() re-percent-encodes
	// fragments containing already-encoded characters (so e.g.
	// user=alice%40example.com becomes user=alice%2540example.com).
	// Strip any existing fragment from dest, then append our encoded form.
	dest.Fragment = ""
	dest.RawFragment = ""
	encoded := url.Values{
		"auth_token": {tok},
		"exp":        {strconv.FormatInt(claims.ExpiresAt.Unix(), 10)},
		"user":       {user},
	}.Encode()

	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, dest.String()+"#"+encoded, http.StatusFound)
}

// parseReturnTo parses raw as an absolute http(s) URL and returns the
// parsed URL plus its hostname (lower-cased, no port, no userinfo). Returns
// ok=false if the URL is unusable as a redirect target.
func parseReturnTo(raw string) (parsed *url.URL, host string, ok bool) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, "", false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, "", false
	}
	host = u.Hostname()
	if host == "" {
		return nil, "", false
	}
	return u, host, true
}

// renderNotGranted writes the page a logged-in user without a grant
// sees instead of the redirect back to the app. It links nowhere but to
// /auth/logout, so nothing on it can start the round again.
func (s *Server) renderNotGranted(w http.ResponseWriter, id *protection.Identity) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	w.WriteHeader(http.StatusForbidden)
	data := notGrantedData{Subject: id.Subject, Email: id.Email, Provider: id.Provider}
	if data.Email == data.Subject {
		data.Email = ""
	}
	if err := notGrantedTmpl.Execute(w, data); err != nil {
		s.log.WithError(err).Warn("render not-granted page")
	}
}

type notGrantedData struct {
	Subject  string
	Email    string // only when it is not the subject
	Provider string
}

var notGrantedTmpl = template.Must(template.New("notGranted").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>authenticatoor — no access</title>
<style>
body { font-family: system-ui, -apple-system, sans-serif; background: #f5f5f5; margin: 0; padding: 2rem; color: #222; }
.box { max-width: 26rem; margin: 4rem auto; background: #fff; padding: 2rem; border-radius: .5rem; box-shadow: 0 1px 3px rgba(0,0,0,.1); }
h1 { margin: 0 0 .5rem; font-size: 1.25rem; }
p { margin: 0 0 1.25rem; font-size: .875rem; color: #555; }
b { color: #222; overflow-wrap: anywhere; }
a.logout { display: block; padding: .625rem 1rem; background: #2563eb; color: #fff; border-radius: .25rem; font-size: 1rem; text-align: center; text-decoration: none; }
a.logout:hover { background: #1d4ed8; }
</style>
</head>
<body>
<div class="box">
<h1>No access</h1>
<p>You are logged in as <b>{{.Subject}}</b>{{if .Email}} ({{.Email}}){{end}} through <b>{{.Provider}}</b>,
but this account is not permitted to use the services of this devnet.</p>
<p>To use another account, log out and sign in again.</p>
<a class="logout" href="/auth/logout">Log out</a>
</div>
</body>
</html>
`))
