package server

import (
	"embed"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/ethpandaops/service-authenticatoor/pkg/auth"
)

//go:embed static/authenticatoor-*.js
var authenticatoorFS embed.FS

// clientVersionRe bounds the `v` query parameter to a small numeric
// namespace before it is interpolated into an embed-FS path or an HTML
// attribute.
var clientVersionRe = regexp.MustCompile(`^[0-9]{1,2}$`)

// clientVersion extracts and validates the `v` query parameter, falling
// back to def when absent. ok=false means the value is malformed and the
// caller should 404.
func clientVersion(r *http.Request, def string) (version string, ok bool) {
	v := r.URL.Query().Get("v")
	if v == "" {
		return def, true
	}
	if !clientVersionRe.MatchString(v) {
		return "", false
	}
	return v, true
}

// handleClientJS serves the authenticatoor JS client library with the
// service's external URL templated in. The result is intended to be loaded
// from a consumer app via:
//
//	<script src="https://auth.<devnet>/client.js?v=2"></script>
//
// v=1 (the default) exposes the polling-style API
// {checkLogin, login, logout, getToken, isLoggedIn, authServiceURL}; v=2
// exposes the shared-session, event-emitting API
// {addEventListener, removeEventListener, getStatus, getToken, login,
// logout, authServiceURL} backed by the /clientFrame hidden iframe.
//
// Hosted under the public path (outside /auth/*) so it can be loaded
// without authenticating to the upstream proxy. Unknown or malformed
// versions get a 404.
func (s *Server) handleClientJS(w http.ResponseWriter, r *http.Request) {
	version, ok := clientVersion(r, "1")
	if !ok {
		http.NotFound(w, r)
		return
	}

	authenticatoorJS, err := authenticatoorFS.ReadFile("static/authenticatoor-v" + version + ".js")
	if err != nil {
		http.NotFound(w, r)
		return
	}

	body := strings.ReplaceAll(string(authenticatoorJS), "__AUTH_SERVICE_URL__", strings.TrimRight(s.cfg.ExternalURL, "/"))

	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write([]byte(body))
}

// handleClientFrameJS serves the script that runs inside the /clientFrame
// iframe. It is served verbatim — the frame is same-origin with this
// service and uses relative request URLs, so no templating is needed.
func (s *Server) handleClientFrameJS(w http.ResponseWriter, r *http.Request) {
	version, ok := clientVersion(r, "2")
	if !ok {
		http.NotFound(w, r)
		return
	}

	frameJS, err := authenticatoorFS.ReadFile("static/authenticatoor-frame-v" + version + ".js")
	if err != nil {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(frameJS)
}

// handleClientFrame serves the HTML shell for the hidden shared-session
// iframe mounted by the v2 client on every consuming app. The page carries
// no secrets and no inline script — its only payload is a <script> tag
// loading /client.frame.js.
//
// Trust chain: the ?origin= query param (the embedding app's origin) is
// validated against AllowedReturnHosts AND pinned via
// Content-Security-Policy frame-ancestors. A page embedded by any origin
// other than the one it claims never renders, so the frame script may
// trust its own origin param as the postMessage peer in both directions.
//
// Hosted under the public path (outside /auth/*): the frame page itself
// needs no identity — the session cookies only come into play on the
// same-origin /auth/token fetches the frame script performs.
func (s *Server) handleClientFrame(w http.ResponseWriter, r *http.Request) {
	version, ok := clientVersion(r, "2")
	if !ok {
		http.NotFound(w, r)
		return
	}
	// The shell is version-agnostic, but don't render a page whose script
	// can only 404.
	if _, err := authenticatoorFS.ReadFile("static/authenticatoor-frame-v" + version + ".js"); err != nil {
		http.NotFound(w, r)
		return
	}

	rawOrigin := r.URL.Query().Get("origin")
	if rawOrigin == "" {
		http.Error(w, "missing origin", http.StatusBadRequest)
		return
	}

	parsed, host, ok := parseReturnTo(rawOrigin)
	if !ok || !auth.MatchAnyHost(s.cfg.AllowedReturnHosts, host) {
		s.log.WithField("frame_origin", host).Warn("clientFrame origin rejected")
		http.Error(w, "origin not allowed", http.StatusBadRequest)
		return
	}

	// Canonical origin (scheme + host[:port], no path/query/fragment).
	canonicalOrigin := parsed.Scheme + "://" + parsed.Host

	// frame-ancestors locks who may embed this page to the validated
	// origin; script-src/connect-src 'self' cover the frame script and its
	// same-origin token fetches, everything else is blocked. No inline
	// script means no 'unsafe-inline'.
	w.Header().Set("Content-Security-Policy",
		fmt.Sprintf("frame-ancestors %s; default-src 'none'; script-src 'self'; connect-src 'self'", canonicalOrigin))
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	_, _ = fmt.Fprintf(w, `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>authenticatoor</title></head>
<body>
<script src="/client.frame.js?v=%s"></script>
</body>
</html>
`, version)
}
