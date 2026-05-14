package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/ethpandaops/service-authenticatoor/pkg/auth"
)

// handleEmbed serves an HTML page meant to be loaded in an invisible iframe
// by a same-organization app. It mints a JWT and posts it to the parent
// window via window.postMessage, restricted to the validated target_origin.
//
// This is the silent token-acquisition path. It bypasses CORS preflight
// entirely (no XHR — a normal HTML navigation inside an iframe) and degrades
// cleanly to the redirect-based /auth/login flow when the user hasn't yet
// authenticated to the upstream proxy: the proxy intercepts the iframe load
// with a login page whose own X-Frame-Options blocks rendering, postMessage
// never fires, and the parent's timeout falls through to the redirect.
func (s *Server) handleEmbed(w http.ResponseWriter, r *http.Request) {
	id := identityFromContext(r.Context())
	if id == nil || id.Subject == "" {
		http.Error(w, "no authenticated user", http.StatusUnauthorized)
		return
	}

	rawTarget := r.URL.Query().Get("target_origin")
	if rawTarget == "" {
		http.Error(w, "missing target_origin", http.StatusBadRequest)
		return
	}

	parsed, host, ok := parseReturnTo(rawTarget)
	if !ok || !auth.MatchAnyHost(s.cfg.AllowedReturnHosts, host) {
		s.log.WithField("target_host", host).Warn("embed target_origin rejected")
		http.Error(w, "target_origin not allowed", http.StatusBadRequest)
		return
	}

	tok, claims, err := s.issuer.Issue(id.Subject, id.Email, nil)
	if err != nil {
		s.tokenIssueErrors.WithLabelValues("issue").Inc()
		s.log.WithError(err).Error("issue token")
		http.Error(w, "issue failed", http.StatusInternalServerError)
		return
	}
	s.tokensIssued.Inc()
	s.log.WithField("sub", id.Subject).WithField("jti", claims.ID).Info("embed token")

	// Canonical origin (scheme + host[:port], no path/query/fragment).
	canonicalOrigin := parsed.Scheme + "://" + parsed.Host

	user := id.Email
	if user == "" {
		user = id.Subject
	}
	payload := map[string]any{
		"type":  "authenticatoor.token",
		"token": tok,
		"exp":   claims.ExpiresAt.Unix(),
		"user":  user,
	}
	payloadBytes, _ := json.Marshal(payload)
	payloadHTML := htmlSafeJSON(payloadBytes)

	targetJSON, _ := json.Marshal(canonicalOrigin)
	targetJS := htmlSafeJSON(targetJSON)

	// CSP locks who is allowed to embed this page (frame-ancestors) to the
	// validated target_origin. default-src 'none' + script-src 'unsafe-inline'
	// blocks every other resource type. Cache-Control: no-store keeps the
	// token out of any caching layer.
	w.Header().Set("Content-Security-Policy",
		fmt.Sprintf("frame-ancestors %s; default-src 'none'; script-src 'unsafe-inline'", canonicalOrigin))
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	fmt.Fprintf(w, `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>auth</title></head>
<body>
<script id="d" type="application/json">%s</script>
<script>
(function(){
  try {
    var d = JSON.parse(document.getElementById('d').textContent);
    window.parent.postMessage(d, %s);
  } catch (e) {}
})();
</script>
</body>
</html>
`, payloadHTML, targetJS)
}

// htmlSafeJSON makes a JSON byte string safe to embed inside an HTML
// <script> element. Go's encoding/json escapes <, >, & by default, so the
// JSON itself can't break out of the script tag. This helper additionally
// escapes U+2028 and U+2029, which are valid JSON characters but illegal
// line terminators inside JS string literals.
func htmlSafeJSON(b []byte) string {
	s := string(b)
	// "\u2028" / "\u2029" are the literal U+2028 / U+2029 line
	// separators (LSEP / PSEP). They are legal in JSON strings but
	// terminate JS string literals; replace them with their \u-escaped
	// form so they parse safely inside <script>.
	s = strings.ReplaceAll(s, "\u2028", `\u2028`)
	s = strings.ReplaceAll(s, "\u2029", `\u2029`)
	return s
}
