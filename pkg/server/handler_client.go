package server

import (
	_ "embed"
	"net/http"
	"strings"
)

//go:embed static/authenticatoor.js
var authenticatoorJS string

// handleClientJS serves the authenticatoor JS client library with the
// service's external URL templated in. The result is intended to be loaded
// from a consumer app via:
//
//	<script src="https://auth.<devnet>/client.js"></script>
//
// The library exposes window.ethpandaops.authenticatoor.{checkLogin, login,
// logout, getToken, isLoggedIn, authServiceURL}.
//
// Hosted under the public path (outside /auth/*) so it can be loaded
// without authenticating to the upstream proxy.
func (s *Server) handleClientJS(w http.ResponseWriter, r *http.Request) {
	body := strings.ReplaceAll(authenticatoorJS, "__AUTH_SERVICE_URL__", strings.TrimRight(s.cfg.ExternalURL, "/"))

	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write([]byte(body))
}
