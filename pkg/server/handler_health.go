package server

import (
	"net/http"
)

// handleHealth is a liveness probe. It does not touch the issuer or any
// external dependency.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte("ok\n"))
}

// handleIndex serves a small landing page describing the available
// endpoints.
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(indexHTML))
}

// indexHTML is the body of GET /. Static content; no user input is
// interpolated.
const indexHTML = `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>authenticatoor</title>
<style>body{font:14px/1.5 system-ui,sans-serif;max-width:40em;margin:4em auto;padding:0 1em;color:#222}code{background:#eee;padding:.1em .3em;border-radius:3px}</style>
</head>
<body>
<h1>authenticatoor</h1>
<p>This service issues short-lived JWTs to users authenticated by the configured protection provider (Cloudflare Access, HTTP Basic, GitHub OAuth, or dev-only any-auth).</p>
<ul>
<li><code>/auth/token</code> — issue a JWT</li>
<li><code>/auth/login?return_to=…</code> — issue a JWT and redirect to an allow-listed host</li>
<li><code>/auth/embed?target_origin=…</code> — issue a JWT and post it to an allow-listed parent window via postMessage (silent iframe path)</li>
<li><code>/auth/userinfo</code> — identity introspection</li>
<li><code>/auth/logout</code> — provider-dispatched logout (clears session cookie / rotates Basic realm / etc.)</li>
<li><code>/jwks.json</code> — public keys (for verifiers)</li>
<li><code>/.well-known/openid-configuration</code> — discovery</li>
<li><code>/client.js</code> — drop-in browser client (<code>window.ethpandaops.authenticatoor</code>)</li>
</ul>
</body>
</html>
`
