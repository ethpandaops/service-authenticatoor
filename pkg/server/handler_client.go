package server

import (
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/evanw/esbuild/pkg/api"
	"github.com/gorilla/mux"

	"github.com/ethpandaops/service-authenticatoor/pkg/auth"
)

//go:embed static/authenticatoor-*.js
var authenticatoorFS embed.FS

// builtClientAsset is a client script prepared for serving: the
// __AUTH_SERVICE_URL__ placeholder templated in, and — outside dev
// mode — minified, with an optional external source map.
type builtClientAsset struct {
	code      []byte
	sourceMap []byte // nil when not generated (dev mode / frame script)
}

// clientAsset returns the serving form of an embedded client script.
// Templating runs BEFORE minification so generated source maps line up
// with the served bytes. Outside dev mode the script is minified
// (comments stripped, whitespace collapsed, local identifiers mangled —
// the scripts are IIFEs, so nearly every identifier is local); a
// non-empty sourceURL additionally generates an external source map
// embedding the templated source. sourceURL must be the script's own
// public URL (relative to the map's URL, e.g. "client-v2.js") — that
// makes the mapped source resolve to the same URL as the served script,
// so devtools overlays the original onto the one file entry instead of
// listing a second file. In dev mode the templated source is served
// verbatim. Falls back to the unminified source if esbuild rejects the
// file: serving readable JS beats serving nothing.
//
// Sources are compiled into the binary and cfg is immutable, so each
// variant is built exactly once, on first use.
func (s *Server) clientAsset(name, sourceURL string) (*builtClientAsset, error) {
	cacheKey := name + "|" + sourceURL

	s.clientAssetMu.Lock()
	defer s.clientAssetMu.Unlock()

	if cached, ok := s.clientAssetCache[cacheKey]; ok {
		return cached, nil
	}

	raw, err := authenticatoorFS.ReadFile(name)
	if err != nil {
		return nil, err
	}
	src := strings.ReplaceAll(string(raw), "__AUTH_SERVICE_URL__", strings.TrimRight(s.cfg.ExternalURL, "/"))

	asset := &builtClientAsset{code: []byte(src)}
	if !s.cfg.DevMode {
		opts := api.TransformOptions{
			Loader:            api.LoaderJS,
			Target:            api.ES2018,
			MinifyWhitespace:  true,
			MinifyIdentifiers: true,
			MinifySyntax:      true,
		}
		if sourceURL != "" {
			opts.Sourcefile = sourceURL
			opts.Sourcemap = api.SourceMapExternal
			opts.SourcesContent = api.SourcesContentInclude
		}
		res := api.Transform(src, opts)
		if len(res.Errors) > 0 {
			s.log.WithField("asset", name).WithField("error", res.Errors[0].Text).
				Warn("client script minification failed, serving unminified")
		} else {
			asset.code = res.Code
			if sourceURL != "" {
				asset.sourceMap = res.Map
			}
		}
	}
	s.clientAssetCache[cacheKey] = asset

	return asset, nil
}

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

// serveClientJS writes the requested client library version with the
// service's external URL templated in. version must already be validated.
//
// The source map link points at the path-versioned name
// (client-v<n>.js.map) whose map names its source client-v<n>.js —
// browser devtools resolve map sources as URLs (query strings don't
// survive that comparison), so only the path-versioned form overlays the
// original source onto the served file instead of listing a second file.
func (s *Server) serveClientJS(w http.ResponseWriter, r *http.Request, version string) {
	asset, err := s.clientAsset("static/authenticatoor-v"+version+".js", "client-v"+version+".js")
	if err != nil {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(asset.code)
	if asset.sourceMap != nil {
		_, _ = fmt.Fprintf(w, "\n//# sourceMappingURL=client-v%s.js.map\n", version)
	}
}

// handleClientJS serves the legacy /client.js path: always v1, for
// consumers that predate versioned client URLs. New integrations load
// the path-versioned form served by handleClientJSVersioned:
//
//	<script src="https://auth.<devnet>/client-v2.js"></script>
//
// v1 exposes the polling-style API
// {checkLogin, login, logout, getToken, isLoggedIn, authServiceURL}; v2
// exposes the shared-session, event-emitting API
// {addEventListener, removeEventListener, getStatus, getToken, login,
// logout, authServiceURL} backed by the /clientFrame hidden iframe.
//
// Hosted under the public path (outside /auth/*) so it can be loaded
// without authenticating to the upstream proxy.
func (s *Server) handleClientJS(w http.ResponseWriter, r *http.Request) {
	s.serveClientJS(w, r, "1")
}

// handleClientJSVersioned serves /client-v{version}.js. The version is
// pattern-validated by the route ([0-9]{1,2}); unknown versions 404 via
// the embed-FS lookup.
func (s *Server) handleClientJSVersioned(w http.ResponseWriter, r *http.Request) {
	s.serveClientJS(w, r, mux.Vars(r)["version"])
}

// handleClientJSMap serves the external source map for
// /client-v{version}.js so the minified client stays debuggable in
// browser devtools. The map embeds the (templated) original source under
// the script's own URL. 404 in dev mode — the script itself is served
// unminified there.
func (s *Server) handleClientJSMap(w http.ResponseWriter, r *http.Request) {
	version := mux.Vars(r)["version"]

	asset, err := s.clientAsset("static/authenticatoor-v"+version+".js", "client-v"+version+".js")
	if err != nil || asset.sourceMap == nil {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(asset.sourceMap)
}

// handleClientFrame serves the HTML shell for the hidden shared-session
// iframe mounted by the v2 client on every consuming app. The frame script
// is inlined into the page (saves the extra script request); the CSP
// allow-lists that one script by its SHA-256 hash, which is stricter than
// both 'unsafe-inline' (any inline script) and 'self' (any same-origin
// script URL) — nothing but the exact embedded source can execute.
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

	frameAsset, err := s.clientAsset("static/authenticatoor-frame-v"+version+".js", "")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	frameJS := frameAsset.code

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

	// The hash source pins script execution to the exact inlined frame
	// script; connect-src 'self' covers its same-origin token/logout
	// fetches; everything else is blocked. frame-ancestors locks who may
	// embed this page to the validated origin.
	scriptHash := sha256.Sum256(frameJS)
	w.Header().Set("Content-Security-Policy",
		fmt.Sprintf("frame-ancestors %s; default-src 'none'; script-src 'sha256-%s'; connect-src 'self'",
			canonicalOrigin, base64.StdEncoding.EncodeToString(scriptHash[:])))
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// frameJS is embedded at build time and verified by tests to contain
	// no "</script" or "<!--" sequences, so it is safe to inline raw.
	_, _ = fmt.Fprintf(w, `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>authenticatoor</title></head>
<body>
<script>%s</script>
</body>
</html>
`, frameJS)
}
