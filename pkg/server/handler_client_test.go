package server

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandleClientJS(t *testing.T) {
	s, _, _ := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/client.js", nil)
	rr := httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d", rr.Code)
	}
	if got := rr.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/javascript") {
		t.Errorf("content-type: %q", got)
	}
	if got := rr.Header().Get("Cache-Control"); got == "" {
		t.Errorf("cache-control: empty")
	}

	body := rr.Body.String()

	// Must contain all four documented entry points + the namespace.
	// Scripts are served minified (local identifiers mangled), so only
	// object property keys and global accesses are stable markers.
	for _, marker := range []string{
		"window.ethpandaops",
		"checkLogin:",
		"login:",
		"logout:",
		"getToken:",
	} {
		if !strings.Contains(body, marker) {
			t.Errorf("body missing %q", marker)
		}
	}

	// Must have substituted the auth service URL — placeholder gone.
	if strings.Contains(body, "__AUTH_SERVICE_URL__") {
		t.Errorf("placeholder __AUTH_SERVICE_URL__ not substituted")
	}
	if !strings.Contains(body, "https://auth.test.example") {
		t.Errorf("body missing templated auth service URL: head:\n%s", body[:600])
	}
}

func TestHandleClientJS_Versions(t *testing.T) {
	s, _, _ := newTestServer(t)

	tests := []struct {
		name       string
		url        string
		wantStatus int
		wantMarker string
	}{
		{name: "legacy path is v1", url: "/client.js", wantStatus: http.StatusOK, wantMarker: "checkLogin:"},
		{name: "legacy path ignores query", url: "/client.js?v=2", wantStatus: http.StatusOK, wantMarker: "checkLogin:"},
		{name: "versioned v1", url: "/client-v1.js", wantStatus: http.StatusOK, wantMarker: "checkLogin:"},
		{name: "versioned v2", url: "/client-v2.js", wantStatus: http.StatusOK, wantMarker: "getStatus:"},
		{name: "unknown version", url: "/client-v9.js", wantStatus: http.StatusNotFound},
		{name: "two digit unknown", url: "/client-v99.js", wantStatus: http.StatusNotFound},
		{name: "non numeric", url: "/client-vx.js", wantStatus: http.StatusNotFound},
		{name: "too long", url: "/client-v123.js", wantStatus: http.StatusNotFound},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.url, nil)
			rr := httptest.NewRecorder()
			s.routes().ServeHTTP(rr, req)

			if rr.Code != tc.wantStatus {
				t.Fatalf("status: got %d, want %d", rr.Code, tc.wantStatus)
			}
			if tc.wantMarker != "" && !strings.Contains(rr.Body.String(), tc.wantMarker) {
				t.Errorf("body missing %q", tc.wantMarker)
			}
		})
	}
}

func TestHandleClientJS_V2Surface(t *testing.T) {
	s, _, _ := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/client-v2.js", nil)
	rr := httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d", rr.Code)
	}

	body := rr.Body.String()

	// Must expose the documented v2 API surface.
	for _, marker := range []string{
		"window.ethpandaops",
		"addEventListener:",
		"removeEventListener:",
		"getStatus:",
		"getToken:",
		"login:",
		"logout:",
		"/clientFrame?v=2&origin=",
	} {
		if !strings.Contains(body, marker) {
			t.Errorf("body missing %q", marker)
		}
	}

	if strings.Contains(body, "__AUTH_SERVICE_URL__") {
		t.Errorf("placeholder __AUTH_SERVICE_URL__ not substituted")
	}
	if !strings.Contains(body, "https://auth.test.example") {
		t.Errorf("body missing templated auth service URL")
	}
}

func TestFrameScriptInlineSafe(t *testing.T) {
	s, _, _ := newTestServer(t)

	// The frame script is inlined raw into the /clientFrame HTML shell,
	// so the SERVED (minified) bytes must never contain sequences that
	// terminate or derail the surrounding <script> element.
	asset, err := s.clientAsset("static/authenticatoor-frame-v2.js", "")
	if err != nil {
		t.Fatalf("load frame script: %v", err)
	}
	body := strings.ToLower(string(asset.code))
	for _, forbidden := range []string{"</script", "<!--"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("frame script contains %q — unsafe to inline into HTML", forbidden)
		}
	}
	if strings.Contains(body, strings.ToLower("__AUTH_SERVICE_URL__")) {
		t.Errorf("frame script must not carry the templating placeholder")
	}
}

func TestClientAssetMinified(t *testing.T) {
	s, _, _ := newTestServer(t)

	// Serving is expected to strip the (large) header comments and mangle
	// whitespace — a served script should be substantially smaller than
	// its source.
	for _, name := range []string{
		"static/authenticatoor-v1.js",
		"static/authenticatoor-v2.js",
		"static/authenticatoor-frame-v2.js",
	} {
		raw, err := authenticatoorFS.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		asset, err := s.clientAsset(name, "")
		if err != nil {
			t.Fatalf("load %s: %v", name, err)
		}
		if len(asset.code) >= len(raw) {
			t.Errorf("%s: served size %d not smaller than source %d — minification inactive",
				name, len(asset.code), len(raw))
		}
		if strings.Contains(string(asset.code), "// ") {
			t.Errorf("%s: served script still contains comments", name)
		}
	}
}

func TestHandleClientJS_SourceMap(t *testing.T) {
	s, _, _ := newTestServer(t)

	// The script must link its path-versioned external source map
	// (devtools resolve map sources as URLs; query strings don't survive
	// that comparison — hence the path-versioned naming scheme).
	req0 := httptest.NewRequest(http.MethodGet, "/client-v2.js", nil)
	rr0 := httptest.NewRecorder()
	s.routes().ServeHTTP(rr0, req0)
	if rr0.Code != http.StatusOK {
		t.Fatalf("client-v2.js status: got %d", rr0.Code)
	}
	if !strings.Contains(rr0.Body.String(), "//# sourceMappingURL=client-v2.js.map") {
		t.Errorf("client-v2.js missing sourceMappingURL comment")
	}

	// The map endpoint must serve a JSON source map embedding the
	// templated source.
	req := httptest.NewRequest(http.MethodGet, "/client-v2.js.map", nil)
	rr := httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("client-v2.js.map status: got %d", rr.Code)
	}
	if got := rr.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Errorf("map content-type: %q", got)
	}
	body := rr.Body.String()
	// The mapped source must carry the script's own public URL so
	// devtools overlays the original onto the served file instead of
	// listing a second file.
	for _, marker := range []string{`"mappings"`, `"sourcesContent"`, `"client-v2.js"`} {
		if !strings.Contains(body, marker) {
			t.Errorf("source map missing %q", marker)
		}
	}

	// Unknown versions 404 like the script itself.
	req = httptest.NewRequest(http.MethodGet, "/client-v9.js.map", nil)
	rr = httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("client-v9.js.map status: got %d, want 404", rr.Code)
	}

	// The inlined frame page stays unmapped.
	req = httptest.NewRequest(http.MethodGet,
		"/clientFrame?v=2&origin=https%3A%2F%2Fapp.test.example", nil)
	rr = httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)
	if strings.Contains(rr.Body.String(), "sourceMappingURL") {
		t.Errorf("frame page must not reference a source map")
	}
}

func TestHandleClientJS_DevMode(t *testing.T) {
	s, _, _ := newTestServer(t)
	// cfg is only consulted on first asset build; flipping it before any
	// request simulates a dev-mode config.
	s.cfg.DevMode = true

	req := httptest.NewRequest(http.MethodGet, "/client-v2.js", nil)
	rr := httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("client.js status: got %d", rr.Code)
	}
	body := rr.Body.String()
	// Unminified: header comments intact, no map link, templating applied.
	if !strings.Contains(body, "// authenticatoor — client library") {
		t.Errorf("dev mode must serve the unminified source")
	}
	if strings.Contains(body, "sourceMappingURL") {
		t.Errorf("dev mode must not link a source map")
	}
	if strings.Contains(body, "__AUTH_SERVICE_URL__") {
		t.Errorf("dev mode must still template the auth service URL")
	}

	// No map to serve in dev mode.
	req = httptest.NewRequest(http.MethodGet, "/client-v2.js.map", nil)
	rr = httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("client-v2.js.map in dev mode: got %d, want 404", rr.Code)
	}

	// The frame page serves (and hash-pins) the unminified script.
	req = httptest.NewRequest(http.MethodGet,
		"/clientFrame?v=2&origin=https%3A%2F%2Fapp.test.example", nil)
	rr = httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("clientFrame status: got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "// authenticatoor — shared-session frame") {
		t.Errorf("dev mode frame page must inline the unminified script")
	}
}

func TestHandleClientFrame(t *testing.T) {
	s, _, _ := newTestServer(t)

	tests := []struct {
		name       string
		url        string
		wantStatus int
	}{
		{
			name:       "allowed origin",
			url:        "/clientFrame?v=2&origin=" + "https%3A%2F%2Fapp.test.example",
			wantStatus: http.StatusOK,
		},
		{
			name:       "missing origin",
			url:        "/clientFrame?v=2",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "disallowed origin",
			url:        "/clientFrame?v=2&origin=https%3A%2F%2Fevil.example.com",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "userinfo spoof",
			url:        "/clientFrame?v=2&origin=https%3A%2F%2Fapp.test.example%40evil.example.com",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "non http scheme",
			url:        "/clientFrame?v=2&origin=javascript%3Aalert(1)",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "unknown version",
			url:        "/clientFrame?v=9&origin=https%3A%2F%2Fapp.test.example",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "malformed version",
			url:        "/clientFrame?v=..%2Fx&origin=https%3A%2F%2Fapp.test.example",
			wantStatus: http.StatusNotFound,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.url, nil)
			rr := httptest.NewRecorder()
			s.routes().ServeHTTP(rr, req)

			if rr.Code != tc.wantStatus {
				t.Fatalf("status: got %d, want %d (body: %s)", rr.Code, tc.wantStatus, rr.Body.String())
			}
		})
	}
}

func TestHandleClientFrame_Headers(t *testing.T) {
	s, _, _ := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet,
		"/clientFrame?v=2&origin=https%3A%2F%2Fapp.test.example%3A8443%2Fsome%2Fpath", nil)
	rr := httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d (body: %s)", rr.Code, rr.Body.String())
	}

	frameAsset, err := s.clientAsset("static/authenticatoor-frame-v2.js", "")
	if err != nil {
		t.Fatalf("load frame script: %v", err)
	}
	frameJS := frameAsset.code
	scriptHash := sha256.Sum256(frameJS)
	wantHashSource := "'sha256-" + base64.StdEncoding.EncodeToString(scriptHash[:]) + "'"

	csp := rr.Header().Get("Content-Security-Policy")
	// The embedder is pinned to the canonical origin — scheme + host:port,
	// path stripped.
	if !strings.Contains(csp, "frame-ancestors https://app.test.example:8443") {
		t.Errorf("csp missing frame-ancestors pin: %q", csp)
	}
	if !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("csp missing default-src 'none': %q", csp)
	}
	// Script execution is pinned to the exact inlined frame script by
	// hash — stricter than both 'unsafe-inline' and 'self'.
	if !strings.Contains(csp, "script-src "+wantHashSource) {
		t.Errorf("csp missing script-src hash pin %s: %q", wantHashSource, csp)
	}
	if !strings.Contains(csp, "connect-src 'self'") {
		t.Errorf("csp missing connect-src 'self': %q", csp)
	}
	if strings.Contains(csp, "unsafe-inline") {
		t.Errorf("csp must not allow arbitrary inline script: %q", csp)
	}
	if strings.Contains(csp, "script-src 'self'") {
		t.Errorf("csp must not allow arbitrary same-origin scripts: %q", csp)
	}
	if got := rr.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Errorf("referrer-policy: %q", got)
	}
	if got := rr.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Errorf("content-type: %q", got)
	}

	body := rr.Body.String()
	// The frame script is inlined verbatim — exactly the bytes the CSP
	// hash covers.
	if !strings.Contains(body, "<script>"+string(frameJS)+"</script>") {
		t.Errorf("body does not inline the frame script verbatim")
	}
	if strings.Contains(body, "<script src=") {
		t.Errorf("frame page must not reference external scripts:\n%s", body)
	}
	// The session machinery must be present in the page. Quote style is
	// left to the minifier, so markers omit the quotes.
	for _, marker := range []string{
		"/auth/token",
		"/auth/logout",
		"ethpandaops.authenticatoor.v2.session",
		"navigator.locks",
	} {
		if !strings.Contains(body, marker) {
			t.Errorf("body missing %q", marker)
		}
	}
}

func TestHandleClientJS_PublicNoAuthRequired(t *testing.T) {
	s, _, prov := newTestServer(t)
	// Even with the active provider configured to reject every request,
	// the client-library paths must be reachable — they are public paths
	// outside /auth/*.
	prov.verifyHeader = "X-Test-Assertion"

	for _, path := range []string{
		"/client.js",
		"/client-v2.js",
		"/client-v2.js.map",
		"/clientFrame?v=2&origin=https%3A%2F%2Fapp.test.example",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		// no email, no assertion
		rr := httptest.NewRecorder()
		s.routes().ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("%s: status: got %d, want 200 (public path must skip auth middleware)", path, rr.Code)
		}
	}
}
