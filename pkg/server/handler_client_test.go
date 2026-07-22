package server

import (
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
	for _, marker := range []string{
		"window.ethpandaops",
		"checkLogin:",
		"login:",
		"logout:",
		"getToken:",
		"function checkLogin(",
		"function login(",
		"function logout(",
		"function getToken(",
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
		{name: "default is v1", url: "/client.js", wantStatus: http.StatusOK, wantMarker: "checkLogin:"},
		{name: "explicit v1", url: "/client.js?v=1", wantStatus: http.StatusOK, wantMarker: "checkLogin:"},
		{name: "v2", url: "/client.js?v=2", wantStatus: http.StatusOK, wantMarker: "getStatus:"},
		{name: "unknown version", url: "/client.js?v=3", wantStatus: http.StatusNotFound},
		{name: "two digit unknown", url: "/client.js?v=99", wantStatus: http.StatusNotFound},
		{name: "path traversal", url: "/client.js?v=..%2Fv1", wantStatus: http.StatusNotFound},
		{name: "non numeric", url: "/client.js?v=x", wantStatus: http.StatusNotFound},
		{name: "too long", url: "/client.js?v=123", wantStatus: http.StatusNotFound},
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

	req := httptest.NewRequest(http.MethodGet, "/client.js?v=2", nil)
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

func TestHandleClientFrameJS(t *testing.T) {
	s, _, _ := newTestServer(t)

	tests := []struct {
		name       string
		url        string
		wantStatus int
	}{
		{name: "default is v2", url: "/client.frame.js", wantStatus: http.StatusOK},
		{name: "explicit v2", url: "/client.frame.js?v=2", wantStatus: http.StatusOK},
		{name: "unknown version", url: "/client.frame.js?v=1", wantStatus: http.StatusNotFound},
		{name: "non numeric", url: "/client.frame.js?v=x", wantStatus: http.StatusNotFound},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.url, nil)
			rr := httptest.NewRecorder()
			s.routes().ServeHTTP(rr, req)

			if rr.Code != tc.wantStatus {
				t.Fatalf("status: got %d, want %d", rr.Code, tc.wantStatus)
			}
			if tc.wantStatus != http.StatusOK {
				return
			}
			if got := rr.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/javascript") {
				t.Errorf("content-type: %q", got)
			}
			body := rr.Body.String()
			// The frame script is served verbatim (relative URLs, no
			// templating) and must contain the session machinery.
			for _, marker := range []string{
				"'/auth/token'",
				"'/auth/logout'",
				"ethpandaops.authenticatoor.v2.session",
				"navigator.locks",
			} {
				if !strings.Contains(body, marker) {
					t.Errorf("body missing %q", marker)
				}
			}
			if strings.Contains(body, "__AUTH_SERVICE_URL__") {
				t.Errorf("frame script must not carry the templating placeholder")
			}
		})
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

	csp := rr.Header().Get("Content-Security-Policy")
	// The embedder is pinned to the canonical origin — scheme + host:port,
	// path stripped.
	if !strings.Contains(csp, "frame-ancestors https://app.test.example:8443") {
		t.Errorf("csp missing frame-ancestors pin: %q", csp)
	}
	if !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("csp missing default-src 'none': %q", csp)
	}
	if !strings.Contains(csp, "script-src 'self'") {
		t.Errorf("csp missing script-src 'self': %q", csp)
	}
	if !strings.Contains(csp, "connect-src 'self'") {
		t.Errorf("csp missing connect-src 'self': %q", csp)
	}
	if strings.Contains(csp, "unsafe-inline") {
		t.Errorf("csp must not allow inline script: %q", csp)
	}
	if got := rr.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Errorf("referrer-policy: %q", got)
	}
	if got := rr.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Errorf("content-type: %q", got)
	}

	body := rr.Body.String()
	if !strings.Contains(body, `<script src="/client.frame.js?v=2"></script>`) {
		t.Errorf("body missing frame script tag:\n%s", body)
	}
	// No inline script — the page must work under script-src 'self'.
	if strings.Contains(body, "<script>") {
		t.Errorf("frame page must not contain inline script:\n%s", body)
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
		"/client.js?v=2",
		"/client.frame.js",
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
