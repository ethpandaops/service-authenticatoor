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

func TestHandleClientJS_PublicNoAuthRequired(t *testing.T) {
	s, _, prov := newTestServer(t)
	// Even with the active provider configured to reject every request,
	// /client.js must be reachable — it's a public path outside /auth/*.
	prov.verifyHeader = "X-Test-Assertion"

	req := httptest.NewRequest(http.MethodGet, "/client.js", nil)
	// no email, no assertion
	rr := httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status: got %d, want 200 (public path must skip auth middleware)", rr.Code)
	}
}
