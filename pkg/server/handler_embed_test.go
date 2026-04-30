package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestHandleEmbed_Success(t *testing.T) {
	s, _ := newTestServer(t)

	q := url.Values{"target_origin": {"https://app.test.example/"}}
	req := httptest.NewRequest(http.MethodGet, "/auth/embed?"+q.Encode(), nil)
	req.Header.Set("X-Test-Email", "alice@example.com")
	rr := httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status: %d body: %s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Errorf("content-type: %q", got)
	}
	csp := rr.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "frame-ancestors https://app.test.example") {
		t.Errorf("CSP missing frame-ancestors: %q", csp)
	}
	if got := rr.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("cache-control: %q", got)
	}
	body := rr.Body.String()
	if !strings.Contains(body, `"type":"authenticatoor.token"`) {
		t.Errorf("body missing token-type marker: %s", body)
	}
	if !strings.Contains(body, `"https://app.test.example"`) {
		t.Errorf("body missing target_origin in postMessage: %s", body)
	}
	if !strings.Contains(body, "window.parent.postMessage") {
		t.Errorf("body missing postMessage call: %s", body)
	}
}

func TestHandleEmbed_RejectsDisallowedTarget(t *testing.T) {
	s, _ := newTestServer(t)

	cases := []string{
		"https://evil.com/",
		"https://test.example.attacker.com/",
		"javascript:alert(1)",
		"",
	}
	for _, target := range cases {
		t.Run(target, func(t *testing.T) {
			q := url.Values{"target_origin": {target}}
			req := httptest.NewRequest(http.MethodGet, "/auth/embed?"+q.Encode(), nil)
			req.Header.Set("X-Test-Email", "alice@example.com")
			rr := httptest.NewRecorder()
			s.routes().ServeHTTP(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Errorf("status: got %d, want 400 for %q", rr.Code, target)
			}
		})
	}
}

func TestHandleEmbed_RejectsMissingEmail(t *testing.T) {
	s, _ := newTestServer(t)

	q := url.Values{"target_origin": {"https://app.test.example/"}}
	req := httptest.NewRequest(http.MethodGet, "/auth/embed?"+q.Encode(), nil)
	// no X-Test-Email
	rr := httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want 401", rr.Code)
	}
}

func TestHandleEmbed_TargetOriginIsStrippedToOrigin(t *testing.T) {
	s, _ := newTestServer(t)

	// Path/query/fragment in target_origin must not appear in the postMessage
	// target — postMessage uses scheme+host only.
	q := url.Values{"target_origin": {"https://app.test.example/some/path?a=1#frag"}}
	req := httptest.NewRequest(http.MethodGet, "/auth/embed?"+q.Encode(), nil)
	req.Header.Set("X-Test-Email", "alice@example.com")
	rr := httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status: %d", rr.Code)
	}
	body := rr.Body.String()
	if strings.Contains(body, "/some/path") {
		t.Errorf("body leaked path from target_origin: %s", body)
	}
	if !strings.Contains(body, `"https://app.test.example"`) {
		t.Errorf("expected canonical origin in body: %s", body)
	}
}

func TestHandleEmbed_HTMLEscapesPayload(t *testing.T) {
	s, _ := newTestServer(t)

	q := url.Values{"target_origin": {"https://app.test.example"}}
	req := httptest.NewRequest(http.MethodGet, "/auth/embed?"+q.Encode(), nil)
	req.Header.Set("X-Test-Email", "alice@example.com")
	rr := httptest.NewRecorder()
	s.routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status: %d", rr.Code)
	}
	body := rr.Body.String()
	// JSON inside <script> must never contain a literal "</script>".
	if strings.Contains(body, "</script>"+`{`) || strings.Contains(strings.ToLower(body), "</script  ") {
		t.Errorf("possible script-tag break in body: %s", body)
	}
	// The JSON block must HTML-escape <, >, & (Go's encoding/json does this
	// by default for the SetEscapeHTML(true) path).
	if strings.Contains(body, ">authenticatoor.token<") {
		t.Errorf("JSON not HTML-escaped: %s", body)
	}
}

func TestHtmlSafeJSON_EscapesLineTerminators(t *testing.T) {
	// Input contains a U+2028 (line separator) and a U+2029 (paragraph
	// separator). They must come out as literal `\u2028` / `\u2029`
	// 6-character JS-escape sequences so they parse safely inside a JS
	// string literal.
	in := []byte("a\u2028b\u2029c")
	got := htmlSafeJSON(in)
	want := `a\u2028b\u2029c`
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
