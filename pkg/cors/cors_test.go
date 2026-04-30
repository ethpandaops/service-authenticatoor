package cors

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func newCORSHandler(allowed []string) http.Handler {
	cfg := DefaultConfig()
	cfg.AllowedOriginPatterns = allowed
	return Middleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
}

func TestCORS_AllowedOrigin(t *testing.T) {
	h := newCORSHandler([]string{"*.example.com"})

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Origin", "https://app.example.com")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Errorf("ACAO: got %q", got)
	}
	if got := rr.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Errorf("ACAC: got %q", got)
	}
	if got := rr.Header().Get("Vary"); got != "Origin" {
		t.Errorf("Vary: got %q", got)
	}
}

func TestCORS_DisallowedOrigin(t *testing.T) {
	h := newCORSHandler([]string{"*.example.com"})

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Origin", "https://evil.com")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("ACAO leaked for disallowed origin: got %q", got)
	}
	if got := rr.Header().Get("Access-Control-Allow-Credentials"); got != "" {
		t.Errorf("ACAC leaked: %q", got)
	}
	// Body still served — browser does the blocking via missing ACAO.
	if rr.Code != http.StatusOK {
		t.Errorf("status: got %d", rr.Code)
	}
}

func TestCORS_OptionsPreflight(t *testing.T) {
	h := newCORSHandler([]string{"*.example.com"})

	req := httptest.NewRequest("OPTIONS", "/auth/token", nil)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", "GET")
	req.Header.Set("Access-Control-Request-Headers", "Authorization")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("status: got %d, want 204", rr.Code)
	}
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Errorf("ACAO: got %q", got)
	}
	if got := rr.Header().Get("Access-Control-Allow-Methods"); got == "" {
		t.Error("ACAM empty")
	}
	if got := rr.Header().Get("Access-Control-Allow-Headers"); got == "" {
		t.Error("ACAH empty")
	}
	if got := rr.Header().Get("Access-Control-Max-Age"); got != "86400" {
		t.Errorf("ACMA: got %q", got)
	}
}

func TestCORS_NoOrigin(t *testing.T) {
	h := newCORSHandler([]string{"*.example.com"})

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("ACAO leaked when no Origin set: %q", got)
	}
	if rr.Code != http.StatusOK {
		t.Errorf("status: got %d", rr.Code)
	}
}

func TestCORS_NonHTTPOrigin(t *testing.T) {
	h := newCORSHandler([]string{"*.example.com"})

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Origin", "file:///etc/passwd")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("ACAO leaked for non-http origin: %q", got)
	}
}
