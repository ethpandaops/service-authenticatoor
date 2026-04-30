package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type fakeVerifier struct {
	tokens map[string]*Claims
}

func (f *fakeVerifier) Verify(s string) (*Claims, error) {
	if c, ok := f.tokens[s]; ok {
		return c, nil
	}
	return nil, errors.New("nope")
}

func TestMiddleware_NoToken(t *testing.T) {
	v := &fakeVerifier{}
	called := false
	h := Middleware(v)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if _, ok := ClaimsFromContext(r.Context()); ok {
			t.Error("did not expect claims")
		}
	}))

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if !called {
		t.Error("next was not called")
	}
}

func TestMiddleware_ValidBearer(t *testing.T) {
	want := &Claims{Email: "alice@example.com"}
	v := &fakeVerifier{tokens: map[string]*Claims{"goodtoken": want}}

	called := false
	h := Middleware(v)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		got, ok := ClaimsFromContext(r.Context())
		if !ok || got != want {
			t.Errorf("claims missing or wrong: %v", got)
		}
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer goodtoken")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if !called {
		t.Error("next was not called")
	}
}

func TestMiddleware_InvalidBearer_PassesThrough(t *testing.T) {
	v := &fakeVerifier{}
	called := false
	h := Middleware(v)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if _, ok := ClaimsFromContext(r.Context()); ok {
			t.Error("did not expect claims")
		}
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer bogus")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if !called {
		t.Error("next was not called")
	}
}

func TestMiddleware_QueryFallback(t *testing.T) {
	want := &Claims{Email: "alice@example.com"}
	v := &fakeVerifier{tokens: map[string]*Claims{"goodtoken": want}}

	called := false
	h := Middleware(v)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		got, ok := ClaimsFromContext(r.Context())
		if !ok || got != want {
			t.Errorf("claims missing or wrong: %v", got)
		}
	}))

	req := httptest.NewRequest("GET", "/?auth=goodtoken", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if !called {
		t.Error("next was not called")
	}
}

func TestRequireAuth_401WhenAbsent(t *testing.T) {
	called := false
	h := RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	h(rr, req)

	if called {
		t.Error("inner handler should not have run")
	}
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want 401", rr.Code)
	}
}

func TestRequireAuth_PassesWithClaims(t *testing.T) {
	want := &Claims{Email: "alice@example.com"}
	called := false
	h := RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if got, ok := ClaimsFromContext(r.Context()); !ok || got != want {
			t.Errorf("claims wrong inside handler: %v", got)
		}
	})

	req := httptest.NewRequest("GET", "/", nil).WithContext(WithClaims(httptest.NewRequest("GET", "/", nil).Context(), want))
	rr := httptest.NewRecorder()
	h(rr, req)
	if !called {
		t.Error("handler should have run")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("status: got %d, want 200", rr.Code)
	}
}
