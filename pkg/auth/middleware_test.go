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

func (f *fakeVerifier) Verify(s string, _ ...VerifyOption) (*Claims, error) {
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

func TestRequireFeature(t *testing.T) {
	tests := []struct {
		name      string
		claims    *Claims // nil: no claims on the context
		wantDeny  int     // status under FeatureDefaultDeny
		wantAllow int     // status under FeatureDefaultAllow
	}{
		{"no claims", nil, http.StatusUnauthorized, http.StatusUnauthorized},
		{"feature granted", &Claims{Services: "-all,+dora,+dora:roll"}, http.StatusOK, http.StatusOK},
		{"every feature granted", &Claims{Services: "+all,+all:all"}, http.StatusOK, http.StatusOK},
		{"no services claim: no constraint", &Claims{}, http.StatusOK, http.StatusOK},
		{"base access only", &Claims{Services: "-all,+dora"}, http.StatusForbidden, http.StatusOK},
		{"base access to everything only", &Claims{Services: "+all"}, http.StatusForbidden, http.StatusOK},
		{"another feature granted", &Claims{Services: "-all,+dora,+dora:hold"}, http.StatusForbidden, http.StatusOK},
		{"feature excluded", &Claims{Services: "-all,+dora,-dora:roll"}, http.StatusForbidden, http.StatusForbidden},
		{"feature excluded from all", &Claims{Services: "+dora:all:-roll"}, http.StatusForbidden, http.StatusForbidden},
		{"feature granted on another service", &Claims{Services: "-all,+spamoor,+spamoor:roll"}, http.StatusForbidden, http.StatusForbidden},
		{"no access at all", &Claims{Services: "-all"}, http.StatusForbidden, http.StatusForbidden},
	}
	for _, tc := range tests {
		for _, mode := range []struct {
			name string
			def  FeatureDefault
			want int
		}{
			{"default deny", FeatureDefaultDeny, tc.wantDeny},
			{"default allow", FeatureDefaultAllow, tc.wantAllow},
		} {
			t.Run(tc.name+"/"+mode.name, func(t *testing.T) {
				called := false
				h := RequireFeature("dora", "roll", mode.def, func(w http.ResponseWriter, _ *http.Request) {
					called = true
					w.WriteHeader(http.StatusOK)
				})

				req := httptest.NewRequest(http.MethodPost, "/api/roll", nil)
				if tc.claims != nil {
					req = req.WithContext(WithClaims(req.Context(), tc.claims))
				}
				rr := httptest.NewRecorder()
				h(rr, req)

				if rr.Code != mode.want {
					t.Errorf("status: got %d, want %d", rr.Code, mode.want)
				}
				if called != (mode.want == http.StatusOK) {
					t.Errorf("handler called: %t with status %d", called, rr.Code)
				}
			})
		}
	}
}
