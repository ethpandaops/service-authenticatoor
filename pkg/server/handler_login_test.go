package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/ethpandaops/service-authenticatoor/pkg/protection/oidc"
	"github.com/ethpandaops/service-authenticatoor/pkg/protection/oidc/oidctest"
)

// TestNotGranted_LoginDoesNotLoop walks a browser from an app through
// the login of a user no group names, following every redirect. The
// walk ends on the 403 page — it is never sent back to the app or to a
// login again — and the page's logout really ends the session, so the
// next attempt starts a fresh login (where another account can be
// used).
func TestNotGranted_LoginDoesNotLoop(t *testing.T) {
	idp := oidctest.New(t, oidctest.User{Subject: "u1", Email: "mallory@example.org"})
	h := newSectionHarness(t, notGrantedSection("oidc"), "", newOIDCProvider(idp, "oidc", oidc.Config{}))

	jar := map[string]*http.Cookie{}
	get := func(target string) *httptest.ResponseRecorder {
		cookies := make([]*http.Cookie, 0, len(jar))
		for _, c := range jar {
			cookies = append(cookies, c)
		}
		rr := h.do(httptest.NewRequest(http.MethodGet, target, nil), cookies...)
		for _, c := range rr.Result().Cookies() {
			if c.MaxAge < 0 || c.Value == "" {
				delete(jar, c.Name)
				continue
			}
			jar[c.Name] = c
		}
		return rr
	}
	// walk follows redirects from target and returns the path of every
	// request made and the final response.
	walk := func(target string) ([]string, *httptest.ResponseRecorder) {
		var visited []string
		for range 10 {
			path, _, _ := strings.Cut(target, "?")
			visited = append(visited, path)
			rr := get(target)
			if rr.Code != http.StatusFound {
				return visited, rr
			}
			target = rr.Header().Get("Location")
			if strings.HasPrefix(target, idp.URL) {
				// The IdP logs the user in and sends them back.
				visited = append(visited, "(idp)")
				target = "/oidc/callback?" + idp.Authorize(t, target).Encode()
			}
			if !strings.HasPrefix(target, "/") {
				t.Fatalf("after %v the browser was sent off the service, to %q", visited, target)
			}
		}
		t.Fatalf("the browser is still being redirected after %v", visited)
		return nil, nil
	}

	start := "/auth/login?return_to=" + url.QueryEscape(appURL)
	visited, rr := walk(start)
	want := []string{"/auth/login", "/oidc/login", "(idp)", "/oidc/callback", "/auth/login"}
	if !slices.Equal(visited, want) {
		t.Fatalf("the walk was %v, want %v", visited, want)
	}
	if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "<b>mallory@example.org</b>") {
		t.Fatalf("the walk ended with %d: %s", rr.Code, rr.Body.String())
	}

	// Reloading the page stays on it: the session is kept, and no
	// further login is started.
	visited, rr = walk(start)
	if !slices.Equal(visited, []string{"/auth/login"}) || rr.Code != http.StatusForbidden {
		t.Fatalf("a reload went %v and ended with %d", visited, rr.Code)
	}
	if len(jar) != 1 {
		t.Fatalf("cookies after the refusal: %v", jar)
	}

	// The page's one link.
	if rr := get("/auth/logout"); rr.Code != http.StatusOK || len(jar) != 0 {
		t.Fatalf("logout: status %d, cookies left %v", rr.Code, jar)
	}
	// Logged out, the same URL starts a login instead of the page.
	if rr := get(start); rr.Code != http.StatusFound || !strings.HasPrefix(rr.Header().Get("Location"), "/oidc/login?") {
		t.Errorf("after the logout: %d → %q", rr.Code, rr.Header().Get("Location"))
	}
}
