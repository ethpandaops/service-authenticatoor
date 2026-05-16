package anyauth

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

func newTestProvider(t *testing.T) *Provider {
	t.Helper()
	log := logrus.New()
	log.SetOutput(io.Discard)
	p := New(log, Config{})
	if err := p.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	return p
}

func TestAuthenticate_AcceptsValidCookie(t *testing.T) {
	p := newTestProvider(t)

	cases := []struct {
		name string
		user string
	}{
		{"plain", "alice"},
		{"email-shaped", "alice@localhost"},
		{"with-symbols", "user_42-foo.bar"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
			r.AddCookie(&http.Cookie{Name: DefaultCookieName, Value: tc.user})
			out, err := p.Authenticate(context.Background(), r)
			if err != nil {
				t.Fatalf("auth: %v", err)
			}
			if out.Identity == nil {
				t.Fatalf("expected identity, got status %d redirect %q", out.Status, out.RedirectTo)
			}
			if out.Identity.Subject != tc.user || out.Identity.Email != tc.user {
				t.Errorf("identity: got sub=%q email=%q want both %q", out.Identity.Subject, out.Identity.Email, tc.user)
			}
		})
	}
}

func TestAuthenticate_RedirectsToFormWithoutCookie(t *testing.T) {
	p := newTestProvider(t)

	r := httptest.NewRequest(http.MethodGet, "/auth/login?return_to=https%3A%2F%2Fapp.localhost%2F", nil)
	out, err := p.Authenticate(context.Background(), r)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	if out.Identity != nil {
		t.Fatalf("expected no identity")
	}
	if !strings.HasPrefix(out.RedirectTo, DefaultLoginPath+"?") {
		t.Errorf("redirect: got %q want prefix %q?", out.RedirectTo, DefaultLoginPath)
	}
	u, err := url.Parse(out.RedirectTo)
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	got := u.Query().Get("return_to")
	want := "/auth/login?return_to=https%3A%2F%2Fapp.localhost%2F"
	if got != want {
		t.Errorf("return_to: got %q want %q", got, want)
	}
}

func TestAuthenticate_IgnoresInvalidCookieValues(t *testing.T) {
	p := newTestProvider(t)

	// Note: control bytes / quotes / semicolons are stripped by net/http's
	// cookie parser before they ever reach the provider — those cases are
	// covered by TestSanitizeUsername. Here we only exercise values that
	// survive the parser but still fail sanitization.
	cases := []struct {
		name  string
		value string
	}{
		{"empty", ""},
		{"whitespace", "   "},
		{"too-long", strings.Repeat("a", maxUsernameLen+1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
			r.AddCookie(&http.Cookie{Name: DefaultCookieName, Value: tc.value})
			out, err := p.Authenticate(context.Background(), r)
			if err != nil {
				t.Fatalf("auth: %v", err)
			}
			if out.Identity != nil {
				t.Fatalf("expected redirect, got identity %+v", out.Identity)
			}
			if out.RedirectTo == "" {
				t.Errorf("expected redirect")
			}
		})
	}
}

func TestHandleLoginForm_RendersWithReturnTo(t *testing.T) {
	p := newTestProvider(t)

	r := httptest.NewRequest(http.MethodGet, DefaultLoginPath+"?return_to=%2Fauth%2Flogin", nil)
	rr := httptest.NewRecorder()
	p.handleLoginForm(rr, r)

	if rr.Code != http.StatusOK {
		t.Fatalf("status: %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, `name="user"`) {
		t.Errorf("body missing username input: %s", body)
	}
	if !strings.Contains(body, `value="/auth/login"`) {
		t.Errorf("body missing return_to hidden input: %s", body)
	}
	if got := rr.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("cache-control: %q", got)
	}
}

func TestHandleLoginForm_FallsBackOnUnsafeReturnTo(t *testing.T) {
	p := newTestProvider(t)

	r := httptest.NewRequest(http.MethodGet, DefaultLoginPath+"?return_to=https%3A%2F%2Fevil.example", nil)
	rr := httptest.NewRecorder()
	p.handleLoginForm(rr, r)

	if rr.Code != http.StatusOK {
		t.Fatalf("status: %d", rr.Code)
	}
	body := rr.Body.String()
	// Unsafe return_to is replaced with "/" — there should be no copy of
	// the attacker's URL anywhere in the rendered form.
	if strings.Contains(body, "evil.example") {
		t.Errorf("body echoed unsafe return_to: %s", body)
	}
	if !strings.Contains(body, `value="/"`) {
		t.Errorf("expected fallback return_to=/: %s", body)
	}
}

func TestHandleLoginSubmit_SetsCookieAndRedirects(t *testing.T) {
	p := newTestProvider(t)

	form := url.Values{
		"user":      {"alice"},
		"return_to": {"/auth/login?return_to=https%3A%2F%2Fapp.localhost%2F"},
	}
	r := httptest.NewRequest(http.MethodPost, DefaultLoginPath, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	p.handleLoginSubmit(rr, r)

	if rr.Code != http.StatusFound {
		t.Fatalf("status: got %d want 302; body=%s", rr.Code, rr.Body.String())
	}
	loc := rr.Header().Get("Location")
	if loc != "/auth/login?return_to=https%3A%2F%2Fapp.localhost%2F" {
		t.Errorf("location: got %q", loc)
	}
	cookies := rr.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != DefaultCookieName || cookies[0].Value != "alice" {
		t.Errorf("cookie: got %+v", cookies)
	}
	// SameSite=None + Secure is required so the iframe-based logout can
	// later overwrite this cookie from a cross-site context.
	if !cookies[0].HttpOnly || !cookies[0].Secure || cookies[0].SameSite != http.SameSiteNoneMode {
		t.Errorf("cookie attributes: got %+v", cookies[0])
	}
}

func TestHandleLoginSubmit_RejectsBadUsername(t *testing.T) {
	p := newTestProvider(t)

	cases := []struct {
		name string
		user string
	}{
		{"empty", ""},
		{"whitespace", "   "},
		{"with-semicolon", "ali;ce"},
		{"with-quote", `ali"ce`},
		{"too-long", strings.Repeat("a", maxUsernameLen+1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			form := url.Values{"user": {tc.user}, "return_to": {"/"}}
			r := httptest.NewRequest(http.MethodPost, DefaultLoginPath, strings.NewReader(form.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rr := httptest.NewRecorder()
			p.handleLoginSubmit(rr, r)

			if rr.Code != http.StatusBadRequest {
				t.Errorf("status: got %d want 400", rr.Code)
			}
			if len(rr.Result().Cookies()) != 0 {
				t.Errorf("expected no cookie set, got %+v", rr.Result().Cookies())
			}
		})
	}
}

func TestHandleLoginSubmit_FallsBackOnUnsafeReturnTo(t *testing.T) {
	p := newTestProvider(t)

	form := url.Values{"user": {"alice"}, "return_to": {"//evil.example/"}}
	r := httptest.NewRequest(http.MethodPost, DefaultLoginPath, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	p.handleLoginSubmit(rr, r)

	if rr.Code != http.StatusFound {
		t.Fatalf("status: %d", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "/" {
		t.Errorf("location: got %q want /", loc)
	}
}

func TestLogout_ClearsCookie(t *testing.T) {
	p := newTestProvider(t)

	r := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	r.AddCookie(&http.Cookie{Name: DefaultCookieName, Value: "alice"})
	rr := httptest.NewRecorder()
	p.Logout(rr, r)

	if rr.Code != http.StatusOK {
		t.Errorf("status: %d", rr.Code)
	}
	cookies := rr.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != DefaultCookieName {
		t.Fatalf("expected one cookie clearing %s, got %+v", DefaultCookieName, cookies)
	}
	if cookies[0].MaxAge >= 0 {
		t.Errorf("expected MaxAge<0 (delete), got %d", cookies[0].MaxAge)
	}
}

func TestRegisterRoutes_BindsBothMethods(t *testing.T) {
	p := newTestProvider(t)

	r := mux.NewRouter()
	p.RegisterRoutes(r)

	for _, m := range []string{http.MethodGet, http.MethodPost} {
		req := httptest.NewRequest(m, DefaultLoginPath, strings.NewReader(""))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		var match mux.RouteMatch
		if !r.Match(req, &match) {
			t.Errorf("no route matched %s %s", m, DefaultLoginPath)
		}
	}
}

func TestSanitizeUsername(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"alice", "alice"},
		{"  alice  ", "alice"},
		{"alice@example.com", "alice@example.com"},
		{"", ""},
		{"   ", ""},
		{"with\nnewline", ""},
		{"semi;colon", ""},
		{`back\slash`, ""},
		{`quo"te`, ""},
		{strings.Repeat("a", maxUsernameLen), strings.Repeat("a", maxUsernameLen)},
		{strings.Repeat("a", maxUsernameLen+1), ""},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := sanitizeUsername(tc.in); got != tc.want {
				t.Errorf("sanitize(%q): got %q want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestIsSafeReturnTo(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"", false},
		{"/", true},
		{"/auth/login", true},
		{"/auth/login?x=1", true},
		{"//evil.example/", false},
		{`/\evil.example/`, false},
		{"https://evil.example/", false},
		{"javascript:alert(1)", false},
		{"./relative", false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := isSafeReturnTo(tc.in); got != tc.want {
				t.Errorf("isSafeReturnTo(%q): got %v want %v", tc.in, got, tc.want)
			}
		})
	}
}
