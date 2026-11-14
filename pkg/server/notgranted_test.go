package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"

	"github.com/ethpandaops/service-authenticatoor/pkg/issuer"
	"github.com/ethpandaops/service-authenticatoor/pkg/protection/cloudflare"
	"github.com/ethpandaops/service-authenticatoor/pkg/protection/oidc"
	"github.com/ethpandaops/service-authenticatoor/pkg/protection/oidc/oidctest"
)

// noToken stands in tables for the services claim of an identity that
// no grants group names: there is no claim, because no token is issued.
const noToken = "(no token)"

// minted is what a token endpoint gave a user: the identity and the
// services claim of the token, or — with Services == noToken — the
// identity as /auth/userinfo reports it.
type minted struct {
	Subject  string
	Email    string
	Teams    []string
	Services string
}

// userinfo is the answer of /auth/userinfo as these tests read it.
type userinfo struct {
	Email   string   `json:"email"`
	Sub     string   `json:"sub"`
	Teams   []string `json:"teams"`
	Granted *bool    `json:"granted"`
}

// assertNotGranted checks the answer of a token endpoint (/auth/token,
// /<name>/token) to a user who is logged in but named by no group: 403
// in the form of the endpoint's other errors, and nothing that sends a
// client to a login.
func assertNotGranted(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403 (location %q, body %s)", rr.Code, rr.Header().Get("Location"), rr.Body.String())
	}
	if got := rr.Header().Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Errorf("Content-Type %q", got)
	}
	if got := strings.TrimSpace(rr.Body.String()); got != notGrantedMessage {
		t.Errorf("body %q", got)
	}
	if loc := rr.Header().Get("Location"); loc != "" {
		t.Errorf("redirected to %q", loc)
	}
	if got := rr.Header().Get("WWW-Authenticate"); got != "" {
		t.Errorf("challenge %q", got)
	}
	if got := rr.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control %q", got)
	}
	// The session stays: nothing is cleared.
	if cookies := rr.Result().Cookies(); len(cookies) != 0 {
		t.Errorf("cookies: %v", cookies)
	}
}

// userinfo calls /auth/userinfo with the credentials of req.
func (h *teamsHarness) userinfo(req *http.Request, cookies ...*http.Cookie) userinfo {
	h.t.Helper()
	probe := httptest.NewRequest(http.MethodGet, "/auth/userinfo", nil)
	probe.Header = req.Header.Clone()
	rr := h.do(probe, cookies...)
	if rr.Code != http.StatusOK {
		h.t.Fatalf("/auth/userinfo: status %d, body %s", rr.Code, rr.Body.String())
	}
	var info userinfo
	if err := json.Unmarshal(rr.Body.Bytes(), &info); err != nil {
		h.t.Fatalf("decode userinfo: %v", err)
	}
	if info.Granted == nil {
		h.t.Fatalf("userinfo has no granted field: %s", rr.Body.String())
	}
	return info
}

// mint calls /auth/token with req. It returns the claims of the token,
// or, when the answer is the refusal for want of a grant, the identity
// from /auth/userinfo with Services == noToken. Either way it checks
// that userinfo's "granted" agrees.
func (h *teamsHarness) mint(req *http.Request, cookies ...*http.Cookie) minted {
	h.t.Helper()
	info := h.userinfo(req, cookies...)
	if len(info.Teams) == 0 {
		info.Teams = nil
	}

	rr := h.do(req, cookies...)
	if rr.Code == http.StatusForbidden {
		assertNotGranted(h.t, rr)
		if *info.Granted {
			h.t.Errorf("no token, but userinfo says granted: true")
		}
		return minted{Subject: info.Sub, Email: info.Email, Teams: info.Teams, Services: noToken}
	}
	if rr.Code != http.StatusOK {
		h.t.Fatalf("/auth/token: status %d, location %q, body %s", rr.Code, rr.Header().Get("Location"), rr.Body.String())
	}
	var resp tokenResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		h.t.Fatalf("decode token response: %v", err)
	}
	claims := h.verify(resp.Token)
	if !*info.Granted {
		h.t.Errorf("a token, but userinfo says granted: false")
	}
	if info.Sub != claims.Subject || info.Email != claims.Email || !slices.Equal(info.Teams, claims.Teams) {
		h.t.Errorf("userinfo %+v and the token (sub %q email %q teams %v) disagree",
			info, claims.Subject, claims.Email, claims.Teams)
	}
	return minted{Subject: claims.Subject, Email: claims.Email, Teams: claims.Teams, Services: claims.Services}
}

// refusals returns the "no token issued" log lines since the last call.
func (h *teamsHarness) refusals() []*logrus.Entry {
	var out []*logrus.Entry
	for _, e := range h.logs.AllEntries() {
		if strings.HasPrefix(e.Message, "no token issued") {
			out = append(out, e)
		}
	}
	h.logs.Reset()
	return out
}

const (
	appURL    = "https://app.test.example/page?x=1"
	appOrigin = "https://app.test.example"
)

func loginRequest() *http.Request {
	return httptest.NewRequest(http.MethodGet, "/auth/login?return_to="+url.QueryEscape(appURL), nil)
}

func embedRequest() *http.Request {
	return httptest.NewRequest(http.MethodGet, "/auth/embed?target_origin="+url.QueryEscape(appOrigin), nil)
}

// notGrantedSection names the team "panda" at the given providers, and
// nobody else.
func notGrantedSection(providers ...string) *issuer.GrantsConfig {
	members := make([]string, 0, len(providers))
	for _, name := range providers {
		members = append(members, name+"/team:panda")
	}
	return &issuer.GrantsConfig{Groups: []issuer.GrantGroup{{
		Name: "staff", Members: members, Services: []string{"dora"},
	}}}
}

// TestNotGranted_EveryMintSite: with a grants section, a user who is
// logged in but named by no group gets no token from any endpoint that
// mints one, through any kind of provider — and the answer never sends
// them to a login. A user the section names gets a token from each of
// the same requests.
func TestNotGranted_EveryMintSite(t *testing.T) {
	type door struct {
		name     string
		provider string
		subject  string
		// credentials returns what authenticates a request at this
		// door: headers to set, and cookies to send.
		credentials func(t *testing.T, h *teamsHarness) (func(*http.Request), []*http.Cookie)
		providers   func(t *testing.T, teams ...string) []NamedProvider
	}
	idp := oidctest.New(t, oidctest.User{Subject: "u1", Email: "mallory@example.org", Groups: []string{"team:reth"}})
	oidcDoor := func(_ *testing.T, teams ...string) []NamedProvider {
		return []NamedProvider{newOIDCProvider(idp, "oidc", oidc.Config{Teams: teams, Bearer: bearerOn()})}
	}
	doors := []door{
		{
			"oidc browser session", "oidc", "mallory@example.org",
			func(_ *testing.T, h *teamsHarness) (func(*http.Request), []*http.Cookie) {
				return func(*http.Request) {}, []*http.Cookie{h.oidcLogin(idp, "oidc")}
			},
			oidcDoor,
		},
		{
			"cloudflare ambient header", "cfaccess", "mallory@example.org",
			func(*testing.T, *teamsHarness) (func(*http.Request), []*http.Cookie) {
				return func(r *http.Request) { r.Header.Set(cloudflare.DefaultUserHeader, "mallory@example.org") }, nil
			},
			func(_ *testing.T, teams ...string) []NamedProvider {
				return []NamedProvider{newCloudflareProvider("cfaccess", teams...)}
			},
		},
		{
			"basic credentials", "htpasswd", "alice",
			func(*testing.T, *teamsHarness) (func(*http.Request), []*http.Cookie) {
				return func(r *http.Request) { r.SetBasicAuth("alice", "hunter2") }, nil
			},
			func(t *testing.T, teams ...string) []NamedProvider {
				return []NamedProvider{newBasicProvider(t, "htpasswd", teams...)}
			},
		},
		{
			"basic session cookie", "htpasswd", "alice",
			func(t *testing.T, h *teamsHarness) (func(*http.Request), []*http.Cookie) {
				login := httptest.NewRequest(http.MethodGet, "/htpasswd/login?return_to=%2Fauth%2Ftoken", nil)
				login.SetBasicAuth("alice", "hunter2")
				cookies := liveCookies(h.do(login))
				if len(cookies) != 1 {
					t.Fatalf("login cookies: %v", cookies)
				}
				return func(*http.Request) {}, cookies
			},
			func(t *testing.T, teams ...string) []NamedProvider {
				return []NamedProvider{newBasicProvider(t, "htpasswd", teams...)}
			},
		},
	}

	for _, d := range doors {
		t.Run(d.name, func(t *testing.T) {
			h := newSectionHarness(t, notGrantedSection(d.provider), "", d.providers(t)...)
			authenticate, cookies := d.credentials(t, h)
			do := func(req *http.Request) *httptest.ResponseRecorder {
				authenticate(req)
				return h.do(req, cookies...)
			}
			h.refusals()

			t.Run("/auth/token", func(t *testing.T) {
				assertNotGranted(t, do(tokenRequest()))
				// As the v2 client frame asks: a background fetch.
				req := tokenRequest()
				req.Header.Set("Sec-Fetch-Dest", "empty")
				assertNotGranted(t, do(req))
			})

			t.Run("/auth/login", func(t *testing.T) {
				rr := do(loginRequest())
				if rr.Code != http.StatusForbidden || rr.Header().Get("Location") != "" {
					t.Fatalf("status %d, location %q", rr.Code, rr.Header().Get("Location"))
				}
				if got := rr.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
					t.Errorf("Content-Type %q", got)
				}
				if got := rr.Header().Get("Cache-Control"); got != "no-store" {
					t.Errorf("Cache-Control %q", got)
				}
				page := rr.Body.String()
				for _, want := range []string{
					"<b>" + d.subject + "</b>", "<b>" + d.provider + "</b>",
					"not permitted to use the services of this devnet", `href="/auth/logout"`,
				} {
					if !strings.Contains(page, want) {
						t.Errorf("the page lacks %q:\n%s", want, page)
					}
				}
				// Nothing on the page leads back into the round: its
				// one link is the logout, and it runs no script.
				if strings.Count(page, "href=") != 1 || strings.Contains(page, "<script") ||
					strings.Contains(page, "http-equiv") || strings.Contains(page, "app.test.example") {
					t.Errorf("the page links somewhere else, or acts on its own:\n%s", page)
				}
				if strings.Contains(page, "auth_token") || strings.Contains(page, "eyJ") {
					t.Errorf("the page carries a token:\n%s", page)
				}
				if cookies := rr.Result().Cookies(); len(cookies) != 0 {
					t.Errorf("cookies: %v", cookies)
				}
			})

			t.Run("/auth/embed", func(t *testing.T) {
				rr := do(embedRequest())
				assertNotGranted(t, rr)
				if body := rr.Body.String(); strings.Contains(body, "postMessage") || strings.Contains(body, "eyJ") {
					t.Errorf("the embed answer posts something: %s", body)
				}
			})

			t.Run("/auth/userinfo", func(t *testing.T) {
				req := httptest.NewRequest(http.MethodGet, "/auth/userinfo", nil)
				authenticate(req)
				info := h.userinfo(req, cookies...)
				if info.Sub != d.subject || *info.Granted {
					t.Errorf("userinfo: %+v granted=%t, want %q and granted false", info, *info.Granted, d.subject)
				}
			})

			t.Run("one Info line per refusal", func(t *testing.T) {
				// /auth/token twice, /auth/login, /auth/embed; userinfo
				// mints nothing and logs nothing.
				lines := h.refusals()
				if len(lines) != 4 {
					t.Fatalf("%d lines, want 4", len(lines))
				}
				endpoints := make([]string, 0, len(lines))
				for _, e := range lines {
					if e.Level != logrus.InfoLevel || e.Data["sub"] != d.subject || e.Data["provider"] != d.provider {
						t.Errorf("line %q: level %s, fields %v", e.Message, e.Level, e.Data)
					}
					endpoints = append(endpoints, e.Data["endpoint"].(string))
				}
				if !slices.Equal(endpoints, []string{"token", "token", "login", "embed"}) {
					t.Errorf("endpoints: %v", endpoints)
				}
			})

			// The control: the same requests of a user the section
			// names. Without it everything above would also pass on a
			// server that refuses everybody.
			t.Run("a named user gets a token from each", func(t *testing.T) {
				named := newSectionHarness(t, notGrantedSection(d.provider), "", d.providers(t, "panda")...)
				authenticate, cookies := d.credentials(t, named)
				do := func(req *http.Request) *httptest.ResponseRecorder {
					authenticate(req)
					return named.do(req, cookies...)
				}
				req := tokenRequest()
				authenticate(req)
				if got := named.mint(req, cookies...); got.Services != "-all,+dora" || got.Subject != d.subject {
					t.Errorf("/auth/token: %+v", got)
				}
				rr := do(loginRequest())
				if rr.Code != http.StatusFound || !strings.HasPrefix(rr.Header().Get("Location"), appURL+"#auth_token=") {
					t.Errorf("/auth/login: %d → %q", rr.Code, rr.Header().Get("Location"))
				}
				rr = do(embedRequest())
				if rr.Code != http.StatusOK || named.verify(embeddedToken(t, rr.Body.String())).Services != "-all,+dora" {
					t.Errorf("/auth/embed: %d", rr.Code)
				}
				if lines := named.refusals(); len(lines) != 0 {
					t.Errorf("refusals logged for a named user: %d", len(lines))
				}
			})
		})
	}
}

// TestNotGranted_TokenAliases: the machine aliases (/<name>/token)
// answer a caller no group names like /auth/token does — for the
// Cloudflare alias and for the oidc bearer alias.
func TestNotGranted_TokenAliases(t *testing.T) {
	idp := oidctest.New(t, oidctest.User{Subject: "u1", Email: "mallory@example.org", Groups: []string{"team:reth"}})
	section := &issuer.GrantsConfig{Groups: []issuer.GrantGroup{{
		Members:  []string{"oidc/team:panda", "cfaccess/user:staff@ethpandaops.io"},
		Services: []string{"dora"},
	}}}
	h := newSectionHarness(t, section, "",
		newCloudflareProvider("cfaccess"),
		newOIDCProvider(idp, "oidc", oidc.Config{TeamRules: teamRules(prefixRule), Bearer: bearerOn()}),
	)
	cf := func(email string) *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/cfaccess/token", nil)
		req.Header.Set(cloudflare.DefaultUserHeader, email)
		return req
	}
	h.refusals()

	assertNotGranted(t, h.do(cf("mallory@example.org")))
	assertNotGranted(t, h.do(bearerGet("/oidc/token", idp.Token(t, cliAudience))))

	lines := h.refusals()
	if len(lines) != 2 {
		t.Fatalf("%d refusal lines, want 2", len(lines))
	}
	for i, provider := range []string{"cfaccess", "oidc"} {
		if e := lines[i]; e.Level != logrus.InfoLevel || e.Data["sub"] != "mallory@example.org" || e.Data["provider"] != provider {
			t.Errorf("line %d: level %s, fields %v", i, e.Level, e.Data)
		}
	}

	// Named callers at the same aliases.
	if rr := h.do(cf("staff@ethpandaops.io")); rr.Code != http.StatusOK {
		t.Errorf("/cfaccess/token for a named user: %d", rr.Code)
	}
	idp.SetUser(oidctest.User{Subject: "u2", Email: "dev@example.org", Groups: []string{"team:panda"}})
	if rr := h.do(bearerGet("/oidc/token", idp.Token(t, cliAudience))); rr.Code != http.StatusOK {
		t.Errorf("/oidc/token for a named user: %d", rr.Code)
	}
}

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

// TestNotGranted_GrantAddedLater: the refusal ends no session. The
// grants are read when a token is minted, so the session cookie of a
// user who was refused yields a token as soon as the config names them
// — no new login. (An attribute member is the exception: what a session
// matches is captured at login; see
// TestGrants_AttributeMembers_Sessions.)
func TestNotGranted_GrantAddedLater(t *testing.T) {
	idp := oidctest.New(t, oidctest.User{Subject: "u1", Email: "dev@example.org", Groups: []string{"team:reth"}})
	build := func(groups ...issuer.GrantGroup) *teamsHarness {
		return newSectionHarness(t, &issuer.GrantsConfig{Groups: groups}, "",
			newOIDCProvider(idp, "oidc", oidc.Config{TeamRules: teamRules(prefixRule)}))
	}
	staff := issuer.GrantGroup{Members: []string{"oidc/team:panda"}, Services: []string{"all"}}

	before := build(staff)
	session := before.oidcLogin(idp, "oidc")
	refused := before.mint(tokenRequest(), session)
	if refused.Services != noToken || !slices.Equal(refused.Teams, []string{"reth"}) {
		t.Fatalf("before: %+v", refused)
	}
	// Still logged in after the refusals: the same cookie identifies
	// the user, again and again.
	for range 3 {
		if got := before.mint(tokenRequest(), session); got.Services != noToken || got.Subject != refused.Subject {
			t.Fatalf("a later request with the same session: %+v", got)
		}
	}

	tests := []struct {
		name  string
		added issuer.GrantGroup
		want  string
	}{
		{"by team", issuer.GrantGroup{Members: []string{"oidc/team:reth"}, Services: []string{"dora"}}, "-all,+dora"},
		{"by user", issuer.GrantGroup{Members: []string{"oidc/user:dev@example.org"}, Services: []string{"spamoor"}}, "-all,+spamoor"},
		{"into a group without services", issuer.GrantGroup{Members: []string{"oidc/team:reth"}, Services: []string{}}, "-all"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			after := build(staff, tc.added)
			got := after.mint(tokenRequest(), session)
			if got.Services != tc.want || got.Subject != "dev@example.org" {
				t.Errorf("the same session after the group was added: %+v, want services %q", got, tc.want)
			}
			rr := after.do(loginRequest(), session)
			if rr.Code != http.StatusFound || !strings.HasPrefix(rr.Header().Get("Location"), appURL+"#auth_token=") {
				t.Errorf("/auth/login: %d → %q", rr.Code, rr.Header().Get("Location"))
			}
		})
	}
}

// TestUserinfo_Granted: /auth/userinfo answers every logged-in user and
// says whether a token would be minted: always without a grants
// section, for members only with one, for nobody with an empty one.
func TestUserinfo_Granted(t *testing.T) {
	tests := []struct {
		name    string
		section *issuer.GrantsConfig
		teams   []string
		want    bool
	}{
		{"no grants section", nil, nil, true},
		{"named by a group", notGrantedSection("cfaccess"), []string{"panda"}, true},
		{
			"named by a group without services",
			&issuer.GrantsConfig{Groups: []issuer.GrantGroup{{Members: []string{"cfaccess/team:panda"}, Services: []string{}}}},
			[]string{"panda"}, true,
		},
		{"named by no group", notGrantedSection("cfaccess"), []string{"reth"}, false},
		{"empty grants section", &issuer.GrantsConfig{Groups: []issuer.GrantGroup{}}, []string{"panda"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newSectionHarness(t, tc.section, "", newCloudflareProvider("cfaccess", tc.teams...))
			req := httptest.NewRequest(http.MethodGet, "/auth/userinfo", nil)
			req.Header.Set(cloudflare.DefaultUserHeader, "someone@example.org")
			rr := h.do(req)
			if rr.Code != http.StatusOK {
				t.Fatalf("status %d", rr.Code)
			}
			var raw map[string]any
			if err := json.Unmarshal(rr.Body.Bytes(), &raw); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if granted, ok := raw["granted"].(bool); !ok || granted != tc.want {
				t.Errorf("granted: %v, want %t (%s)", raw["granted"], tc.want, rr.Body.String())
			}
			if raw["sub"] != "someone@example.org" {
				t.Errorf("sub: %v", raw["sub"])
			}
			// And /auth/token agrees.
			token := tokenRequest()
			token.Header.Set(cloudflare.DefaultUserHeader, "someone@example.org")
			if got := h.do(token).Code; (got == http.StatusOK) != tc.want || (got != http.StatusOK && got != http.StatusForbidden) {
				t.Errorf("/auth/token: status %d", got)
			}
			if len(h.refusals()) != btoi(!tc.want) {
				t.Errorf("refusal lines: userinfo must log none, /auth/token one per refusal")
			}
		})
	}
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

// TestClientFrame_ReadsNotGrantedAsUnauthenticated pins the signal the
// v2 client relies on: its frame script treats a 403 from /auth/token
// as a settled "unauthenticated" — it does not go into its retry
// ladder, and it never follows a redirect. The server's answer to a
// user without a grant is exactly that status.
func TestClientFrame_ReadsNotGrantedAsUnauthenticated(t *testing.T) {
	src, err := authenticatoorFS.ReadFile("static/authenticatoor-frame-v2.js")
	if err != nil {
		t.Fatalf("read frame script: %v", err)
	}
	for _, want := range []string{
		"res.status === 403",
		"redirect: 'manual'",
		"if (outcome === 'ok' || outcome === 'unauthenticated') return undefined;",
	} {
		if !strings.Contains(string(src), want) {
			t.Errorf("the frame script no longer has %q", want)
		}
	}
}
