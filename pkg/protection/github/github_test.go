package github

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"

	"github.com/ethpandaops/service-authenticatoor/pkg/protection"
	"github.com/ethpandaops/service-authenticatoor/pkg/session"
)

// stubGitHub stands in for github.com + api.github.com. Tests configure the
// fixed responses and inspect what was sent.
type stubGitHub struct {
	server            *httptest.Server
	gotCode           string
	tokenResp         tokenResponse
	user              githubUser
	emails            []githubEmail
	orgs              []githubOrg
	publicOrgs        []githubOrg
	tokenStatus       int
	userStatus        int
	emailsStatus      int
	orgsStatus        int
	publicOrgsStatus  int
	publicOrgsForUser string // login captured from the most recent /users/{login}/orgs call
	authzReceived     url.Values
}

func newStubGitHub(t *testing.T) *stubGitHub {
	t.Helper()
	s := &stubGitHub{
		tokenStatus:      200,
		userStatus:       200,
		emailsStatus:     200,
		orgsStatus:       200,
		publicOrgsStatus: 200,
		tokenResp:        tokenResponse{AccessToken: "stub-access", TokenType: "bearer"},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/login/oauth/authorize", func(w http.ResponseWriter, r *http.Request) {
		s.authzReceived = r.URL.Query()
		http.Redirect(w, r, s.authzReceived.Get("redirect_uri")+"?code=stub-code&state="+s.authzReceived.Get("state"), http.StatusFound)
	})
	mux.HandleFunc("/login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		s.gotCode = r.Form.Get("code")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(s.tokenStatus)
		_ = json.NewEncoder(w).Encode(s.tokenResp)
	})
	mux.HandleFunc("/user", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(s.userStatus)
		_ = json.NewEncoder(w).Encode(s.user)
	})
	mux.HandleFunc("/user/emails", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(s.emailsStatus)
		_ = json.NewEncoder(w).Encode(s.emails)
	})
	mux.HandleFunc("/user/orgs", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(s.orgsStatus)
		_ = json.NewEncoder(w).Encode(s.orgs)
	})
	// /users/{login}/orgs — Go 1.22+ ServeMux wildcard pattern.
	mux.HandleFunc("/users/{login}/orgs", func(w http.ResponseWriter, r *http.Request) {
		s.publicOrgsForUser = r.PathValue("login")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(s.publicOrgsStatus)
		_ = json.NewEncoder(w).Encode(s.publicOrgs)
	})
	s.server = httptest.NewServer(mux)
	t.Cleanup(s.server.Close)
	return s
}

func newTestProvider(t *testing.T, gh *stubGitHub, allowedOrgs ...string) *Provider {
	t.Helper()
	log := logrus.New()
	log.SetOutput(io.Discard)
	now := time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)
	p := New(log, Config{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		SessionKey:   []byte("0123456789abcdef0123456789abcdef"), // 32 bytes
		PublicURL:    "http://auth.localhost:18080",
		AllowedOrgs:  allowedOrgs,
		AuthorizeURL: gh.server.URL + "/login/oauth/authorize",
		TokenURL:     gh.server.URL + "/login/oauth/access_token",
		APIBaseURL:   gh.server.URL,
		Now:          func() time.Time { return now },
	})
	if err := p.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	return p
}

func TestGitHub_Authenticate_NoSession_RedirectsToLogin(t *testing.T) {
	gh := newStubGitHub(t)
	p := newTestProvider(t, gh, "ethpandaops")

	r := httptest.NewRequest(http.MethodGet, "/auth/token?aud=foo", nil)
	out, err := p.Authenticate(context.Background(), r)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	if !strings.HasPrefix(out.RedirectTo, DefaultLoginPath+"?") {
		t.Errorf("redirect: got %q, want %s?...", out.RedirectTo, DefaultLoginPath)
	}
	if !strings.Contains(out.RedirectTo, "return_to=%2Fauth%2Ftoken%3Faud%3Dfoo") {
		t.Errorf("redirect missing return_to: %q", out.RedirectTo)
	}
	if len(out.SetCookies) != 0 {
		t.Errorf("passive Authenticate must not set cookies, got %d", len(out.SetCookies))
	}
}

func TestGitHub_LoginStart_RedirectsToAuthorize(t *testing.T) {
	gh := newStubGitHub(t)
	p := newTestProvider(t, gh, "ethpandaops")

	r := httptest.NewRequest(http.MethodGet, DefaultLoginPath+"?return_to=%2Fauth%2Ftoken", nil)
	rr := httptest.NewRecorder()
	p.handleLoginStart(rr, r)

	if rr.Code != http.StatusFound {
		t.Fatalf("status: got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.HasPrefix(loc, gh.server.URL+"/login/oauth/authorize") {
		t.Errorf("redirect: %q", loc)
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if u.Query().Get("client_id") != "client-id" {
		t.Errorf("client_id: %q", u.Query().Get("client_id"))
	}
	if u.Query().Get("scope") != "read:org user:email" {
		t.Errorf("scope: %q", u.Query().Get("scope"))
	}
	if u.Query().Get("state") == "" {
		t.Error("state empty")
	}
	cookies := rr.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected one state cookie, got %d", len(cookies))
	}
	if cookies[0].Name != DefaultStateCookieName {
		t.Errorf("state cookie name: %q", cookies[0].Name)
	}
	if !cookies[0].HttpOnly {
		t.Error("state cookie should be HttpOnly")
	}
}

func TestGitHub_Authenticate_ValidSession_ReturnsIdentity(t *testing.T) {
	gh := newStubGitHub(t)
	p := newTestProvider(t, gh, "ethpandaops")

	cookie, err := p.signSessionCookie("octocat", "octo@example.com", nil, nil)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	r := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
	r.AddCookie(cookie)

	out, err := p.Authenticate(context.Background(), r)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	if out.Identity == nil {
		t.Fatalf("expected identity, got redirect %q", out.RedirectTo)
	}
	if out.Identity.Subject != "octocat" {
		t.Errorf("subject: %q", out.Identity.Subject)
	}
	if out.Identity.Email != "octo@example.com" {
		t.Errorf("email: %q", out.Identity.Email)
	}
}

func TestGitHub_Authenticate_TamperedSession_RedirectsAgain(t *testing.T) {
	gh := newStubGitHub(t)
	p := newTestProvider(t, gh, "ethpandaops")

	r := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
	r.AddCookie(&http.Cookie{Name: DefaultSessionCookieName, Value: "garbage"})

	out, err := p.Authenticate(context.Background(), r)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	if out.Identity != nil {
		t.Fatal("expected redirect for tampered session")
	}
	if out.RedirectTo == "" {
		t.Error("expected redirect-to")
	}
}

func TestGitHub_Callback_HappyPath(t *testing.T) {
	gh := newStubGitHub(t)
	gh.user = githubUser{Login: "octocat", Email: "octo@example.com"}
	gh.emails = []githubEmail{{Email: "octo@example.com", Primary: true, Verified: true}}
	gh.orgs = []githubOrg{{Login: "ethpandaops"}}

	p := newTestProvider(t, gh, "ethpandaops")

	// Build a state cookie that matches the URL state.
	state := "rand-state-value"
	stateTok, err := session.SignState(p.sessionSecret, state, "/auth/token?aud=foo", p.cfg.Now(), DefaultStateTTL)
	if err != nil {
		t.Fatalf("sign state: %v", err)
	}

	r := mux.NewRouter()
	p.RegisterRoutes(r)

	req := httptest.NewRequest(http.MethodGet, p.cfg.CallbackPath+"?code=stub-code&state="+state, nil)
	req.AddCookie(&http.Cookie{Name: DefaultStateCookieName, Value: stateTok})
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("status: %d, body: %s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Location"); got != "/auth/token?aud=foo" {
		t.Errorf("location: %q", got)
	}
	cookies := rr.Result().Cookies()
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == DefaultSessionCookieName {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("session cookie not set")
	}
	sess, err := session.Parse(p.sessionSecret, p.door, sessionCookie.Value, p.cfg.Now())
	if err != nil {
		t.Fatalf("parse session: %v", err)
	}
	if sess.Subject != "octocat" || sess.Email != "octo@example.com" {
		t.Errorf("session: login=%q email=%q", sess.Subject, sess.Email)
	}
}

func TestGitHub_Callback_RejectsStateMismatch(t *testing.T) {
	gh := newStubGitHub(t)
	gh.user = githubUser{Login: "octocat"}
	gh.orgs = []githubOrg{{Login: "ethpandaops"}}

	p := newTestProvider(t, gh, "ethpandaops")

	stateTok, _ := session.SignState(p.sessionSecret, "expected-state", "/", p.cfg.Now(), DefaultStateTTL)

	r := mux.NewRouter()
	p.RegisterRoutes(r)
	req := httptest.NewRequest(http.MethodGet, p.cfg.CallbackPath+"?code=c&state=different-state", nil)
	req.AddCookie(&http.Cookie{Name: DefaultStateCookieName, Value: stateTok})
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status: got %d, want 400", rr.Code)
	}
}

func TestGitHub_Callback_RejectsUserNotInAllowedOrg(t *testing.T) {
	gh := newStubGitHub(t)
	gh.user = githubUser{Login: "intruder"}
	gh.orgs = []githubOrg{{Login: "evilcorp"}}

	p := newTestProvider(t, gh, "ethpandaops")

	state := "rand-state-value"
	stateTok, _ := session.SignState(p.sessionSecret, state, "/auth/token", p.cfg.Now(), DefaultStateTTL)

	r := mux.NewRouter()
	p.RegisterRoutes(r)
	req := httptest.NewRequest(http.MethodGet, p.cfg.CallbackPath+"?code=stub-code&state="+state, nil)
	req.AddCookie(&http.Cookie{Name: DefaultStateCookieName, Value: stateTok})
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("status: got %d, want 403", rr.Code)
	}
}

// Public-org membership is enough to pass even when /user/orgs hides
// the org (e.g. the OAuth App hasn't been approved for an org that has
// third-party app restrictions enabled).
func TestGitHub_Callback_PublicOrgMembershipSatisfiesAllowList(t *testing.T) {
	gh := newStubGitHub(t)
	gh.user = githubUser{Login: "octocat", Email: "octo@example.com"}
	// /user/orgs returns nothing — simulating the OAuth-App-not-approved case.
	gh.orgs = []githubOrg{}
	// But the user has publicized the membership, so /users/octocat/orgs sees it.
	gh.publicOrgs = []githubOrg{{Login: "ethpandaops"}}

	p := newTestProvider(t, gh, "ethpandaops")

	state := "rand"
	stateTok, _ := session.SignState(p.sessionSecret, state, "/", p.cfg.Now(), DefaultStateTTL)

	r := mux.NewRouter()
	p.RegisterRoutes(r)
	req := httptest.NewRequest(http.MethodGet, p.cfg.CallbackPath+"?code=stub-code&state="+state, nil)
	req.AddCookie(&http.Cookie{Name: DefaultStateCookieName, Value: stateTok})
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("status: %d body: %s", rr.Code, rr.Body.String())
	}
	if gh.publicOrgsForUser != "octocat" {
		t.Errorf("public orgs queried for %q, want %q", gh.publicOrgsForUser, "octocat")
	}
}

// When the OAuth App's per-org grant is missing, /user/orgs returns at
// most other orgs, but /users/{login}/orgs is still authoritative for
// public membership. The merged view must dedupe so the same org isn't
// reported twice in diagnostic output.
func TestGitHub_Callback_MergesPrivateAndPublicOrgsDeduped(t *testing.T) {
	gh := newStubGitHub(t)
	gh.user = githubUser{Login: "octocat", Email: "octo@example.com"}
	// Both endpoints report ethpandaops — must not appear twice in the merged set.
	gh.orgs = []githubOrg{{Login: "ethpandaops"}, {Login: "secret-org"}}
	gh.publicOrgs = []githubOrg{{Login: "EthPandaOps"}, {Login: "public-org"}}

	p := newTestProvider(t, gh, "ethpandaops")
	profile, err := p.fetchProfile(context.Background(), "stub-access")
	if err != nil {
		t.Fatalf("fetchProfile: %v", err)
	}

	wantSet := map[string]bool{"ethpandaops": false, "secret-org": false, "public-org": false}
	for _, o := range profile.Orgs {
		key := strings.ToLower(o)
		if _, ok := wantSet[key]; !ok {
			t.Errorf("unexpected org in merged list: %q", o)
			continue
		}
		if wantSet[key] {
			t.Errorf("duplicate org in merged list: %q", o)
		}
		wantSet[key] = true
	}
	for k, seen := range wantSet {
		if !seen {
			t.Errorf("missing org in merged list: %q", k)
		}
	}
}

func TestGitHub_Callback_FallsBackToPrimaryEmail(t *testing.T) {
	gh := newStubGitHub(t)
	// /user returns no email (private setting).
	gh.user = githubUser{Login: "octocat", Email: ""}
	gh.orgs = []githubOrg{{Login: "ethpandaops"}}
	gh.emails = []githubEmail{
		{Email: "noisy@example.com", Primary: false, Verified: true},
		{Email: "primary@example.com", Primary: true, Verified: true},
	}

	p := newTestProvider(t, gh, "ethpandaops")

	state := "rand"
	stateTok, _ := session.SignState(p.sessionSecret, state, "/", p.cfg.Now(), DefaultStateTTL)

	r := mux.NewRouter()
	p.RegisterRoutes(r)
	req := httptest.NewRequest(http.MethodGet, p.cfg.CallbackPath+"?code=stub-code&state="+state, nil)
	req.AddCookie(&http.Cookie{Name: DefaultStateCookieName, Value: stateTok})
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("status: %d body: %s", rr.Code, rr.Body.String())
	}
	cookies := rr.Result().Cookies()
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == DefaultSessionCookieName {
			sessionCookie = c
		}
	}
	if sessionCookie == nil {
		t.Fatal("session cookie not set")
	}
	sess, err := session.Parse(p.sessionSecret, p.door, sessionCookie.Value, p.cfg.Now())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if sess.Email != "primary@example.com" {
		t.Errorf("email: %q want primary@example.com", sess.Email)
	}
}

func TestGitHub_Start_RejectsShortSessionKey(t *testing.T) {
	log := logrus.New()
	log.SetOutput(io.Discard)
	p := New(log, Config{
		ClientID:     "x",
		ClientSecret: "x",
		SessionKey:   []byte("tooshort"),
		PublicURL:    "http://x",
		AllowedOrgs:  []string{"x"},
	})
	if err := p.Start(context.Background()); err == nil {
		t.Error("expected error for short session key")
	}
}

func TestGitHub_Start_RejectsMissingAllowedOrgs(t *testing.T) {
	log := logrus.New()
	log.SetOutput(io.Discard)
	p := New(log, Config{
		ClientID:     "x",
		ClientSecret: "x",
		SessionKey:   []byte("0123456789abcdef0123456789abcdef"),
		PublicURL:    "http://x",
	})
	if err := p.Start(context.Background()); err == nil {
		t.Error("expected error for missing AllowedOrgs")
	}
}

// runCallback drives the OAuth callback against the stub and returns the
// recorder plus the session cookie it set (nil when none).
func runCallback(t *testing.T, p *Provider) (*httptest.ResponseRecorder, *http.Cookie) {
	t.Helper()
	state := "rand-state-value"
	stateTok, err := session.SignState(p.sessionSecret, state, "/auth/token", p.cfg.Now(), DefaultStateTTL)
	if err != nil {
		t.Fatalf("sign state: %v", err)
	}
	r := mux.NewRouter()
	p.RegisterRoutes(r)
	req := httptest.NewRequest(http.MethodGet, p.cfg.CallbackPath+"?code=stub-code&state="+state, nil)
	req.AddCookie(&http.Cookie{Name: DefaultStateCookieName, Value: stateTok})
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	for _, c := range rr.Result().Cookies() {
		if c.Name == DefaultSessionCookieName {
			return rr, c
		}
	}
	return rr, nil
}

// newTeamsProvider builds a started provider whose only team rule maps
// the "orgs" attribute through orgTeams.
func newTeamsProvider(t *testing.T, gh *stubGitHub, static []string, orgTeams map[string][]string) *Provider {
	t.Helper()
	var rules []protection.TeamRule
	if orgTeams != nil {
		rules = []protection.TeamRule{{Claim: "orgs", Map: orgTeams}}
	}
	return newRulesProvider(t, gh, static, rules)
}

// newRulesProvider builds a started provider allowing the orgs
// "ethpandaops" and "sigp", with the given team configuration.
func newRulesProvider(
	t *testing.T, gh *stubGitHub, static []string, rules []protection.TeamRule,
) *Provider {
	t.Helper()
	log := logrus.New()
	log.SetOutput(io.Discard)
	now := time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)
	p := New(log, Config{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		SessionKey:   []byte("0123456789abcdef0123456789abcdef"),
		PublicURL:    "http://auth.localhost:18080",
		AllowedOrgs:  []string{"ethpandaops", "sigp"},
		Teams:        static,
		TeamRules:    rules,
		AuthorizeURL: gh.server.URL + "/login/oauth/authorize",
		TokenURL:     gh.server.URL + "/login/oauth/access_token",
		APIBaseURL:   gh.server.URL,
		Now:          func() time.Time { return now },
	})
	if err := p.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	return p
}

// TestGitHub_Teams runs the full login (callback → session cookie →
// Authenticate) for each team configuration.
func TestGitHub_Teams(t *testing.T) {
	orgTeams := map[string][]string{
		"ethpandaops": {"panda"},
		"SigP":        {"lighthouse", "anchor"},
		"unrelated":   {"nope"},
	}

	tests := []struct {
		name       string
		static     []string
		orgTeams   map[string][]string
		orgs       []githubOrg
		publicOrgs []githubOrg
		want       []string
	}{
		{"nothing configured", nil, nil, []githubOrg{{Login: "ethpandaops"}}, nil, nil},
		{"static only", []string{"devnet"}, nil, []githubOrg{{Login: "ethpandaops"}}, nil, []string{"devnet"}},
		{"org map", nil, orgTeams, []githubOrg{{Login: "ethpandaops"}}, nil, []string{"panda"}},
		{"org match ignores case", nil, orgTeams, []githubOrg{{Login: "EthPandaOps"}}, nil, []string{"panda"}},
		{
			"several orgs, private and public",
			nil, orgTeams,
			[]githubOrg{{Login: "ethpandaops"}}, []githubOrg{{Login: "sigp"}},
			[]string{"anchor", "lighthouse", "panda"},
		},
		{
			"static plus org map",
			[]string{"devnet", "panda"}, orgTeams,
			[]githubOrg{{Login: "sigp"}}, nil,
			[]string{"anchor", "devnet", "lighthouse", "panda"},
		},
		{
			"an org outside the map grants nothing",
			nil, map[string][]string{"unrelated": {"nope"}},
			[]githubOrg{{Login: "ethpandaops"}}, nil,
			nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gh := newStubGitHub(t)
			gh.user = githubUser{Login: "octocat", Email: "octo@example.com"}
			gh.orgs = tc.orgs
			gh.publicOrgs = tc.publicOrgs
			p := newTeamsProvider(t, gh, tc.static, tc.orgTeams)

			rr, cookie := runCallback(t, p)
			if rr.Code != http.StatusFound || cookie == nil {
				t.Fatalf("callback: status %d body %s", rr.Code, rr.Body.String())
			}

			r := httptest.NewRequest(http.MethodGet, "/auth/token?teams=intruder", nil)
			r.Header.Set("X-Teams", "intruder")
			r.AddCookie(cookie)
			out, err := p.Authenticate(context.Background(), r)
			if err != nil || out.Identity == nil {
				t.Fatalf("auth: identity=%v err=%v", out.Identity, err)
			}
			if !slices.Equal(out.Identity.Teams, tc.want) {
				t.Errorf("teams: got %v, want %v", out.Identity.Teams, tc.want)
			}
		})
	}
}

// TestGitHub_SessionTeams_ConfigChange: the org-derived teams stay as
// captured at login; the static teams follow the current config.
func TestGitHub_SessionTeams_ConfigChange(t *testing.T) {
	gh := newStubGitHub(t)
	gh.user = githubUser{Login: "octocat"}
	gh.orgs = []githubOrg{{Login: "sigp"}}

	before := newTeamsProvider(t, gh, []string{"devnet"}, map[string][]string{"sigp": {"lighthouse"}})
	_, cookie := runCallback(t, before)
	if cookie == nil {
		t.Fatal("no session cookie")
	}

	// New config: other static teams, and the org mapping is gone.
	after := newTeamsProvider(t, gh, []string{"ops"}, nil)
	r := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
	r.AddCookie(cookie)
	out, err := after.Authenticate(context.Background(), r)
	if err != nil || out.Identity == nil {
		t.Fatalf("auth: identity=%v err=%v", out.Identity, err)
	}
	if want := []string{"lighthouse", "ops"}; !slices.Equal(out.Identity.Teams, want) {
		t.Errorf("teams: got %v, want %v", out.Identity.Teams, want)
	}
}

// TestGitHub_OrgTeams_NoExtraAPICalls pins "no new GitHub API calls or
// scopes": the team mapping works off the four calls the org gate makes.
func TestGitHub_OrgTeams_NoExtraAPICalls(t *testing.T) {
	gh := newStubGitHub(t)
	gh.user = githubUser{Login: "octocat"}
	gh.orgs = []githubOrg{{Login: "sigp"}}

	var (
		mu    sync.Mutex
		paths []string
	)
	inner := gh.server.Config.Handler
	gh.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		inner.ServeHTTP(w, r)
	})

	p := newTeamsProvider(t, gh, nil, map[string][]string{"sigp": {"lighthouse"}})
	if got := p.authorizeRedirect("s"); !strings.Contains(got, "scope=read%3Aorg+user%3Aemail") {
		t.Errorf("authorize scopes changed: %s", got)
	}
	if rr, cookie := runCallback(t, p); cookie == nil {
		t.Fatalf("callback: status %d", rr.Code)
	}

	mu.Lock()
	defer mu.Unlock()
	slices.Sort(paths)
	want := []string{"/login/oauth/access_token", "/user", "/user/emails", "/user/orgs", "/users/octocat/orgs"}
	if !slices.Equal(paths, want) {
		t.Errorf("upstream calls: got %v, want %v", paths, want)
	}
}

func TestGitHub_Start_RejectsInvalidTeams(t *testing.T) {
	tests := []struct {
		name   string
		static []string
		rules  []protection.TeamRule
	}{
		{"static", []string{"core devs"}, nil},
		{"rule map value", nil, []protection.TeamRule{{Claim: "orgs", Map: map[string][]string{"sigp": {"light house"}}}}},
		{"rule without a claim", nil, []protection.TeamRule{{Prefix: "x"}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			log := logrus.New()
			log.SetOutput(io.Discard)
			p := New(log, Config{
				ClientID:     "client-id",
				ClientSecret: "client-secret",
				SessionKey:   []byte("0123456789abcdef0123456789abcdef"),
				PublicURL:    "http://auth.localhost:18080",
				AllowedOrgs:  []string{"sigp"},
				Teams:        tc.static,
				TeamRules:    tc.rules,
			})
			if err := p.Start(context.Background()); err == nil {
				t.Fatal("expected Start to reject the team configuration")
			}
		})
	}
}

// TestGitHub_TeamRules covers the rule forms against this provider's
// attributes: login, email, orgs.
func TestGitHub_TeamRules(t *testing.T) {
	tests := []struct {
		name  string
		rules []protection.TeamRule
		user  githubUser
		orgs  []githubOrg
		want  []string
	}{
		{
			"orgs through a map, with a glob",
			[]protection.TeamRule{{Claim: "orgs", Map: map[string][]string{"sigp": {"lighthouse"}, "eth*": {"eth"}}}},
			githubUser{Login: "octocat"}, []githubOrg{{Login: "SigP"}, {Login: "ethpandaops"}},
			[]string{"eth", "lighthouse"},
		},
		{
			"orgs as teams: only names already in normal form",
			[]protection.TeamRule{{Claim: "orgs", Value: true}},
			githubUser{Login: "octocat"}, []githubOrg{{Login: "sigp"}, {Login: "EthPandaOps"}},
			[]string{"sigp"},
		},
		{
			"login through a map: a team for one user",
			[]protection.TeamRule{{Claim: "login", Map: map[string][]string{"OctoCat": {"panda"}}}},
			githubUser{Login: "octocat"}, []githubOrg{{Login: "sigp"}},
			[]string{"panda"},
		},
		{
			"email through a regex",
			[]protection.TeamRule{{Claim: "email", Regex: `[^@]+@([a-z0-9-]+)\.example`}},
			githubUser{Login: "octocat", Email: "octo@sigma-prime.example"}, []githubOrg{{Login: "sigp"}},
			[]string{"sigma-prime"},
		},
		{
			"a missing attribute yields nothing",
			[]protection.TeamRule{{Claim: "email", Value: true}, {Claim: "groups", Value: true}, {Claim: "orgs.name", Value: true}},
			githubUser{Login: "octocat"}, []githubOrg{{Login: "sigp"}},
			nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gh := newStubGitHub(t)
			gh.user = tc.user
			gh.orgs = tc.orgs
			if tc.user.Email != "" {
				gh.emails = []githubEmail{{Email: tc.user.Email, Primary: true, Verified: true}}
			}
			p := newRulesProvider(t, gh, nil, tc.rules)

			rr, cookie := runCallback(t, p)
			if cookie == nil {
				t.Fatalf("callback: status %d body %s", rr.Code, rr.Body.String())
			}
			r := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
			r.AddCookie(cookie)
			out, err := p.Authenticate(context.Background(), r)
			if err != nil || out.Identity == nil {
				t.Fatalf("auth: identity=%v err=%v", out.Identity, err)
			}
			if !slices.Equal(out.Identity.Teams, tc.want) {
				t.Errorf("teams: got %v, want %v", out.Identity.Teams, tc.want)
			}
		})
	}
}

// TestGitHub_GrantMembers: attribute members against this provider's
// attributes (login, email, orgs), captured at login.
func TestGitHub_GrantMembers(t *testing.T) {
	gh := newStubGitHub(t)
	gh.user = githubUser{Login: "OctoCat", Email: "octo@example.com"}
	gh.emails = []githubEmail{{Email: "octo@example.com", Primary: true, Verified: true}}
	gh.orgs = []githubOrg{{Login: "EthPandaOps"}}
	gh.publicOrgs = []githubOrg{{Login: "sigp"}}

	log := logrus.New()
	log.SetOutput(io.Discard)
	now := time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)
	p := New(log, Config{
		ClientID: "client-id", ClientSecret: "client-secret",
		SessionKey:  []byte("0123456789abcdef0123456789abcdef"),
		PublicURL:   "http://auth.localhost:18080",
		AllowedOrgs: []string{"ethpandaops"},
		GrantMembers: []protection.AttributeMember{
			{Attribute: "orgs", Value: "ethpandaops"},
			{Attribute: "orgs", Value: "sigp"},
			{Attribute: "orgs", Value: "other-org"},
			{Attribute: "login", Value: "octocat"},
			{Attribute: "login", Value: "someone-else"},
			{Attribute: "email", Value: "OCTO@example.com"},
		},
		AuthorizeURL: gh.server.URL + "/login/oauth/authorize",
		TokenURL:     gh.server.URL + "/login/oauth/access_token",
		APIBaseURL:   gh.server.URL,
		Now:          func() time.Time { return now },
	})
	if err := p.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}

	rr, cookie := runCallback(t, p)
	if cookie == nil {
		t.Fatalf("callback: status %d body %s", rr.Code, rr.Body.String())
	}
	r := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
	r.AddCookie(cookie)
	out, err := p.Authenticate(context.Background(), r)
	if err != nil || out.Identity == nil {
		t.Fatalf("auth: identity=%v err=%v", out.Identity, err)
	}
	want := []string{"email:octo@example.com", "login:octocat", "orgs:ethpandaops", "orgs:sigp"}
	if !slices.Equal(out.Identity.Matches, want) {
		t.Errorf("matches: got %v, want %v", out.Identity.Matches, want)
	}
}

// TestGitHub_OnlyVerifiedEmails: the email of an identity — in the
// session, in the "email" attribute for team rules and grant members —
// is one GitHub reports as verified. The profile's public email is not
// taken on trust, and when the address list cannot be fetched the user
// has no email at all.
func TestGitHub_OnlyVerifiedEmails(t *testing.T) {
	tests := []struct {
		name         string
		public       string
		emails       []githubEmail
		emailsStatus int
		want         string
	}{
		{"public email, verified", "octo@example.com", []githubEmail{{Email: "octo@example.com", Verified: true}}, 200, "octo@example.com"},
		{"public email, verified, not primary", "pub@example.com", []githubEmail{{Email: "main@example.com", Primary: true, Verified: true}, {Email: "pub@example.com", Verified: true}}, 200, "pub@example.com"},
		{"public email, unverified: the primary verified one", "victim@example.org", []githubEmail{{Email: "victim@example.org", Verified: false}, {Email: "real@example.com", Primary: true, Verified: true}}, 200, "real@example.com"},
		{"public email not in the list: the primary verified one", "victim@example.org", []githubEmail{{Email: "real@example.com", Primary: true, Verified: true}}, 200, "real@example.com"},
		{"public email, nothing verified", "victim@example.org", []githubEmail{{Email: "victim@example.org", Primary: true, Verified: false}}, 200, ""},
		{"no public email, primary verified", "", []githubEmail{{Email: "real@example.com", Primary: true, Verified: true}}, 200, "real@example.com"},
		{"no public email, primary unverified", "", []githubEmail{{Email: "real@example.com", Primary: true, Verified: false}}, 200, ""},
		{"verified but not primary, no public email", "", []githubEmail{{Email: "side@example.com", Verified: true}}, 200, ""},
		{"the address list cannot be fetched", "victim@example.org", nil, 500, ""},
		{"no addresses", "victim@example.org", []githubEmail{}, 200, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gh := newStubGitHub(t)
			gh.user = githubUser{Login: "octocat", Email: tc.public}
			gh.emails = tc.emails
			gh.emailsStatus = tc.emailsStatus
			gh.orgs = []githubOrg{{Login: "sigp"}}

			log := logrus.New()
			log.SetOutput(io.Discard)
			now := time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)
			p := New(log, Config{
				ClientID: "client-id", ClientSecret: "client-secret",
				SessionKey:  []byte("0123456789abcdef0123456789abcdef"),
				PublicURL:   "http://auth.localhost:18080",
				AllowedOrgs: []string{"sigp"},
				TeamRules: []protection.TeamRule{
					{Claim: "email", Map: map[string][]string{"victim@example.org": {"victims-team"}, "*": {"has-email"}}},
				},
				GrantMembers: []protection.AttributeMember{{Attribute: "email", Value: "victim@example.org"}},
				AuthorizeURL: gh.server.URL + "/login/oauth/authorize",
				TokenURL:     gh.server.URL + "/login/oauth/access_token",
				APIBaseURL:   gh.server.URL,
				Now:          func() time.Time { return now },
			})
			if err := p.Start(context.Background()); err != nil {
				t.Fatalf("start: %v", err)
			}
			rr, cookie := runCallback(t, p)
			if cookie == nil {
				t.Fatalf("callback: status %d body %s", rr.Code, rr.Body.String())
			}
			r := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
			r.AddCookie(cookie)
			out, err := p.Authenticate(context.Background(), r)
			if err != nil || out.Identity == nil {
				t.Fatalf("auth: identity=%v err=%v", out.Identity, err)
			}
			id := out.Identity
			if id.Subject != "octocat" || id.Email != tc.want {
				t.Errorf("identity: sub=%q email=%q, want email %q", id.Subject, id.Email, tc.want)
			}
			if slices.Contains(id.Teams, "victims-team") || len(id.Matches) != 0 {
				t.Errorf("an unverified address reached rules or members: teams=%v matches=%v", id.Teams, id.Matches)
			}
			if got := slices.Contains(id.Teams, "has-email"); got != (tc.want != "") {
				t.Errorf("email attribute present: %t, want %t", got, tc.want != "")
			}
		})
	}
}
