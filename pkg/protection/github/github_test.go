package github

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"

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

func TestGitHub_Authenticate_NoSession_RedirectsToAuthorize(t *testing.T) {
	gh := newStubGitHub(t)
	p := newTestProvider(t, gh, "ethpandaops")

	r := httptest.NewRequest(http.MethodGet, "/auth/token?aud=foo", nil)
	out, err := p.Authenticate(context.Background(), r)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	if out.RedirectTo == "" {
		t.Fatal("expected redirect")
	}
	if !strings.HasPrefix(out.RedirectTo, gh.server.URL+"/login/oauth/authorize") {
		t.Errorf("redirect: %q", out.RedirectTo)
	}
	u, err := url.Parse(out.RedirectTo)
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
	if len(out.SetCookies) != 1 {
		t.Fatalf("expected one state cookie, got %d", len(out.SetCookies))
	}
	if out.SetCookies[0].Name != DefaultStateCookieName {
		t.Errorf("state cookie name: %q", out.SetCookies[0].Name)
	}
	if !out.SetCookies[0].HttpOnly {
		t.Error("state cookie should be HttpOnly")
	}
}

func TestGitHub_Authenticate_ValidSession_ReturnsIdentity(t *testing.T) {
	gh := newStubGitHub(t)
	p := newTestProvider(t, gh, "ethpandaops")

	cookie, err := p.signSessionCookie("octocat", "octo@example.com")
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
	login, email, err := session.Parse(p.sessionSecret, sessionCookie.Value, p.cfg.Now())
	if err != nil {
		t.Fatalf("parse session: %v", err)
	}
	if login != "octocat" || email != "octo@example.com" {
		t.Errorf("session: login=%q email=%q", login, email)
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
	_, email, err := session.Parse(p.sessionSecret, sessionCookie.Value, p.cfg.Now())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if email != "primary@example.com" {
		t.Errorf("email: %q want primary@example.com", email)
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
