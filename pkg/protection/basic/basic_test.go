package basic

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"

	"github.com/ethpandaops/service-authenticatoor/pkg/protection"
	"github.com/ethpandaops/service-authenticatoor/pkg/session"
)

// htpasswdSHA returns a one-entry htpasswd body using the {SHA} format
// that go-htpasswd parses without external tooling.
func htpasswdSHA(user, pass string) string {
	sum := sha1.Sum([]byte(pass))
	return user + ":{SHA}" + base64.StdEncoding.EncodeToString(sum[:]) + "\n"
}

func writeHtpasswd(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "htpasswd")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

var testSessionKey = []byte("0123456789abcdef0123456789abcdef")

func newTestProvider(t *testing.T, htpasswdBody string) *Provider {
	t.Helper()
	log := logrus.New()
	log.SetOutput(io.Discard)
	p := New(log, Config{
		HtpasswdFile: writeHtpasswd(t, htpasswdBody),
		Realm:        "test-realm",
		SessionKey:   testSessionKey,
	})
	if err := p.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	return p
}

// alice / hunter2 in {SHA} form.
var aliceHtpasswd = htpasswdSHA("alice", "hunter2")

func TestBasic_AcceptsCorrectCredentials(t *testing.T) {
	p := newTestProvider(t, aliceHtpasswd)

	r := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
	r.SetBasicAuth("alice", "hunter2")
	out, err := p.Authenticate(context.Background(), r)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	if out.Identity == nil {
		t.Fatalf("expected identity, got status %d", out.Status)
	}
	if out.Identity.Subject != "alice" {
		t.Errorf("subject: %q", out.Identity.Subject)
	}
}

func TestBasic_RejectsWrongPassword(t *testing.T) {
	p := newTestProvider(t, aliceHtpasswd)

	r := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
	r.SetBasicAuth("alice", "wrong")
	out, err := p.Authenticate(context.Background(), r)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	if out.Identity != nil {
		t.Fatal("expected no identity")
	}
	if out.Status != http.StatusUnauthorized {
		t.Errorf("status: got %d", out.Status)
	}
	chall := out.Challenge.Get("WWW-Authenticate")
	if !strings.Contains(chall, `realm="test-realm"`) {
		t.Errorf("challenge: %q", chall)
	}
}

func TestBasic_RejectsUnknownUser(t *testing.T) {
	p := newTestProvider(t, aliceHtpasswd)

	r := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
	r.SetBasicAuth("bob", "anything")
	out, err := p.Authenticate(context.Background(), r)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	if out.Identity != nil {
		t.Fatal("expected no identity for unknown user")
	}
}

func TestBasic_RejectsMissingHeader(t *testing.T) {
	p := newTestProvider(t, aliceHtpasswd)

	r := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
	out, err := p.Authenticate(context.Background(), r)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	if out.Identity != nil {
		t.Fatal("expected no identity")
	}
	if out.Status != http.StatusUnauthorized {
		t.Errorf("status: got %d", out.Status)
	}
}

func TestBasic_Start_RejectsMissingFile(t *testing.T) {
	log := logrus.New()
	log.SetOutput(io.Discard)
	p := New(log, Config{HtpasswdFile: "", SessionKey: testSessionKey})
	if err := p.Start(context.Background()); err == nil {
		t.Error("expected error for empty HtpasswdFile")
	}
}

func TestBasic_Start_RejectsShortSessionKey(t *testing.T) {
	log := logrus.New()
	log.SetOutput(io.Discard)
	p := New(log, Config{HtpasswdFile: writeHtpasswd(t, aliceHtpasswd), SessionKey: []byte("short")})
	if err := p.Start(context.Background()); err == nil {
		t.Error("expected error for short SessionKey")
	}
}

// TestBasic_LoginMintsSessionCookie exercises the multi-provider flow:
// the login entry challenges, converts valid credentials into a session
// cookie, and a later /auth/* request without an Authorization header
// authenticates via that cookie.
func TestBasic_LoginMintsSessionCookie(t *testing.T) {
	p := newTestProvider(t, aliceHtpasswd)

	// Without credentials the login entry challenges.
	r := httptest.NewRequest(http.MethodGet, DefaultLoginPath+"?return_to=%2Fauth%2Ftoken", nil)
	rr := httptest.NewRecorder()
	p.handleLogin(rr, r)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401 challenge", rr.Code)
	}
	if chall := rr.Header().Get("WWW-Authenticate"); !strings.Contains(chall, `realm="test-realm"`) {
		t.Errorf("challenge: %q", chall)
	}

	// With credentials it mints the cookie and redirects.
	r = httptest.NewRequest(http.MethodGet, DefaultLoginPath+"?return_to=%2Fauth%2Ftoken", nil)
	r.SetBasicAuth("alice", "hunter2")
	rr = httptest.NewRecorder()
	p.handleLogin(rr, r)
	if rr.Code != http.StatusFound {
		t.Fatalf("status: got %d, want 302", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "/auth/token" {
		t.Errorf("redirect: got %q", loc)
	}
	cookies := rr.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != DefaultSessionCookieName {
		t.Fatalf("expected one session cookie, got %v", cookies)
	}

	// Replay the cookie on a bare /auth/* request.
	r2 := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
	r2.AddCookie(cookies[0])
	out, err := p.Authenticate(context.Background(), r2)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	if out.Identity == nil {
		t.Fatalf("expected identity from session cookie, got status %d", out.Status)
	}
	if out.Identity.Subject != "alice" {
		t.Errorf("subject: %q", out.Identity.Subject)
	}
}

// newTeamsProvider builds a started provider with the given static teams.
func newTeamsProvider(t *testing.T, teams ...string) *Provider {
	t.Helper()
	log := logrus.New()
	log.SetOutput(io.Discard)
	p := New(log, Config{
		HtpasswdFile: writeHtpasswd(t, aliceHtpasswd),
		SessionKey:   testSessionKey,
		Teams:        teams,
	})
	if err := p.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	return p
}

// loginCookie runs the login entry with alice's credentials and returns
// the session cookie it minted.
func loginCookie(t *testing.T, p *Provider) *http.Cookie {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, DefaultLoginPath, nil)
	r.SetBasicAuth("alice", "hunter2")
	rr := httptest.NewRecorder()
	p.handleLogin(rr, r)
	cookies := rr.Result().Cookies()
	if rr.Code != http.StatusFound || len(cookies) != 1 {
		t.Fatalf("login: status %d, cookies %v", rr.Code, cookies)
	}
	return cookies[0]
}

// TestBasic_Teams covers both paths that build an Identity: the ambient
// Authorization header and the session cookie minted by the login entry.
func TestBasic_Teams(t *testing.T) {
	tests := []struct {
		name   string
		static []string
		want   []string
	}{
		{"none configured", nil, nil},
		{"one", []string{"panda"}, []string{"panda"}},
		{"sorted, de-duplicated", []string{"panda", "geth", "panda"}, []string{"geth", "panda"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := newTeamsProvider(t, tc.static...)

			ambient := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
			ambient.SetBasicAuth("alice", "hunter2")
			out, err := p.Authenticate(context.Background(), ambient)
			if err != nil || out.Identity == nil {
				t.Fatalf("ambient auth: identity=%v err=%v", out.Identity, err)
			}
			if !slices.Equal(out.Identity.Teams, tc.want) {
				t.Errorf("ambient teams: got %v, want %v", out.Identity.Teams, tc.want)
			}

			viaCookie := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
			viaCookie.AddCookie(loginCookie(t, p))
			out, err = p.Authenticate(context.Background(), viaCookie)
			if err != nil || out.Identity == nil {
				t.Fatalf("cookie auth: identity=%v err=%v", out.Identity, err)
			}
			if !slices.Equal(out.Identity.Teams, tc.want) {
				t.Errorf("session teams: got %v, want %v", out.Identity.Teams, tc.want)
			}
		})
	}
}

// TestBasic_SessionFollowsCurrentStaticTeams: a session minted under one
// config picks up the static teams of the config in force when it is
// used (the session key is the same across the restart).
func TestBasic_SessionFollowsCurrentStaticTeams(t *testing.T) {
	before := newTeamsProvider(t, "panda")
	cookie := loginCookie(t, before)

	tests := []struct {
		name   string
		static []string
		want   []string
	}{
		{"unchanged", []string{"panda"}, []string{"panda"}},
		{"team added", []string{"panda", "ops"}, []string{"ops", "panda"}},
		{"team replaced", []string{"ops"}, []string{"ops"}},
		{"teams removed", nil, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			after := newTeamsProvider(t, tc.static...)
			r := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
			r.AddCookie(cookie)
			out, err := after.Authenticate(context.Background(), r)
			if err != nil || out.Identity == nil {
				t.Fatalf("auth: identity=%v err=%v", out.Identity, err)
			}
			if !slices.Equal(out.Identity.Teams, tc.want) {
				t.Errorf("teams: got %v, want %v", out.Identity.Teams, tc.want)
			}
		})
	}
}

// TestBasic_TeamsNotTakenFromRequest: nothing a client can put on the
// request — query, headers, a forged or tampered cookie — adds a team.
func TestBasic_TeamsNotTakenFromRequest(t *testing.T) {
	p := newTeamsProvider(t, "geth")

	r := httptest.NewRequest(http.MethodGet, "/auth/token?teams=panda&team=panda", nil)
	r.SetBasicAuth("alice", "hunter2")
	r.Header.Set("X-Teams", "panda")
	r.Header.Set("X-Auth-Teams", "panda")
	r.AddCookie(&http.Cookie{Name: "teams", Value: "panda"})
	out, err := p.Authenticate(context.Background(), r)
	if err != nil || out.Identity == nil {
		t.Fatalf("auth: identity=%v err=%v", out.Identity, err)
	}
	if !slices.Equal(out.Identity.Teams, []string{"geth"}) {
		t.Errorf("teams: got %v, want only the configured [geth]", out.Identity.Teams)
	}

	// A session cookie that fails verification yields no identity at all.
	cookie := loginCookie(t, p)
	cookie.Value = cookie.Value[:len(cookie.Value)-2] + "xx"
	r = httptest.NewRequest(http.MethodGet, "/auth/token", nil)
	r.AddCookie(cookie)
	out, err = p.Authenticate(context.Background(), r)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	if out.Identity != nil {
		t.Errorf("tampered cookie produced an identity: %+v", out.Identity)
	}
}

func TestBasic_Start_RejectsInvalidTeams(t *testing.T) {
	log := logrus.New()
	log.SetOutput(io.Discard)
	p := New(log, Config{
		HtpasswdFile: writeHtpasswd(t, aliceHtpasswd),
		SessionKey:   testSessionKey,
		Teams:        []string{"panda", "core devs"},
	})
	if err := p.Start(context.Background()); err == nil {
		t.Fatal("expected Start to reject an invalid team name")
	}
}

// TestBasic_TeamRules: the one attribute is "username"; rules run on
// every request, for the Authorization header and the session cookie
// alike, against the current config.
func TestBasic_TeamRules(t *testing.T) {
	build := func(static []string, rules []protection.TeamRule) *Provider {
		log := logrus.New()
		log.SetOutput(io.Discard)
		p := New(log, Config{
			HtpasswdFile: writeHtpasswd(t, aliceHtpasswd),
			SessionKey:   testSessionKey,
			Teams:        static,
			TeamRules:    rules,
		})
		if err := p.Start(context.Background()); err != nil {
			t.Fatalf("start: %v", err)
		}
		return p
	}

	tests := []struct {
		name  string
		rules []protection.TeamRule
		want  []string
	}{
		{"map: a team for one user", []protection.TeamRule{{Claim: "username", Map: map[string][]string{"Alice": {"lighthouse"}}}}, []string{"lighthouse", "ops"}},
		{"map: another user", []protection.TeamRule{{Claim: "username", Map: map[string][]string{"bob": {"geth"}}}}, []string{"ops"}},
		{"bare: the username as a team", []protection.TeamRule{{Claim: "username", Value: true}}, []string{"alice", "ops"}},
		{"regex", []protection.TeamRule{{Claim: "username", Regex: "(al)ice"}}, []string{"al", "ops"}},
		{"no other attribute exists", []protection.TeamRule{{Claim: "email", Value: true}, {Claim: "groups", Value: true}, {Claim: "sub", Value: true}}, []string{"ops"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := build([]string{"ops"}, tc.rules)

			ambient := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
			ambient.SetBasicAuth("alice", "hunter2")
			out, err := p.Authenticate(context.Background(), ambient)
			if err != nil || out.Identity == nil {
				t.Fatalf("ambient: identity=%v err=%v", out.Identity, err)
			}
			if !slices.Equal(out.Identity.Teams, tc.want) {
				t.Errorf("ambient teams: got %v, want %v", out.Identity.Teams, tc.want)
			}

			viaCookie := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
			viaCookie.AddCookie(loginCookie(t, p))
			out, err = p.Authenticate(context.Background(), viaCookie)
			if err != nil || out.Identity == nil {
				t.Fatalf("session: identity=%v err=%v", out.Identity, err)
			}
			if !slices.Equal(out.Identity.Teams, tc.want) {
				t.Errorf("session teams: got %v, want %v", out.Identity.Teams, tc.want)
			}
		})
	}

	// A session minted before a rule change follows the new rules.
	before := build(nil, []protection.TeamRule{{Claim: "username", Map: map[string][]string{"alice": {"old"}}}})
	cookie := loginCookie(t, before)
	after := build(nil, []protection.TeamRule{{Claim: "username", Map: map[string][]string{"alice": {"new"}}}})
	r := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
	r.AddCookie(cookie)
	out, err := after.Authenticate(context.Background(), r)
	if err != nil || out.Identity == nil {
		t.Fatalf("auth: identity=%v err=%v", out.Identity, err)
	}
	if !slices.Equal(out.Identity.Teams, []string{"new"}) {
		t.Errorf("teams after a rule change: %v", out.Identity.Teams)
	}
}

// TestBasic_IgnoresTeamsInSessionCookie: this provider never stores
// teams in a session, so it does not read any from one either — not
// even from a cookie that verifies under its key and names its door.
func TestBasic_IgnoresTeamsInSessionCookie(t *testing.T) {
	p := newTeamsProvider(t, "ops")

	signed, err := session.Sign(testSessionKey, p.door,
		session.Payload{Subject: "alice", Email: "alice", Teams: []string{"panda", "lighthouse"}},
		DefaultSessionTTL, p.cfg.Now())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	r := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
	r.AddCookie(&http.Cookie{Name: DefaultSessionCookieName, Value: signed})
	out, err := p.Authenticate(context.Background(), r)
	if err != nil || out.Identity == nil {
		t.Fatalf("auth: identity=%v err=%v", out.Identity, err)
	}
	if !slices.Equal(out.Identity.Teams, []string{"ops"}) {
		t.Errorf("teams: got %v, want only the configured [ops]", out.Identity.Teams)
	}
}

// TestBasic_RejectsSessionsOfAnotherProviderType: the session key is
// derived from the provider's name, so an entry that was "oidc" and is
// now "basic" under the same name shares its key with the old cookies.
// Those were opened at another door and no longer count.
func TestBasic_RejectsSessionsOfAnotherProviderType(t *testing.T) {
	p := newTeamsProvider(t, "ops")

	for _, door := range []session.Door{
		session.NewDoor("oidc", "https://idp.example", "authenticatoor"),
		session.NewDoor("github", ""),
		session.NewDoor("cloudflare", "team.cloudflareaccess.com", "true"),
	} {
		signed, err := session.Sign(testSessionKey, door,
			session.Payload{Subject: "mallory@idp.example", Email: "mallory@idp.example", Teams: []string{"panda"}},
			DefaultSessionTTL, p.cfg.Now())
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		r := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
		r.AddCookie(&http.Cookie{Name: DefaultSessionCookieName, Value: signed})
		out, err := p.Authenticate(context.Background(), r)
		if err != nil {
			t.Fatalf("auth: %v", err)
		}
		if out.Identity != nil {
			t.Errorf("a session opened at door %s authenticated at the basic provider: %+v", door, out.Identity)
		}
	}
}

// TestBasic_GrantMembers: the one attribute is "username"; members are
// evaluated on every request against the current config, and matches a
// session cookie claims to hold are not read.
func TestBasic_GrantMembers(t *testing.T) {
	build := func(members ...protection.AttributeMember) *Provider {
		log := logrus.New()
		log.SetOutput(io.Discard)
		p := New(log, Config{HtpasswdFile: writeHtpasswd(t, aliceHtpasswd), SessionKey: testSessionKey, GrantMembers: members})
		if err := p.Start(context.Background()); err != nil {
			t.Fatalf("start: %v", err)
		}
		return p
	}
	alice := protection.AttributeMember{Attribute: "username", Value: "Alice"}
	bob := protection.AttributeMember{Attribute: "username", Value: "bob"}

	p := build(alice, bob)
	ambient := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
	ambient.SetBasicAuth("alice", "hunter2")
	out, err := p.Authenticate(context.Background(), ambient)
	if err != nil || out.Identity == nil {
		t.Fatalf("ambient: identity=%v err=%v", out.Identity, err)
	}
	if want := []string{"username:alice"}; !slices.Equal(out.Identity.Matches, want) {
		t.Errorf("ambient matches: got %v, want %v", out.Identity.Matches, want)
	}

	cookie := loginCookie(t, build())
	viaCookie := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
	viaCookie.AddCookie(cookie)
	out, err = p.Authenticate(context.Background(), viaCookie)
	if err != nil || out.Identity == nil {
		t.Fatalf("session: identity=%v err=%v", out.Identity, err)
	}
	if want := []string{"username:alice"}; !slices.Equal(out.Identity.Matches, want) {
		t.Errorf("a session minted before the member existed: got %v, want %v", out.Identity.Matches, want)
	}

	// A cookie that verifies and claims matches: not read.
	forged, err := session.Sign(testSessionKey, p.door,
		session.Payload{Subject: "alice", Email: "alice", Matches: []string{"username:bob", "groups:panda-access"}},
		DefaultSessionTTL, p.cfg.Now())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	r := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
	r.AddCookie(&http.Cookie{Name: DefaultSessionCookieName, Value: forged})
	out, err = p.Authenticate(context.Background(), r)
	if err != nil || out.Identity == nil {
		t.Fatalf("auth: identity=%v err=%v", out.Identity, err)
	}
	if want := []string{"username:alice"}; !slices.Equal(out.Identity.Matches, want) {
		t.Errorf("matches from a cookie were read: %v", out.Identity.Matches)
	}
}

// TestBasic_LoginRefusedWhenSessionDoesNotFitACookie: a username too
// long for a session cookie gets no cookie at the login entry. (It
// still authenticates with its Authorization header, which needs none.)
func TestBasic_LoginRefusedWhenSessionDoesNotFitACookie(t *testing.T) {
	long := strings.Repeat("u", 4000)
	p := newTestProvider(t, htpasswdSHA(long, "hunter2"))

	r := httptest.NewRequest(http.MethodGet, DefaultLoginPath, nil)
	r.SetBasicAuth(long, "hunter2")
	rr := httptest.NewRecorder()
	p.handleLogin(rr, r)
	if rr.Code != http.StatusForbidden || len(rr.Result().Cookies()) != 0 ||
		!strings.Contains(rr.Body.String(), "too long to be stored in a session cookie") {
		t.Errorf("status %d, cookies %v, body %q", rr.Code, rr.Result().Cookies(), rr.Body.String())
	}

	ambient := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
	ambient.SetBasicAuth(long, "hunter2")
	out, err := p.Authenticate(context.Background(), ambient)
	if err != nil || out.Identity == nil || out.Identity.Subject != long {
		t.Errorf("ambient: %v %+v", err, out)
	}
}

// TestBasic_AmbientMatchesAreNotCutToACookie: nothing of a basic
// identity is stored in a cookie but its username, so the bounds of a
// session cookie do not apply to the grants members it satisfies.
func TestBasic_AmbientMatchesAreNotCutToACookie(t *testing.T) {
	// One member whose key is as long as a member may be: with a few
	// teams' worth of budget it would still fit, but the budget is not
	// what decides here.
	members := make([]protection.AttributeMember, 0, 2)
	members = append(members, protection.AttributeMember{Attribute: "username", Value: "alice"})
	log, hook := test.NewNullLogger()
	p := New(log, Config{HtpasswdFile: writeHtpasswd(t, aliceHtpasswd), SessionKey: testSessionKey, GrantMembers: members})
	if err := p.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	hook.Reset()
	for _, viaCookie := range []bool{false, true} {
		r := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
		if viaCookie {
			r.AddCookie(loginCookie(t, p))
		} else {
			r.SetBasicAuth("alice", "hunter2")
		}
		out, err := p.Authenticate(context.Background(), r)
		if err != nil || out.Identity == nil {
			t.Fatalf("authenticate: %v %+v", err, out)
		}
		if !slices.Equal(out.Identity.Matches, []string{"username:alice"}) || out.Identity.SubjectIsEmail {
			t.Errorf("identity (cookie: %t): %+v", viaCookie, out.Identity)
		}
	}
	if len(hook.AllEntries()) != 0 {
		t.Errorf("log: %v", hook.AllEntries())
	}
}
