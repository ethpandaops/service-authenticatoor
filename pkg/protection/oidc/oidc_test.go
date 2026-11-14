package oidc

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"

	"github.com/ethpandaops/service-authenticatoor/pkg/auth"
	"github.com/ethpandaops/service-authenticatoor/pkg/protection"
	"github.com/ethpandaops/service-authenticatoor/pkg/protection/oidc/oidctest"
	"github.com/ethpandaops/service-authenticatoor/pkg/session"
)

// TestStatePrefix pins the relay routing contract: the relay redirects
// to <statePrefix>/callback, so the prefix must be the public URL plus
// the callback path with exactly its "/callback" suffix removed.
func TestStatePrefix(t *testing.T) {
	log := logrus.New()
	log.SetOutput(io.Discard)

	tests := []struct {
		name         string
		publicURL    string
		callbackPath string
		want         string
	}{
		{"default path", "https://auth.example", "", "https://auth.example/oidc"},
		{"named instance", "https://auth.example/", "/corp/callback", "https://auth.example/corp"},
		{"legacy path", "https://auth.example", "/auth/oidc/callback", "https://auth.example/auth/oidc"},
		{"no callback suffix", "https://auth.example", "/cb", "https://auth.example/cb"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := New(log, Config{PublicURL: tc.publicURL, CallbackPath: tc.callbackPath})
			if got := p.statePrefix(); got != tc.want {
				t.Errorf("statePrefix: got %q, want %q", got, tc.want)
			}
		})
	}
}

var testSessionKey = []byte("0123456789abcdef0123456789abcdef")

// prefixRule is the rule the central IdP setup uses: every `team:<slug>`
// group is the team <slug>.
var prefixRule = protection.TeamRule{Claim: "groups", Prefix: "team:"}

// mapRule maps values of the groups claim to teams.
func mapRule(m map[string][]string) protection.TeamRule {
	return protection.TeamRule{Claim: "groups", Map: m}
}

func teamRules(rules ...protection.TeamRule) []protection.TeamRule { return rules }

// newIdPProvider builds a started provider wired to a fake IdP. cfg
// supplies the team (and gating) configuration; the endpoints, client and
// session key are filled in here.
func newIdPProvider(t *testing.T, idp *oidctest.IdP, cfg Config) *Provider {
	t.Helper()
	log := logrus.New()
	log.SetOutput(io.Discard)

	cfg.IssuerURL = idp.URL
	cfg.PublicURL = "https://auth.test.example"
	cfg.CallbackURL = "https://auth.test.example/oidc/callback"
	cfg.ClientID = "authenticatoor"
	cfg.ClientSecret = "client-secret"
	cfg.SessionKey = testSessionKey

	p := New(log, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel) // stops the JWKS refresh goroutine
	if err := p.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	return p
}

// login runs the whole interactive flow — login entry, the IdP's
// authorize redirect, the callback with its code exchange and id_token
// verification — and returns the callback response and the session
// cookie it set (nil when the login was refused).
func login(t *testing.T, p *Provider, idp *oidctest.IdP) (*httptest.ResponseRecorder, *http.Cookie) {
	t.Helper()
	r := mux.NewRouter()
	p.RegisterRoutes(r)

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, p.cfg.LoginPath+"?return_to=%2Fauth%2Ftoken", nil))
	if rr.Code != http.StatusFound {
		t.Fatalf("login entry: status %d", rr.Code)
	}
	var stateCookie *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == p.cfg.StateCookieName {
			stateCookie = c
		}
	}
	if stateCookie == nil {
		t.Fatal("login entry set no state cookie")
	}

	back := idp.Authorize(t, rr.Header().Get("Location"))

	req := httptest.NewRequest(http.MethodGet, p.cfg.CallbackPath+"?"+back.Encode(), nil)
	req.AddCookie(stateCookie)
	rr = httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	for _, c := range rr.Result().Cookies() {
		if c.Name == p.cfg.SessionCookieName && c.MaxAge > 0 {
			return rr, c
		}
	}
	return rr, nil
}

// identityFor replays the session cookie on a bare /auth/* request.
func identityFor(t *testing.T, p *Provider, cookie *http.Cookie) *protection.Identity {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/auth/token?teams=intruder", nil)
	r.Header.Set("X-Teams", "intruder")
	r.AddCookie(cookie)
	out, err := p.Authenticate(context.Background(), r)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	return out.Identity
}

// TestOIDC_Teams runs the full login against the fake IdP for each team
// configuration and checks the teams on the resulting identity.
func TestOIDC_Teams(t *testing.T) {
	groupTeams := map[string][]string{
		"ethpandaops":   {"panda"},
		"ethpandaops:*": {"panda"},
		"SigP:Core":     {"lighthouse"},
		"not-in-claims": {"nope"},
	}

	tests := []struct {
		name   string
		cfg    Config
		groups []string
		want   []string
	}{
		{"nothing configured", Config{}, []string{"team:lighthouse", "ethpandaops"}, nil},
		{"static only", Config{Teams: []string{"devnet"}}, []string{"team:lighthouse"}, []string{"devnet"}},
		{
			"a map rule alone does not treat team: groups as teams",
			Config{TeamRules: teamRules(mapRule(map[string][]string{"x": {"y"}}))},
			[]string{"team:lighthouse"},
			nil,
		},
		{
			"prefix",
			Config{TeamRules: teamRules(prefixRule)},
			[]string{"team:lighthouse", "team:geth", "ethpandaops", "other:thing"},
			[]string{"geth", "lighthouse"},
		},
		{
			"the prefix matches in any case, the team name must be in normal form",
			Config{TeamRules: teamRules(prefixRule)},
			[]string{"Team:Lighthouse", "TEAM:lighthouse"},
			[]string{"lighthouse"},
		},
		{
			"prefix: invalid team names are dropped",
			Config{TeamRules: teamRules(prefixRule)},
			[]string{"team:", "team:core devs", "team:-x", "team:a:b", "team:geth"},
			[]string{"geth"},
		},
		{
			"prefix is a prefix, not a substring",
			Config{TeamRules: teamRules(prefixRule)},
			[]string{"xteam:geth", "org/team:geth"},
			nil,
		},
		{"group map: exact group", Config{TeamRules: teamRules(mapRule(groupTeams))}, []string{"ethpandaops"}, []string{"panda"}},
		{"group map: case-insensitive", Config{TeamRules: teamRules(mapRule(groupTeams))}, []string{"EthPandaOps", "sigp:core"}, []string{"lighthouse", "panda"}},
		{
			"group map: org:* covers the org's teams",
			Config{TeamRules: teamRules(mapRule(groupTeams))},
			[]string{"ethpandaops:devops"},
			[]string{"panda"},
		},
		{
			"group map: a bare org key does not match org:team or org-other",
			Config{TeamRules: teamRules(mapRule(map[string][]string{"ethpandaops": {"panda"}}))},
			[]string{"ethpandaops:devops", "ethpandaops-evil", "xethpandaops"},
			nil,
		},
		{
			"group map: an org:team key matches only that team",
			Config{TeamRules: teamRules(mapRule(groupTeams))},
			[]string{"sigp:other", "sigp"},
			nil,
		},
		{
			"static, prefix and group map add up",
			Config{Teams: []string{"devnet"}, TeamRules: teamRules(prefixRule, mapRule(groupTeams))},
			[]string{"team:geth", "ethpandaops", "team:panda"},
			[]string{"devnet", "geth", "panda"},
		},
		{"no groups claim", Config{Teams: []string{"devnet"}, TeamRules: teamRules(prefixRule)}, nil, []string{"devnet"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			idp := oidctest.New(t, oidctest.User{
				Subject: "user-1", Email: "alice@example.com", Groups: tc.groups,
			})
			p := newIdPProvider(t, idp, tc.cfg)

			rr, cookie := login(t, p, idp)
			if cookie == nil {
				t.Fatalf("login refused: status %d body %s", rr.Code, rr.Body.String())
			}
			id := identityFor(t, p, cookie)
			if id == nil {
				t.Fatal("session cookie did not authenticate")
			}
			if id.Subject != "alice@example.com" || id.Email != "alice@example.com" {
				t.Errorf("identity: %q/%q", id.Subject, id.Email)
			}
			if !slices.Equal(id.Teams, tc.want) {
				t.Errorf("teams: got %v, want %v", id.Teams, tc.want)
			}
		})
	}
}

// TestOIDC_Teams_BoundedAndLoggedAtLogin: an IdP that sends far too many
// (and invalid) groups is cut to the bound with the configured team
// kept, the warnings are logged once at login, and later requests log
// nothing.
func TestOIDC_Teams_BoundedAndLoggedAtLogin(t *testing.T) {
	groups := make([]string, 0, 202)
	for i := range 200 {
		groups = append(groups, fmt.Sprintf("team:a-%03d", i))
	}
	groups = append(groups, "team:not valid", "team:")
	idp := oidctest.New(t, oidctest.User{Subject: "user-1", Email: "alice@example.com", Groups: groups})

	log, hook := test.NewNullLogger()
	p := New(log, Config{
		IssuerURL:    idp.URL,
		PublicURL:    "https://auth.test.example",
		CallbackURL:  "https://auth.test.example/oidc/callback",
		ClientID:     "authenticatoor",
		ClientSecret: "client-secret",
		SessionKey:   testSessionKey,
		Teams:        []string{"panda"},
		TeamRules:    teamRules(prefixRule),
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := p.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	hook.Reset()

	_, cookie := login(t, p, idp)
	if cookie == nil {
		t.Fatal("login refused")
	}
	var warnings []string
	for _, e := range hook.AllEntries() {
		if e.Level == logrus.WarnLevel {
			warnings = append(warnings, e.Message)
		}
	}
	if len(warnings) != 2 ||
		!strings.Contains(warnings[0], "not in normal form") ||
		!strings.Contains(warnings[1], "too many teams") {
		t.Errorf("login warnings: %q", warnings)
	}
	if size := len(cookie.String()); size >= 4096 {
		t.Errorf("session cookie is %d bytes", size)
	}

	hook.Reset()
	for range 3 {
		id := identityFor(t, p, cookie)
		if id == nil {
			t.Fatal("session cookie did not authenticate")
		}
		if len(id.Teams) != auth.MaxTeams {
			t.Fatalf("teams: got %d, want %d", len(id.Teams), auth.MaxTeams)
		}
		if !slices.Contains(id.Teams, "panda") {
			t.Errorf("the configured team was pushed out: %v", id.Teams)
		}
		if id.Teams[0] != "a-000" || id.Teams[auth.MaxTeams-2] != "a-030" {
			t.Errorf("truncation is not the sorted head: %v", id.Teams)
		}
	}
	if n := len(hook.AllEntries()); n != 0 {
		t.Errorf("per-request authentication logged %d entries", n)
	}
}

// TestOIDC_SessionTeams_ConfigChange: IdP-derived teams stay as captured
// at login — even when the user's groups or the mapping config change —
// while the static teams follow the current config.
func TestOIDC_SessionTeams_ConfigChange(t *testing.T) {
	idp := oidctest.New(t, oidctest.User{
		Subject: "user-1", Email: "alice@example.com", Groups: []string{"team:lighthouse", "ethpandaops"},
	})
	before := newIdPProvider(t, idp, Config{
		Teams:     []string{"devnet"},
		TeamRules: teamRules(prefixRule, mapRule(map[string][]string{"ethpandaops": {"panda"}})),
	})
	_, cookie := login(t, before, idp)
	if cookie == nil {
		t.Fatal("login refused")
	}
	if got, want := identityFor(t, before, cookie).Teams, []string{"devnet", "lighthouse", "panda"}; !slices.Equal(got, want) {
		t.Fatalf("teams at login: got %v, want %v", got, want)
	}

	// The user leaves their groups at the IdP; the session is unaffected
	// until it expires.
	idp.SetUser(oidctest.User{Subject: "user-1", Email: "alice@example.com"})

	tests := []struct {
		name string
		cfg  Config
		want []string
	}{
		{
			"static teams replaced",
			Config{Teams: []string{"ops"}, TeamRules: teamRules(prefixRule)},
			[]string{"lighthouse", "ops", "panda"},
		},
		{"all team config removed", Config{}, []string{"lighthouse", "panda"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			after := newIdPProvider(t, idp, tc.cfg)
			id := identityFor(t, after, cookie)
			if id == nil {
				t.Fatal("session cookie did not authenticate")
			}
			if !slices.Equal(id.Teams, tc.want) {
				t.Errorf("teams: got %v, want %v", id.Teams, tc.want)
			}
		})
	}

	// A fresh login picks up the IdP's current view.
	_, fresh := login(t, before, idp)
	if fresh == nil {
		t.Fatal("re-login refused")
	}
	if got, want := identityFor(t, before, fresh).Teams, []string{"devnet"}; !slices.Equal(got, want) {
		t.Errorf("teams after re-login: got %v, want %v", got, want)
	}
}

// TestOIDC_OldAndTamperedSessions: a cookie as released versions issued
// it — no door — is not accepted (its user logs in again once after
// the upgrade); a cookie that fails verification yields no identity.
func TestOIDC_OldAndTamperedSessions(t *testing.T) {
	idp := oidctest.New(t, oidctest.User{
		Subject: "user-1", Email: "alice@example.com", Groups: []string{"team:lighthouse"},
	})
	p := newIdPProvider(t, idp, Config{Teams: []string{"devnet"}, TeamRules: teamRules(prefixRule)})

	// Exactly what the previous release signed: sub, email, iat, exp.
	now := p.cfg.Now()
	oldTok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":   "alice@example.com",
		"email": "alice@example.com",
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
	})
	oldValue, err := oldTok.SignedString(testSessionKey)
	if err != nil {
		t.Fatalf("sign old cookie: %v", err)
	}
	if id := identityFor(t, p, &http.Cookie{Name: p.cfg.SessionCookieName, Value: oldValue}); id != nil {
		t.Errorf("a session without a door authenticated: %+v", id)
	}
	// The request is sent on to the login entry, as for no cookie at all.
	r := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
	r.AddCookie(&http.Cookie{Name: p.cfg.SessionCookieName, Value: oldValue})
	if out, err := p.Authenticate(context.Background(), r); err != nil || out.RedirectTo == "" {
		t.Errorf("outcome for a doorless cookie: %+v err=%v", out, err)
	}

	// A payload claiming "panda", signed with a key that is not ours.
	forged := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":   "alice@example.com",
		"teams": []string{"panda"},
		"exp":   now.Add(time.Hour).Unix(),
	})
	forgedValue, err := forged.SignedString([]byte("another-key-another-key-another-"))
	if err != nil {
		t.Fatalf("sign forged cookie: %v", err)
	}
	if id := identityFor(t, p, &http.Cookie{Name: p.cfg.SessionCookieName, Value: forgedValue}); id != nil {
		t.Errorf("forged cookie produced an identity: %+v", id)
	}

	// A genuine cookie with its payload swapped for the forged one.
	_, cookie := login(t, p, idp)
	if cookie == nil {
		t.Fatal("login refused")
	}
	genuine := strings.Split(cookie.Value, ".")
	swapped := genuine[0] + "." + strings.Split(forgedValue, ".")[1] + "." + genuine[2]
	if id := identityFor(t, p, &http.Cookie{Name: p.cfg.SessionCookieName, Value: swapped}); id != nil {
		t.Errorf("tampered cookie produced an identity: %+v", id)
	}
}

func TestOIDC_Start_RejectsInvalidTeams(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
	}{
		{"static", Config{Teams: []string{"team:panda"}}},
		{"group map value", Config{TeamRules: teamRules(mapRule(map[string][]string{"ethpandaops": {"Panda Team"}}))}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			log := logrus.New()
			log.SetOutput(io.Discard)
			tc.cfg.IssuerURL = "https://idp.invalid"
			tc.cfg.PublicURL = "https://auth.test.example"
			tc.cfg.CallbackURL = "https://auth.test.example/oidc/callback"
			tc.cfg.ClientID = "authenticatoor"
			tc.cfg.ClientSecret = "client-secret"
			tc.cfg.SessionKey = testSessionKey
			err := New(log, tc.cfg).Start(context.Background())
			if err == nil || !strings.Contains(err.Error(), "invalid team name") {
				t.Fatalf("Start: got %v, want an invalid team name error", err)
			}
		})
	}
}

// TestOIDC_TeamRules covers the rule forms against this provider's
// attributes: every claim of the verified id_token, by dotted path.
func TestOIDC_TeamRules(t *testing.T) {
	user := oidctest.User{
		Subject: "user-1",
		Email:   "Alice@Example.org",
		Groups:  []string{"team:lighthouse", "ethpandaops", "sigp:core"},
		Claims: map[string]any{
			"department":      "eng-consensus",
			"scope":           "openid team-a team-b",
			"level":           3,
			"staff":           true,
			"realm_access":    map[string]any{"roles": []string{"dev", "Ops"}},
			"resource_access": map[string]any{"myapp": map[string]any{"roles": []string{"myapp-admin"}}},
			"profile":         map[string]any{"team": "nested"},
			// Claims the IdP sets itself cannot be overridden from here.
			"sub": "someone-else",
			"iss": "https://evil.example",
		},
	}

	tests := []struct {
		name  string
		rules []protection.TeamRule
		want  []string
	}{
		{"prefix on groups", teamRules(prefixRule), []string{"lighthouse"}},
		{"map on groups with a glob", teamRules(mapRule(map[string][]string{"ethpandaops": {"panda"}, "sigp:*": {"lighthouse"}})), []string{"lighthouse", "panda"}},
		{"regex on a string claim", teamRules(protection.TeamRule{Claim: "department", Regex: "^eng-([a-z0-9-]+)$"}), []string{"consensus"}},
		{"split a string claim", teamRules(protection.TeamRule{Claim: "scope", Split: " ", Prefix: "team-"}), []string{"a", "b"}},
		{"nested path, list", teamRules(protection.TeamRule{Claim: "realm_access.roles", Value: true}), []string{"dev"}},
		{"deeper nested path", teamRules(protection.TeamRule{Claim: "resource_access.myapp.roles", Value: true}), []string{"myapp-admin"}},
		{"nested path, string", teamRules(protection.TeamRule{Claim: "profile.team", Value: true}), []string{"nested"}},
		{"number", teamRules(protection.TeamRule{Claim: "level", Map: map[string][]string{"3": {"senior"}}}), []string{"senior"}},
		{"bool", teamRules(protection.TeamRule{Claim: "staff", Map: map[string][]string{"true": {"panda"}}}), []string{"panda"}},
		{"email: a team for one user", teamRules(protection.TeamRule{Claim: "email", Map: map[string][]string{"alice@example.org": {"lighthouse"}}}), []string{"lighthouse"}},
		{"sub is the verified one", teamRules(protection.TeamRule{Claim: "sub", Map: map[string][]string{"user-1": {"me"}, "someone-else": {"forged"}}}), []string{"me"}},
		{"an object claim is ignored", teamRules(protection.TeamRule{Claim: "realm_access", Value: true}, protection.TeamRule{Claim: "profile", Map: map[string][]string{"*": {"x"}}}), nil},
		{"a missing claim yields nothing", teamRules(protection.TeamRule{Claim: "roles", Value: true}, protection.TeamRule{Claim: "realm_access.groups", Value: true}), nil},
		{
			"several rules",
			teamRules(prefixRule, protection.TeamRule{Claim: "department", Regex: "eng-(.+)"}, protection.TeamRule{Claim: "realm_access.roles", Value: true}),
			[]string{"consensus", "dev", "lighthouse"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			idp := oidctest.New(t, user)
			p := newIdPProvider(t, idp, Config{TeamRules: tc.rules})
			rr, cookie := login(t, p, idp)
			if cookie == nil {
				t.Fatalf("login refused: status %d body %s", rr.Code, rr.Body.String())
			}
			id := identityFor(t, p, cookie)
			if id == nil {
				t.Fatal("session cookie did not authenticate")
			}
			if !slices.Equal(id.Teams, tc.want) {
				t.Errorf("teams: got %v, want %v", id.Teams, tc.want)
			}
		})
	}
}

// TestOIDC_TeamRules_SeeAllGroups pins a property worth knowing: the
// rules read every group of the id_token, not only the ones that got
// the user past allowedGroups. That is harmless for access — a team
// only counts in a grant together with this provider's name — but it
// means the teams claim reports what the IdP says, all of it.
func TestOIDC_TeamRules_SeeAllGroups(t *testing.T) {
	idp := oidctest.New(t, oidctest.User{
		Subject: "u1", Email: "dev@client.example", Groups: []string{"clients", "team:lighthouse", "team:panda"},
	})
	p := newIdPProvider(t, idp, Config{AllowedGroups: []string{"clients"}, TeamRules: teamRules(prefixRule)})
	_, cookie := login(t, p, idp)
	if cookie == nil {
		t.Fatal("login refused")
	}
	if got := identityFor(t, p, cookie).Teams; !slices.Equal(got, []string{"lighthouse", "panda"}) {
		t.Errorf("teams: %v", got)
	}
}

// TestOIDC_TeamRules_CollidingUpstreamNames: groups that differ from a
// privileged team only by case, padding or a look-alike character do not
// become that team.
func TestOIDC_TeamRules_CollidingUpstreamNames(t *testing.T) {
	idp := oidctest.New(t, oidctest.User{
		Subject: "u1", Email: "dev@client.example",
		Groups: []string{
			"team:PANDA", "team:Panda", "team:panda ", "team:panda\u00a0", " team:panda",
			"team:\u212aurtosis", "team:lighthouse",
		},
	})
	p := newIdPProvider(t, idp, Config{TeamRules: teamRules(prefixRule)})
	_, cookie := login(t, p, idp)
	if cookie == nil {
		t.Fatal("login refused")
	}
	if got := identityFor(t, p, cookie).Teams; !slices.Equal(got, []string{"lighthouse"}) {
		t.Errorf("teams: got %v, want only [lighthouse]", got)
	}
}

// TestOIDC_RejectsSessionsOfAnotherDoor: a session opened against one
// IdP does not count once the provider entry — same name, same session
// key — points at another IdP or another client, or was another type of
// provider before.
func TestOIDC_RejectsSessionsOfAnotherDoor(t *testing.T) {
	idp := oidctest.New(t, oidctest.User{Subject: "u1", Email: "alice@example.com", Groups: []string{"team:lighthouse"}})
	p := newIdPProvider(t, idp, Config{TeamRules: teamRules(prefixRule)})

	_, own := login(t, p, idp)
	if own == nil {
		t.Fatal("login refused")
	}
	if id := identityFor(t, p, own); id == nil || !slices.Equal(id.Teams, []string{"lighthouse"}) {
		t.Fatalf("own session: %+v", id)
	}

	payload := session.Payload{Subject: "mallory", Email: "mallory@other.example", Teams: []string{"panda"}}
	for name, door := range map[string]session.Door{
		"another IdP":    session.NewDoor("oidc", "https://other-idp.example", "authenticatoor"),
		"another client": session.NewDoor("oidc", idp.URL, "other-client"),
		"a github door":  session.NewDoor("github", "https://api.github.com"),
		"a basic door":   session.NewDoor("basic"),
	} {
		signed, err := session.Sign(testSessionKey, door, payload, DefaultSessionTTL, p.cfg.Now())
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		if id := identityFor(t, p, &http.Cookie{Name: p.cfg.SessionCookieName, Value: signed}); id != nil {
			t.Errorf("%s: a session of another door authenticated: %+v", name, id)
		}
	}
}

// TestOIDC_GrantMembers: the provider reports which attribute members
// of the grants section an identity satisfies — from a list claim, a
// string claim and a nested path — captures that at login, and keeps
// only the matches in the session.
func TestOIDC_GrantMembers(t *testing.T) {
	idp := oidctest.New(t, oidctest.User{
		Subject: "user-1", Email: "Alice@Example.org",
		Groups: []string{"panda-access", "sigp:core", "Team:Upper"},
		Claims: map[string]any{
			"department":   "eng/consensus:core",
			"realm_access": map[string]any{"roles": []string{"ops"}},
			"level":        3,
		},
	})
	members := []protection.AttributeMember{
		{Attribute: "groups", Value: "panda-access"},
		{Attribute: "groups", Value: "SIGP:CORE"},
		{Attribute: "groups", Value: "not-mine"},
		{Attribute: "department", Value: "eng/consensus:core"},
		{Attribute: "realm_access.roles", Value: "ops"},
		{Attribute: "realm_access.roles", Value: "admin"},
		{Attribute: "level", Value: "3"},
		{Attribute: "email", Value: "alice@example.org"},
		{Attribute: "sub", Value: "user-1"},
		{Attribute: "missing", Value: "x"},
	}
	p := newIdPProvider(t, idp, Config{GrantMembers: members})
	_, cookie := login(t, p, idp)
	if cookie == nil {
		t.Fatal("login refused")
	}
	want := []string{
		"department:eng/consensus:core", "email:alice@example.org", "groups:panda-access",
		"groups:sigp:core", "level:3", "realm_access.roles:ops", "sub:user-1",
	}
	if got := identityFor(t, p, cookie).Matches; !slices.Equal(got, want) {
		t.Errorf("matches:\n got %v\nwant %v", got, want)
	}

	// The matches are fixed at login: a provider that looks for more
	// members finds no more in a running session, one that looks for
	// none still passes on what the session holds (the grants decide
	// what a match is worth).
	more := newIdPProvider(t, idp, Config{GrantMembers: append(slices.Clone(members), protection.AttributeMember{Attribute: "groups", Value: "Team:Upper"})})
	if got := identityFor(t, more, cookie).Matches; !slices.Equal(got, want) {
		t.Errorf("after a member was added: %v", got)
	}
	_, fresh := login(t, more, idp)
	if got := identityFor(t, more, fresh).Matches; !slices.Contains(got, "groups:team:upper") {
		t.Errorf("after a new login: %v", got)
	}

	// The IdP changing its mind does not alter a running session.
	idp.SetUser(oidctest.User{Subject: "user-1", Email: "alice@example.org"})
	if got := identityFor(t, p, cookie).Matches; !slices.Equal(got, want) {
		t.Errorf("after the user left the groups: %v", got)
	}

	// No members configured: nothing is matched or stored.
	none := newIdPProvider(t, idp, Config{})
	_, plain := login(t, none, idp)
	if got := identityFor(t, none, plain).Matches; got != nil {
		t.Errorf("without members: %v", got)
	}
}

// TestOIDC_UnverifiedEmail: the id_token's email is used only when the
// IdP marks it email_verified. Otherwise it is not the subject, is not
// in the session or the token, and is not an attribute for team rules
// or grant members — so a user of an IdP that does not confirm
// addresses cannot take someone else's email-keyed teams or grants.
func TestOIDC_UnverifiedEmail(t *testing.T) {
	rules := teamRules(
		protection.TeamRule{Claim: "email", Map: map[string][]string{"victim@example.org": {"victims-team"}}},
		protection.TeamRule{Claim: "email_verified", Map: map[string][]string{"*": {"has-flag"}}},
		prefixRule,
	)
	members := []protection.AttributeMember{{Attribute: "email", Value: "victim@example.org"}}

	tests := []struct {
		name         string
		verified     any  // value of the email_verified claim; nil: absent
		trust        bool // trustUnverifiedEmail
		wantVerified bool
	}{
		{"email_verified: true", true, false, true},
		{`email_verified: "true" (a string, as some IdPs send)`, "true", false, true},
		{"email_verified: false", false, false, false},
		{"email_verified absent", nil, false, false},
		{`email_verified: "false"`, "false", false, false},
		{`email_verified: "yes"`, "yes", false, false},
		{`email_verified: "TRUE"`, "TRUE", false, false},
		{"email_verified: 1", 1, false, false},
		{"email_verified: an object", map[string]any{"verified": true}, false, false},
		{"email_verified: false, trustUnverifiedEmail", false, true, true},
		{"email_verified absent, trustUnverifiedEmail", nil, true, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			idp := oidctest.New(t, oidctest.User{
				Subject: "idp-sub-42", Email: "victim@example.org", Groups: []string{"team:lighthouse"},
				Claims: map[string]any{"email_verified": tc.verified},
			})
			p := newIdPProvider(t, idp, Config{TeamRules: rules, GrantMembers: members, TrustUnverifiedEmail: tc.trust})

			rr, cookie := login(t, p, idp)
			if cookie == nil {
				t.Fatalf("login refused: status %d body %s", rr.Code, rr.Body.String())
			}
			id := identityFor(t, p, cookie)
			if id == nil {
				t.Fatal("session cookie did not authenticate")
			}

			if tc.wantVerified {
				if id.Subject != "victim@example.org" || id.Email != "victim@example.org" {
					t.Errorf("identity: sub=%q email=%q", id.Subject, id.Email)
				}
				if !slices.Contains(id.Teams, "victims-team") || !slices.Equal(id.Matches, []string{"email:victim@example.org"}) {
					t.Errorf("teams=%v matches=%v", id.Teams, id.Matches)
				}
			} else {
				if id.Subject != "idp-sub-42" || id.Email != "" {
					t.Errorf("identity: sub=%q email=%q, want the IdP subject and no email", id.Subject, id.Email)
				}
				if slices.Contains(id.Teams, "victims-team") || id.Matches != nil {
					t.Errorf("an unverified email reached rules or members: teams=%v matches=%v", id.Teams, id.Matches)
				}
			}
			// Everything else in the token still counts.
			if !slices.Contains(id.Teams, "lighthouse") {
				t.Errorf("teams from groups lost: %v", id.Teams)
			}
		})
	}
}

// newLoggedIdPProvider is newIdPProvider with a logger the test can
// read.
func newLoggedIdPProvider(t *testing.T, idp *oidctest.IdP, cfg Config) (*Provider, *test.Hook) {
	t.Helper()
	log, hook := test.NewNullLogger()
	log.SetLevel(logrus.DebugLevel)

	cfg.IssuerURL = idp.URL
	cfg.PublicURL = "https://auth.test.example"
	cfg.CallbackURL = "https://auth.test.example/oidc/callback"
	cfg.ClientID = "authenticatoor"
	cfg.ClientSecret = "client-secret"
	cfg.SessionKey = testSessionKey

	p := New(log, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := p.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	hook.Reset()
	return p, hook
}

// messages returns the log messages at a level.
func messages(hook *test.Hook, level logrus.Level) []string {
	var out []string
	for _, e := range hook.AllEntries() {
		if e.Level == level {
			out = append(out, e.Message)
		}
	}
	return out
}

// TestOIDC_SubjectKind: the identity says whether its subject is an
// email the IdP verified or the IdP's raw "sub" — at login and from the
// session — and the log says, per login, when an email was dropped and
// when a raw subject looks like an address.
func TestOIDC_SubjectKind(t *testing.T) {
	tests := []struct {
		name        string
		user        oidctest.User
		trust       bool
		wantSubject string
		wantIsEmail bool
		wantInfo    string // a login line at info level; "": none
		wantWarn    string // a login line at warn level; "": none
	}{
		{
			"a verified email is the subject",
			oidctest.User{Subject: "idp-sub-1", Email: "alice@example.org"},
			false, "alice@example.org", true, "", "",
		},
		{
			"an unverified email is dropped, and the log says so",
			oidctest.User{Subject: "idp-sub-1", Email: "alice@example.org", Claims: map[string]any{"email_verified": false}},
			false, "idp-sub-1", false, "the email is dropped and the user is identified by the IdP subject", "",
		},
		{
			"no email at all: nothing to say",
			oidctest.User{Subject: "idp-sub-1"},
			false, "idp-sub-1", false, "", "",
		},
		{
			"a raw subject that looks like an address, without an email",
			oidctest.User{Subject: "alice@example.org"},
			false, "alice@example.org", false, "", "looks like an email address but is not a verified email",
		},
		{
			"a raw subject that looks like an address, with an unverified email",
			oidctest.User{Subject: "alice@example.org", Email: "alice@example.org", Claims: map[string]any{"email_verified": false}},
			false, "alice@example.org", false,
			"the email is dropped", "looks like an email address but is not a verified email",
		},
		{
			"an unverified email that is trusted",
			oidctest.User{Subject: "idp-sub-1", Email: "alice@example.org", Claims: map[string]any{"email_verified": false}},
			true, "alice@example.org", true, "", "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			idp := oidctest.New(t, tc.user)
			p, hook := newLoggedIdPProvider(t, idp, Config{TrustUnverifiedEmail: tc.trust})
			rr, cookie := login(t, p, idp)
			if cookie == nil {
				t.Fatalf("login refused: status %d body %s", rr.Code, rr.Body.String())
			}
			infos, warns := messages(hook, logrus.InfoLevel), messages(hook, logrus.WarnLevel)
			check := func(level string, got []string, want string) {
				switch {
				case want == "" && len(got) != 0:
					t.Errorf("%s lines at login: %v", level, got)
				case want != "" && (len(got) != 1 || !strings.Contains(got[0], want)):
					t.Errorf("%s lines at login: %v, want one containing %q", level, got, want)
				}
			}
			check("info", infos, tc.wantInfo)
			check("warn", warns, tc.wantWarn)

			id := identityFor(t, p, cookie)
			if id == nil {
				t.Fatal("session cookie did not authenticate")
			}
			if id.Subject != tc.wantSubject || id.SubjectIsEmail != tc.wantIsEmail {
				t.Errorf("identity: subject %q SubjectIsEmail %t, want %q / %t",
					id.Subject, id.SubjectIsEmail, tc.wantSubject, tc.wantIsEmail)
			}
			if id.SubjectIsEmail != (id.Email != "") {
				t.Errorf("SubjectIsEmail %t with email %q", id.SubjectIsEmail, id.Email)
			}
		})
	}
}

// TestOIDC_ClaimNamesAreExact: the claims the provider reads from the
// id_token are matched by their exact names, like the attributes of
// team rules are. A claim that differs in case is another claim.
func TestOIDC_ClaimNamesAreExact(t *testing.T) {
	tests := []struct {
		name       string
		user       oidctest.User
		allowed    []string // allowedGroups
		wantLogin  bool
		wantEmail  string
		wantGroups bool // the rule on "groups" found something
	}{
		{
			"Email_Verified: true does not verify",
			oidctest.User{Subject: "idp-sub-1", Email: "alice@example.org", Claims: map[string]any{
				"email_verified": nil, "Email_Verified": true,
			}},
			nil, true, "", false,
		},
		{
			"EMAIL_VERIFIED does not override email_verified: false",
			oidctest.User{Subject: "idp-sub-1", Email: "alice@example.org", Claims: map[string]any{
				"email_verified": false, "EMAIL_VERIFIED": true,
			}},
			nil, true, "", false,
		},
		{
			"Email is not the email",
			oidctest.User{Subject: "idp-sub-1", Claims: map[string]any{"Email": "alice@example.org", "email_verified": true}},
			nil, true, "", false,
		},
		{
			"Groups does not pass allowedGroups",
			oidctest.User{Subject: "idp-sub-1", Email: "alice@example.org", Claims: map[string]any{"Groups": []string{"staff"}}},
			[]string{"staff"}, false, "", false,
		},
		{
			"the exact names work",
			oidctest.User{Subject: "idp-sub-1", Email: "alice@example.org", Groups: []string{"staff", "team:lighthouse"}},
			[]string{"staff"}, true, "alice@example.org", true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			idp := oidctest.New(t, tc.user)
			p := newIdPProvider(t, idp, Config{AllowedGroups: tc.allowed, TeamRules: teamRules(prefixRule)})
			rr, cookie := login(t, p, idp)
			if !tc.wantLogin {
				if cookie != nil || rr.Code != http.StatusForbidden {
					t.Fatalf("login: status %d, cookie %v", rr.Code, cookie)
				}
				return
			}
			if cookie == nil {
				t.Fatalf("login refused: status %d body %s", rr.Code, rr.Body.String())
			}
			id := identityFor(t, p, cookie)
			if id.Email != tc.wantEmail {
				t.Errorf("email: %q, want %q", id.Email, tc.wantEmail)
			}
			if got := slices.Contains(id.Teams, "lighthouse"); got != tc.wantGroups {
				t.Errorf("teams: %v", id.Teams)
			}
		})
	}

	// The verifier itself: the registered claims are exact too.
	var claims idTokenClaims
	if err := claims.UnmarshalJSON([]byte(`{"Sub":"x","ISS":"y","Aud":"z","Exp":1,"Nonce":"n","Name":"m",` +
		`"Email":"e@example.org","Email_Verified":true,"Groups":["g"]}`)); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if claims.Subject != "" || claims.Issuer != "" || claims.Audience != nil || claims.ExpiresAt != nil ||
		claims.Nonce != "" || claims.Name != "" || claims.Email != "" || bool(claims.EmailVerified) || claims.Groups != nil {
		t.Errorf("claims with other spellings were read: %+v", claims)
	}
	if err := claims.UnmarshalJSON([]byte(`{"sub":"x","iss":"y","aud":["z"],"exp":1,"nonce":"n","name":"m",` +
		`"email":"e@example.org","email_verified":true,"groups":["g"]}`)); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if claims.Subject != "x" || claims.Issuer != "y" || !slices.Equal(claims.Audience, []string{"z"}) ||
		claims.ExpiresAt == nil || claims.Nonce != "n" || claims.Name != "m" || claims.Email != "e@example.org" ||
		!bool(claims.EmailVerified) || !slices.Equal(claims.Groups, []string{"g"}) {
		t.Errorf("claims with the exact names were not read: %+v", claims)
	}
}

// TestOIDC_LoginRefusedWhenSessionDoesNotFitACookie: a subject (or an
// email) long enough to push the session cookie over what browsers
// accept does not get a cookie that would be dropped — and with it an
// endless round through the login. The login is refused, and says why.
func TestOIDC_LoginRefusedWhenSessionDoesNotFitACookie(t *testing.T) {
	groups := make([]string, 0, auth.MaxTeams)
	for i := range auth.MaxTeams {
		groups = append(groups, "team:"+fmt.Sprintf("%02d", i)+strings.Repeat("x", 61))
	}
	tests := []struct {
		name   string
		user   oidctest.User
		wantOK bool
	}{
		{"an ordinary user with every team", oidctest.User{Subject: "idp-sub-1", Email: "alice@example.org", Groups: groups}, true},
		{"a 200-byte subject with every team", oidctest.User{Subject: strings.Repeat("s", 200), Groups: groups}, true},
		{"a 4000-byte subject", oidctest.User{Subject: strings.Repeat("s", 4000)}, false},
		{"a 1500-byte subject with every team", oidctest.User{Subject: strings.Repeat("s", 1500), Groups: groups}, false},
		{
			"a 2000-byte verified email",
			oidctest.User{Subject: "idp-sub-1", Email: strings.Repeat("e", 1988) + "@example.org"}, false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			idp := oidctest.New(t, tc.user)
			p, hook := newLoggedIdPProvider(t, idp, Config{TeamRules: teamRules(prefixRule)})
			rr, cookie := login(t, p, idp)
			for _, c := range rr.Result().Cookies() {
				if size := len(c.Name) + len(c.Value); size > session.MaxCookieBytes {
					t.Errorf("cookie %s is %d bytes: a browser drops it", c.Name, size)
				}
			}
			if tc.wantOK {
				if cookie == nil || rr.Code != http.StatusFound {
					t.Fatalf("login: status %d body %s", rr.Code, rr.Body.String())
				}
				if id := identityFor(t, p, cookie); id == nil || len(id.Teams) != auth.MaxTeams {
					t.Errorf("identity: %+v", id)
				}
				return
			}
			if cookie != nil {
				t.Fatal("a session cookie was set")
			}
			if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "too long to be stored in a session cookie") {
				t.Errorf("response: status %d body %q", rr.Code, rr.Body.String())
			}
			if rr.Header().Get("Location") != "" {
				t.Errorf("a refused login redirects to %q", rr.Header().Get("Location"))
			}
			warns := messages(hook, logrus.WarnLevel)
			if len(warns) != 1 || !strings.Contains(warns[0], "login refused: the session does not fit a cookie") {
				t.Errorf("log: %v", warns)
			}
		})
	}
}
