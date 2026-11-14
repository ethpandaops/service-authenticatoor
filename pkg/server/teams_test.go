package server

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"

	"github.com/ethpandaops/service-authenticatoor/pkg/auth"
	"github.com/ethpandaops/service-authenticatoor/pkg/cfaccess"
	"github.com/ethpandaops/service-authenticatoor/pkg/config"
	"github.com/ethpandaops/service-authenticatoor/pkg/issuer"
	"github.com/ethpandaops/service-authenticatoor/pkg/protection"
	"github.com/ethpandaops/service-authenticatoor/pkg/protection/anyauth"
	"github.com/ethpandaops/service-authenticatoor/pkg/protection/basic"
	"github.com/ethpandaops/service-authenticatoor/pkg/protection/cloudflare"
	"github.com/ethpandaops/service-authenticatoor/pkg/protection/oidc"
	"github.com/ethpandaops/service-authenticatoor/pkg/protection/oidc/oidctest"
)

// teamsHarness is a Server built from real providers, the real issuer
// and a real pkg/auth verifier fed from the server's own /jwks.json — the
// same pieces a deployment and a resource server use.
type teamsHarness struct {
	t        *testing.T
	handler  http.Handler
	verifier *auth.JWKSVerifier
	jwksURL  string
	issuer   string
}

// newTeamsHarness starts the given providers and wires them into a
// Server. Each provider gets its own session key, as in main.go.
func newTeamsHarness(t *testing.T, providers ...NamedProvider) *teamsHarness {
	t.Helper()
	return newGrantsHarness(t, nil, "", providers...)
}

// newGrantsHarness is newTeamsHarness with a table of team grants
// (nil: section absent) and an instance-wide services directive.
func newGrantsHarness(
	t *testing.T, teamServices map[string][]string, instanceWide string, providers ...NamedProvider,
) *teamsHarness {
	t.Helper()

	// These tables map a team to its grants. Each becomes a group whose
	// members are that team at every provider of the harness: the tests
	// using them are about the claim, not about which door a team came
	// through.
	var section *issuer.GrantsConfig
	if teamServices != nil {
		section = &issuer.GrantsConfig{}
		for _, team := range slices.Sorted(maps.Keys(teamServices)) {
			members := make([]string, 0, len(providers))
			for _, np := range providers {
				members = append(members, np.Name+"/team:"+team)
			}
			section.Groups = append(section.Groups, issuer.GrantGroup{Members: members, Services: teamServices[team]})
		}
	}
	return newSectionHarness(t, section, instanceWide, providers...)
}

// sectionGrants validates a grants section for providers of these names
// (each accepting any attribute).
func sectionGrants(t *testing.T, section issuer.GrantsConfig, providers ...string) *issuer.ServiceGrants {
	t.Helper()
	described := make([]issuer.Provider, 0, len(providers))
	for _, name := range providers {
		described = append(described, issuer.Provider{Name: name})
	}
	g, err := issuer.NewServiceGrants(section, described)
	if err != nil {
		t.Fatalf("grants: %v", err)
	}
	return g
}

// newSectionHarness is newTeamsHarness with a grants section (nil:
// absent) and an instance-wide services directive.
func newSectionHarness(
	t *testing.T, section *issuer.GrantsConfig, instanceWide string, providers ...NamedProvider,
) *teamsHarness {
	t.Helper()

	var grants *issuer.ServiceGrants
	if section != nil {
		names := make([]string, 0, len(providers))
		for _, np := range providers {
			names = append(names, np.Name)
		}
		grants = sectionGrants(t, *section, names...)
	}

	cfg := &config.Config{
		Listen:             ":0",
		Issuer:             "https://auth.test.example",
		ExternalURL:        "https://auth.test.example",
		Audience:           []string{"test.example"},
		ScopePattern:       "*.test.example",
		TokenTTL:           30 * time.Minute,
		AllowedReturnHosts: []string{"*.test.example"},
		CORS:               config.CORSConfig{AllowedOrigins: []string{"*.test.example"}},
		Signing:            config.SigningConfig{Mode: "rs256"},
	}
	key, err := issuer.GenerateRSAKey()
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	iss, err := issuer.NewRS256Issuer(issuer.Config{
		ActiveKey:       key,
		Issuer:          cfg.Issuer,
		DefaultAudience: cfg.Audience,
		Scope:           cfg.ScopePattern,
		Services:        instanceWide,
		Grants:          grants,
		TTL:             cfg.TokenTTL,
	})
	if err != nil {
		t.Fatalf("newissuer: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	for _, np := range providers {
		if err := np.Provider.Start(ctx); err != nil {
			t.Fatalf("start provider %s: %v", np.Name, err)
		}
	}

	log := logrus.New()
	log.SetOutput(io.Discard)
	s, err := New(Options{
		Config:    cfg,
		Issuer:    iss,
		Providers: providers,
		Log:       log,
		Registry:  prometheus.NewRegistry(),
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	handler := s.routes()

	jwks := httptest.NewServer(handler)
	t.Cleanup(jwks.Close)
	verifier, err := auth.NewJWKSVerifier(ctx, auth.VerifierConfig{
		JWKSURL:          jwks.URL + "/jwks.json",
		ExpectedIssuer:   cfg.Issuer,
		ExpectedAudience: "test.example",
	})
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	return &teamsHarness{
		t: t, handler: handler, verifier: verifier,
		jwksURL: jwks.URL + "/jwks.json", issuer: cfg.Issuer,
	}
}

// rawToken calls /auth/token and returns the token string.
func (h *teamsHarness) rawToken(req *http.Request, cookies ...*http.Cookie) string {
	h.t.Helper()
	rr := h.do(req, cookies...)
	if rr.Code != http.StatusOK {
		h.t.Fatalf("/auth/token: status %d, body %s", rr.Code, rr.Body.String())
	}
	var resp tokenResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		h.t.Fatalf("decode token response: %v", err)
	}
	return resp.Token
}

// serviceVerifier builds the verifier of a resource server that gates on
// its own service name, as spamoor, assertoor and dora do.
func (h *teamsHarness) serviceVerifier(service string) *auth.JWKSVerifier {
	h.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	h.t.Cleanup(cancel)
	v, err := auth.NewJWKSVerifier(ctx, auth.VerifierConfig{
		JWKSURL:          h.jwksURL,
		ExpectedIssuer:   h.issuer,
		ExpectedAudience: "test.example",
		ExpectedService:  service,
	})
	if err != nil {
		h.t.Fatalf("new verifier for %s: %v", service, err)
	}
	return v
}

// do serves one request, carrying the given cookies.
func (h *teamsHarness) do(req *http.Request, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	h.t.Helper()
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	h.handler.ServeHTTP(rr, req)
	return rr
}

// verify checks a token the way a resource server does and returns its
// claims.
func (h *teamsHarness) verify(token string) *auth.Claims {
	h.t.Helper()
	claims, err := h.verifier.Verify(token)
	if err != nil {
		h.t.Fatalf("verify: %v", err)
	}
	return claims
}

// token calls /auth/token and returns the verified claims of the token
// it issued.
func (h *teamsHarness) token(req *http.Request, cookies ...*http.Cookie) *auth.Claims {
	h.t.Helper()
	rr := h.do(req, cookies...)
	if rr.Code != http.StatusOK {
		h.t.Fatalf("/auth/token: status %d, location %q, body %s", rr.Code, rr.Header().Get("Location"), rr.Body.String())
	}
	var resp tokenResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		h.t.Fatalf("decode token response: %v", err)
	}
	return h.verify(resp.Token)
}

func tokenRequest() *http.Request {
	return httptest.NewRequest(http.MethodGet, "/auth/token", nil)
}

// liveCookies returns the cookies a response sets (ignoring deletions).
func liveCookies(rr *httptest.ResponseRecorder) []*http.Cookie {
	var out []*http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.MaxAge >= 0 && c.Value != "" {
			out = append(out, c)
		}
	}
	return out
}

func quietLog() logrus.FieldLogger {
	log := logrus.New()
	log.SetOutput(io.Discard)
	return log
}

// testSessionKey derives a distinct per-provider key, as main.go does.
func testSessionKey(name string) []byte {
	return []byte((name + "-0123456789abcdef0123456789abcdef")[:32])
}

func newBasicProvider(t *testing.T, name string, teams ...string) NamedProvider {
	t.Helper()
	sum := sha1.Sum([]byte("hunter2"))
	file := filepath.Join(t.TempDir(), "htpasswd")
	body := "alice:{SHA}" + base64.StdEncoding.EncodeToString(sum[:]) + "\n"
	if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
		t.Fatalf("write htpasswd: %v", err)
	}
	return NamedProvider{Name: name, Provider: basic.New(quietLog(), basic.Config{
		HtpasswdFile:      file,
		LoginPath:         "/" + name + "/login",
		SessionKey:        testSessionKey(name),
		SessionCookieName: "authenticatoor_" + name + "_session",
		Teams:             teams,
	})}
}

func newCloudflareProvider(name string, teams ...string) NamedProvider {
	return NamedProvider{Name: name, Provider: cloudflare.New(quietLog(), cloudflare.Config{
		VerifyJWT:         false, // trust the header, as behind a trusted ingress
		LoginPath:         "/" + name + "/login",
		SessionKey:        testSessionKey(name),
		SessionCookieName: "authenticatoor_" + name + "_session",
		Teams:             teams,
	})}
}

// prefixRule is the rule the central IdP setup uses: every `team:<slug>`
// group is the team <slug>.
var prefixRule = protection.TeamRule{Claim: "groups", Prefix: "team:"}

// mapRule maps values of the groups claim to teams.
func mapRule(m map[string][]string) protection.TeamRule {
	return protection.TeamRule{Claim: "groups", Map: m}
}

func teamRules(rules ...protection.TeamRule) []protection.TeamRule { return rules }

func newOIDCProvider(idp *oidctest.IdP, name string, cfg oidc.Config) NamedProvider {
	cfg.IssuerURL = idp.URL
	cfg.PublicURL = "https://auth.test.example"
	cfg.CallbackURL = "https://auth.test.example/" + name + "/callback"
	cfg.ClientID = "authenticatoor"
	cfg.ClientSecret = "client-secret"
	cfg.SessionKey = testSessionKey(name)
	cfg.LoginPath = "/" + name + "/login"
	cfg.CallbackPath = "/" + name + "/callback"
	cfg.SessionCookieName = "authenticatoor_" + name + "_session"
	cfg.StateCookieName = "authenticatoor_" + name + "_state"
	return NamedProvider{Name: name, Provider: oidc.New(quietLog(), cfg)}
}

// oidcLogin walks the browser through /<name>/login → IdP → callback and
// returns the session cookie.
func (h *teamsHarness) oidcLogin(idp *oidctest.IdP, name string) *http.Cookie {
	h.t.Helper()
	rr := h.do(httptest.NewRequest(http.MethodGet, "/"+name+"/login?return_to=%2Fauth%2Ftoken", nil))
	if rr.Code != http.StatusFound {
		h.t.Fatalf("oidc login entry: status %d", rr.Code)
	}
	state := liveCookies(rr)
	if len(state) != 1 {
		h.t.Fatalf("oidc login entry cookies: %v", state)
	}
	back := idp.Authorize(h.t, rr.Header().Get("Location"))

	rr = h.do(httptest.NewRequest(http.MethodGet, "/"+name+"/callback?"+back.Encode(), nil), state[0])
	if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/auth/token" {
		h.t.Fatalf("oidc callback: status %d location %q body %s", rr.Code, rr.Header().Get("Location"), rr.Body.String())
	}
	session := liveCookies(rr)
	if len(session) != 1 {
		h.t.Fatalf("oidc callback cookies: %v", session)
	}
	return session[0]
}

// TestTeams_EndToEnd_Basic: login → cookie → /auth/token → verify → teams,
// for the session-cookie path and the ambient Authorization path, and the
// other minting endpoints.
func TestTeams_EndToEnd_Basic(t *testing.T) {
	tests := []struct {
		name   string
		static []string
		want   []string
	}{
		{"static teams", []string{"panda", "ops"}, []string{"ops", "panda"}},
		{"no teams", nil, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newTeamsHarness(t, newBasicProvider(t, "htpasswd", tc.static...))

			// Interactive login mints the session cookie.
			login := httptest.NewRequest(http.MethodGet, "/htpasswd/login?return_to=%2Fauth%2Ftoken", nil)
			login.SetBasicAuth("alice", "hunter2")
			rr := h.do(login)
			cookies := liveCookies(rr)
			if rr.Code != http.StatusFound || len(cookies) != 1 {
				t.Fatalf("login: status %d cookies %v", rr.Code, cookies)
			}

			// Session cookie → /auth/token.
			claims := h.token(tokenRequest(), cookies[0])
			if claims.Subject != "alice" {
				t.Errorf("sub: %q", claims.Subject)
			}
			if !slices.Equal(claims.Teams, tc.want) {
				t.Errorf("session token teams: got %v, want %v", claims.Teams, tc.want)
			}
			if got, want := claims.HasTeam("panda"), slices.Contains(tc.want, "panda"); got != want {
				t.Errorf("HasTeam(panda) = %t, want %t", got, want)
			}

			// A refresh on the same session carries the same teams.
			if again := h.token(tokenRequest(), cookies[0]); !slices.Equal(again.Teams, tc.want) {
				t.Errorf("refreshed token teams: got %v, want %v", again.Teams, tc.want)
			}

			// Ambient Authorization header → /auth/token.
			ambient := tokenRequest()
			ambient.SetBasicAuth("alice", "hunter2")
			if claims := h.token(ambient); !slices.Equal(claims.Teams, tc.want) {
				t.Errorf("ambient token teams: got %v, want %v", claims.Teams, tc.want)
			}

			// /auth/login redirect.
			rr = h.do(httptest.NewRequest(http.MethodGet,
				"/auth/login?return_to="+url.QueryEscape("https://app.test.example/"), nil), cookies[0])
			if rr.Code != http.StatusFound {
				t.Fatalf("/auth/login: status %d", rr.Code)
			}
			loc, err := url.Parse(rr.Header().Get("Location"))
			if err != nil {
				t.Fatalf("parse location: %v", err)
			}
			frag, err := url.ParseQuery(loc.Fragment)
			if err != nil {
				t.Fatalf("parse fragment: %v", err)
			}
			if claims := h.verify(frag.Get("auth_token")); !slices.Equal(claims.Teams, tc.want) {
				t.Errorf("/auth/login token teams: got %v, want %v", claims.Teams, tc.want)
			}

			// /auth/embed.
			rr = h.do(httptest.NewRequest(http.MethodGet,
				"/auth/embed?target_origin="+url.QueryEscape("https://app.test.example"), nil), cookies[0])
			if rr.Code != http.StatusOK {
				t.Fatalf("/auth/embed: status %d", rr.Code)
			}
			if claims := h.verify(embeddedToken(t, rr.Body.String())); !slices.Equal(claims.Teams, tc.want) {
				t.Errorf("/auth/embed token teams: got %v, want %v", claims.Teams, tc.want)
			}

			// /auth/userinfo mirrors the claim, always as an array.
			rr = h.do(httptest.NewRequest(http.MethodGet, "/auth/userinfo", nil), cookies[0])
			if rr.Code != http.StatusOK {
				t.Fatalf("/auth/userinfo: status %d", rr.Code)
			}
			var info struct {
				Teams *[]string `json:"teams"`
			}
			if err := json.Unmarshal(rr.Body.Bytes(), &info); err != nil {
				t.Fatalf("decode userinfo: %v", err)
			}
			if info.Teams == nil {
				t.Fatalf("userinfo has no teams array: %s", rr.Body.String())
			}
			if len(*info.Teams) != len(tc.want) || (len(tc.want) > 0 && !slices.Equal(*info.Teams, tc.want)) {
				t.Errorf("userinfo teams: got %v, want %v", *info.Teams, tc.want)
			}
		})
	}
}

// embeddedToken pulls the token out of the /auth/embed page's JSON blob.
func embeddedToken(t *testing.T, page string) string {
	t.Helper()
	const open = `<script id="d" type="application/json">`
	start := strings.Index(page, open)
	if start < 0 {
		t.Fatalf("embed page has no payload: %s", page)
	}
	rest := page[start+len(open):]
	end := strings.Index(rest, "</script>")
	if end < 0 {
		t.Fatalf("embed page payload is not closed: %s", page)
	}
	var payload struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal([]byte(rest[:end]), &payload); err != nil {
		t.Fatalf("decode embed payload: %v", err)
	}
	return payload.Token
}

// TestTeams_EndToEnd_AnyAuth: the dev provider hands out its configured
// teams and nothing a client supplies.
func TestTeams_EndToEnd_AnyAuth(t *testing.T) {
	h := newTeamsHarness(t, NamedProvider{Name: "anyauth", Provider: anyauth.New(quietLog(), anyauth.Config{
		LoginPath: "/anyauth/login",
		Teams:     []string{"dev"},
	})})

	form := url.Values{"user": {"alice"}, "return_to": {"/auth/token"}, "teams": {"panda"}}
	login := httptest.NewRequest(http.MethodPost, "/anyauth/login", strings.NewReader(form.Encode()))
	login.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := h.do(login)
	cookies := liveCookies(rr)
	if rr.Code != http.StatusFound || len(cookies) != 1 {
		t.Fatalf("login: status %d cookies %v", rr.Code, cookies)
	}

	claims := h.token(tokenRequest(), cookies[0])
	if claims.Subject != "alice" || !slices.Equal(claims.Teams, []string{"dev"}) {
		t.Errorf("token: sub=%q teams=%v", claims.Subject, claims.Teams)
	}
}

// TestTeams_EndToEnd_OIDC: login through the fake IdP → session cookie →
// /auth/token → verify → teams from the id_token groups plus the static
// list.
func TestTeams_EndToEnd_OIDC(t *testing.T) {
	tests := []struct {
		name   string
		cfg    oidc.Config
		groups []string
		want   []string
	}{
		{
			"central IdP team: groups",
			oidc.Config{TeamRules: teamRules(prefixRule)},
			[]string{"team:lighthouse", "team:geth", "team:Reth", "unrelated"},
			[]string{"geth", "lighthouse"},
		},
		{
			"prefix, group map and static together",
			oidc.Config{
				Teams:     []string{"devnet"},
				TeamRules: teamRules(prefixRule, mapRule(map[string][]string{"ethpandaops": {"panda"}})),
			},
			[]string{"team:lighthouse", "ethpandaops"},
			[]string{"devnet", "lighthouse", "panda"},
		},
		{"team feature off", oidc.Config{}, []string{"team:lighthouse"}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			idp := oidctest.New(t, oidctest.User{Subject: "u1", Email: "alice@example.com", Groups: tc.groups})
			h := newTeamsHarness(t, newOIDCProvider(idp, "oidc", tc.cfg))

			session := h.oidcLogin(idp, "oidc")

			claims := h.token(tokenRequest(), session)
			if claims.Subject != "alice@example.com" || claims.Email != "alice@example.com" {
				t.Errorf("identity: sub=%q email=%q", claims.Subject, claims.Email)
			}
			if !slices.Equal(claims.Teams, tc.want) {
				t.Errorf("teams: got %v, want %v", claims.Teams, tc.want)
			}

			// The IdP changing its mind does not alter a running session:
			// a refresh carries the teams captured at login.
			idp.SetUser(oidctest.User{Subject: "u1", Email: "alice@example.com", Groups: []string{"team:panda"}})
			if again := h.token(tokenRequest(), session); !slices.Equal(again.Teams, tc.want) {
				t.Errorf("refreshed teams: got %v, want %v", again.Teams, tc.want)
			}
		})
	}
}

// TestTeams_WinnersTeamsOnly: with several providers configured, a token
// carries the teams of the provider that authenticated the request —
// never a union with another provider's, whatever other credentials the
// request holds.
func TestTeams_WinnersTeamsOnly(t *testing.T) {
	idp := oidctest.New(t, oidctest.User{
		Subject: "u1", Email: "dev@lighthouse.example", Groups: []string{"team:lighthouse"},
	})
	h := newTeamsHarness(t,
		newCloudflareProvider("cfaccess", "panda"),
		newOIDCProvider(idp, "oidc", oidc.Config{TeamRules: teamRules(prefixRule)}),
		newBasicProvider(t, "htpasswd", "ops"),
	)
	oidcSession := h.oidcLogin(idp, "oidc")

	withCF := func(r *http.Request) *http.Request {
		r.Header.Set(cloudflare.DefaultUserHeader, "staff@ethpandaops.io")
		return r
	}
	withBasic := func(r *http.Request) *http.Request {
		r.SetBasicAuth("alice", "hunter2")
		return r
	}

	tests := []struct {
		name    string
		req     *http.Request
		cookies []*http.Cookie
		wantSub string
		want    []string
	}{
		{"cloudflare alone", withCF(tokenRequest()), nil, "staff@ethpandaops.io", []string{"panda"}},
		{"oidc alone", tokenRequest(), []*http.Cookie{oidcSession}, "dev@lighthouse.example", []string{"lighthouse"}},
		{"basic alone", withBasic(tokenRequest()), nil, "alice", []string{"ops"}},
		{
			"cloudflare wins over an oidc session",
			withCF(tokenRequest()), []*http.Cookie{oidcSession},
			"staff@ethpandaops.io", []string{"panda"},
		},
		{
			"oidc session wins over basic credentials",
			withBasic(tokenRequest()), []*http.Cookie{oidcSession},
			"dev@lighthouse.example", []string{"lighthouse"},
		},
		{
			"all three credentials: the first provider's teams only",
			withBasic(withCF(tokenRequest())), []*http.Cookie{oidcSession},
			"staff@ethpandaops.io", []string{"panda"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			claims := h.token(tc.req, tc.cookies...)
			if claims.Subject != tc.wantSub {
				t.Errorf("sub: got %q, want %q", claims.Subject, tc.wantSub)
			}
			if !slices.Equal(claims.Teams, tc.want) {
				t.Errorf("teams: got %v, want %v", claims.Teams, tc.want)
			}
		})
	}

	// The Cloudflare machine alias is ambient-only: its teams are the
	// Cloudflare provider's even with the oidc session attached.
	rr := h.do(withCF(httptest.NewRequest(http.MethodGet, "/cfaccess/token", nil)), oidcSession)
	if rr.Code != http.StatusOK {
		t.Fatalf("/cfaccess/token: status %d", rr.Code)
	}
	var resp tokenResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if claims := h.verify(resp.Token); !slices.Equal(claims.Teams, []string{"panda"}) {
		t.Errorf("/cfaccess/token teams: got %v, want [panda]", claims.Teams)
	}
}

// TestTeams_NothingFromTheRequest: teams never come from request
// parameters, client-settable headers, cookies of the client's making, a
// session cookie replayed under another provider's name, or a cookie
// that fails verification.
func TestTeams_NothingFromTheRequest(t *testing.T) {
	idp := oidctest.New(t, oidctest.User{
		Subject: "u1", Email: "dev@lighthouse.example", Groups: []string{"team:lighthouse"},
	})
	h := newTeamsHarness(t,
		newBasicProvider(t, "staff", "panda"),
		newOIDCProvider(idp, "oidc", oidc.Config{TeamRules: teamRules(prefixRule)}),
	)
	session := h.oidcLogin(idp, "oidc")

	// Every way of asking for more, on an otherwise valid request.
	greedy := httptest.NewRequest(http.MethodGet, "/auth/token?teams=panda&team=panda&groups=team:panda", nil)
	greedy.Header.Set("X-Teams", "panda")
	greedy.Header.Set("X-Auth-Request-Groups", "team:panda")
	greedy.Header.Set("X-Forwarded-Groups", "team:panda")
	greedy.Header.Set(cloudflare.DefaultUserHeader, "staff@ethpandaops.io") // no cloudflare provider here
	claims := h.token(greedy, session, &http.Cookie{Name: "teams", Value: "panda"})
	if !slices.Equal(claims.Teams, []string{"lighthouse"}) {
		t.Errorf("teams: got %v, want [lighthouse]", claims.Teams)
	}

	unauthenticated := func(what string, cookies ...*http.Cookie) {
		t.Helper()
		rr := h.do(tokenRequest(), cookies...)
		if rr.Code == http.StatusOK {
			t.Errorf("%s: a token was issued: %s", what, rr.Body.String())
		}
		if rr.Code != http.StatusFound || !strings.HasPrefix(rr.Header().Get("Location"), "/login?") {
			t.Errorf("%s: status %d location %q, want a redirect to /login", what, rr.Code, rr.Header().Get("Location"))
		}
	}

	// The oidc session replayed as the staff provider's cookie: the
	// per-provider key rejects it, so the static [panda] is out of reach.
	unauthenticated("cookie replayed under another provider",
		&http.Cookie{Name: "authenticatoor_staff_session", Value: session.Value})

	// Tampered: payload edited, signature kept.
	parts := strings.Split(session.Value, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode session payload: %v", err)
	}
	edited := strings.Replace(string(payload), `"lighthouse"`, `"lighthouse","panda"`, 1)
	if edited == string(payload) {
		t.Fatalf("session payload has no teams to edit: %s", payload)
	}
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(edited)) + "." + parts[2]
	unauthenticated("tampered session cookie",
		&http.Cookie{Name: session.Name, Value: tampered})

	// Truncated signature.
	unauthenticated("session cookie with a broken signature",
		&http.Cookie{Name: session.Name, Value: session.Value[:len(session.Value)-4]})

	// And the genuine cookie still works afterwards.
	if claims := h.token(tokenRequest(), session); !slices.Equal(claims.Teams, []string{"lighthouse"}) {
		t.Errorf("genuine session teams: got %v", claims.Teams)
	}
}

// TestTeams_FakeProviderIdentityReachesToken pins the server's side of
// the contract in isolation: whatever Teams the winning provider's
// Identity carries is what the issuer is given.
func TestTeams_FakeProviderIdentityReachesToken(t *testing.T) {
	prov := &teamsFakeProvider{teams: []string{"lighthouse", "panda"}}
	h := newTeamsHarness(t, NamedProvider{Name: "fake", Provider: prov})

	claims := h.token(tokenRequest())
	if !slices.Equal(claims.Teams, []string{"lighthouse", "panda"}) {
		t.Errorf("teams: got %v", claims.Teams)
	}

	prov.teams = nil
	if claims := h.token(tokenRequest()); claims.Teams != nil {
		t.Errorf("teams: got %v, want the claim omitted", claims.Teams)
	}
}

// teamsFakeProvider authenticates every request as one fixed identity.
type teamsFakeProvider struct {
	fakeProvider
	teams []string
}

func (p *teamsFakeProvider) Authenticate(_ context.Context, _ *http.Request) (protection.Outcome, error) {
	return protection.Outcome{Identity: &protection.Identity{
		Subject: "alice@example.com",
		Email:   "alice@example.com",
		Teams:   p.teams,
	}}, nil
}

// TestGrants_EndToEnd: two doors — Cloudflare Access for staff,
// OIDC for client teams — with a grant table. Login → /auth/token →
// Verify with ExpectedService: accepted for a granted service, rejected
// for every other one, including one no grant mentions.
func TestGrants_EndToEnd(t *testing.T) {
	grants := map[string][]string{
		"panda":      {"all"},
		"lighthouse": {"dora"},
		"geth":       {"dora", "spamoor"},
	}
	services := []string{"dora", "spamoor", "assertoor", "buildoor"}

	tests := []struct {
		name         string
		teamServices map[string][]string
		instanceWide string
		groups       []string // id_token groups of the OIDC user; nil: come in through Cloudflare
		wantClaim    string
		wantAllowed  []string
	}{
		{"staff through cloudflare: everything", grants, "", nil, "+all", services},
		{"lighthouse: its one service", grants, "", []string{"team:lighthouse"}, "-all,+dora", []string{"dora"}},
		{
			"two teams: the union", grants, "", []string{"team:lighthouse", "team:geth"},
			"-all,+dora,+spamoor", []string{"dora", "spamoor"},
		},
		{"a team without a grant: nothing", grants, "", []string{"team:reth"}, "-all", nil},
		{"no teams at all: nothing", grants, "", []string{}, "-all", nil},
		{
			"instance-wide directive bounds staff", grants, "+all,-spamoor", nil,
			"+all,-spamoor", []string{"dora", "assertoor", "buildoor"},
		},
		{
			"instance-wide directive bounds a team", grants, "+all,-spamoor", []string{"team:geth"},
			"-all,+dora", []string{"dora"},
		},
		{"section absent: unchanged, every service", nil, "", []string{"team:lighthouse"}, "", services},
		{
			"section absent: the instance-wide directive as before", nil, "+all,-spamoor", []string{"team:lighthouse"},
			"+all,-spamoor", []string{"dora", "assertoor", "buildoor"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			idp := oidctest.New(t, oidctest.User{Subject: "u1", Email: "dev@client.example", Groups: tc.groups})
			h := newGrantsHarness(t, tc.teamServices, tc.instanceWide,
				newCloudflareProvider("cfaccess", "panda"),
				newOIDCProvider(idp, "oidc", oidc.Config{TeamRules: teamRules(prefixRule)}),
			)

			var token string
			if tc.groups == nil {
				req := tokenRequest()
				req.Header.Set(cloudflare.DefaultUserHeader, "staff@ethpandaops.io")
				token = h.rawToken(req)
			} else {
				token = h.rawToken(tokenRequest(), h.oidcLogin(idp, "oidc"))
			}

			// The user is authenticated either way: the token itself is
			// valid for a verifier that does not gate on a service.
			claims := h.verify(token)
			if claims.Services != tc.wantClaim {
				t.Errorf("services claim: got %q, want %q", claims.Services, tc.wantClaim)
			}

			for _, service := range services {
				_, err := h.serviceVerifier(service).Verify(token)
				if want := slices.Contains(tc.wantAllowed, service); (err == nil) != want {
					t.Errorf("Verify with ExpectedService=%q: err=%v, want accepted=%t", service, err, want)
				}
			}
		})
	}
}

// TestGrants_EveryMintingEndpoint: the grant applies wherever a
// token is minted — /auth/token, /auth/login, /auth/embed and the
// Cloudflare machine alias.
func TestGrants_EveryMintingEndpoint(t *testing.T) {
	idp := oidctest.New(t, oidctest.User{
		Subject: "u1", Email: "dev@client.example", Groups: []string{"team:lighthouse"},
	})
	h := newGrantsHarness(t, map[string][]string{"panda": {"all"}, "lighthouse": {"dora"}}, "",
		newCloudflareProvider("cfaccess", "panda"),
		newOIDCProvider(idp, "oidc", oidc.Config{TeamRules: teamRules(prefixRule)}),
	)
	session := h.oidcLogin(idp, "oidc")

	if got := h.verify(h.rawToken(tokenRequest(), session)).Services; got != "-all,+dora" {
		t.Errorf("/auth/token: %q", got)
	}

	rr := h.do(httptest.NewRequest(http.MethodGet,
		"/auth/login?return_to="+url.QueryEscape("https://app.test.example/"), nil), session)
	loc, err := url.Parse(rr.Header().Get("Location"))
	if err != nil || rr.Code != http.StatusFound {
		t.Fatalf("/auth/login: status %d err %v", rr.Code, err)
	}
	frag, err := url.ParseQuery(loc.Fragment)
	if err != nil {
		t.Fatalf("parse fragment: %v", err)
	}
	if got := h.verify(frag.Get("auth_token")).Services; got != "-all,+dora" {
		t.Errorf("/auth/login: %q", got)
	}

	rr = h.do(httptest.NewRequest(http.MethodGet,
		"/auth/embed?target_origin="+url.QueryEscape("https://app.test.example"), nil), session)
	if rr.Code != http.StatusOK {
		t.Fatalf("/auth/embed: status %d", rr.Code)
	}
	if got := h.verify(embeddedToken(t, rr.Body.String())).Services; got != "-all,+dora" {
		t.Errorf("/auth/embed: %q", got)
	}

	alias := httptest.NewRequest(http.MethodGet, "/cfaccess/token", nil)
	alias.Header.Set(cloudflare.DefaultUserHeader, "staff@ethpandaops.io")
	rr = h.do(alias, session)
	if rr.Code != http.StatusOK {
		t.Fatalf("/cfaccess/token: status %d", rr.Code)
	}
	var resp tokenResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := h.verify(resp.Token).Services; got != "+all" {
		t.Errorf("/cfaccess/token: %q", got)
	}
}

// TestGrants_FollowCurrentConfig: the grant is computed at every
// mint from the config in force, not captured in the session — the same
// session cookie yields a different services claim after the table
// changes (the teams, captured at login, stay).
func TestGrants_FollowCurrentConfig(t *testing.T) {
	idp := oidctest.New(t, oidctest.User{
		Subject: "u1", Email: "dev@client.example", Groups: []string{"team:lighthouse"},
	})
	provider := func() NamedProvider {
		return newOIDCProvider(idp, "oidc", oidc.Config{TeamRules: teamRules(prefixRule)})
	}

	before := newGrantsHarness(t, map[string][]string{"lighthouse": {"dora"}}, "", provider())
	session := before.oidcLogin(idp, "oidc")
	if got := before.verify(before.rawToken(tokenRequest(), session)).Services; got != "-all,+dora" {
		t.Fatalf("before: %q", got)
	}

	tests := []struct {
		name         string
		teamServices map[string][]string
		want         string
	}{
		{"grant widened", map[string][]string{"lighthouse": {"dora", "spamoor"}}, "-all,+dora,+spamoor"},
		{"grant revoked", map[string][]string{"lighthouse": {}}, "-all"},
		{"section removed", nil, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			after := newGrantsHarness(t, tc.teamServices, "", provider())
			claims := after.verify(after.rawToken(tokenRequest(), session))
			if claims.Services != tc.want {
				t.Errorf("services: got %q, want %q", claims.Services, tc.want)
			}
			if !slices.Equal(claims.Teams, []string{"lighthouse"}) {
				t.Errorf("teams: %v", claims.Teams)
			}
		})
	}
}

// TestGrants_Features_EndToEnd: login → /auth/token → Verify with
// ExpectedService → HasFeature, for a team with the bare service, one
// with a feature of it, and the internal team with everything. A
// resource server checks "roll" as a privileged (default-deny) feature
// and "view-logs" as an ordinary (default-allow) one.
func TestGrants_Features_EndToEnd(t *testing.T) {
	grants := map[string][]string{
		"panda":      {"all:all"},
		"lighthouse": {"dora"},
		"geth":       {"dora:roll"},
	}

	tests := []struct {
		name      string
		groups    []string // id_token groups; nil: come in through Cloudflare (team panda)
		wantClaim string
		wantUse   bool // dora's verifier accepts the token
		wantRoll  bool // default-deny feature
		wantHold  bool // another default-deny feature
		wantLogs  bool // default-allow feature
		wantOther bool // spamoor's verifier accepts the token
	}{
		{"team with the bare service", []string{"team:lighthouse"}, "-all,+dora", true, false, false, true, false},
		{"team with a feature", []string{"team:geth"}, "-all,+dora,+dora:roll", true, true, false, true, false},
		{"both teams", []string{"team:geth", "team:lighthouse"}, "-all,+dora,+dora:roll", true, true, false, true, false},
		{"the internal team: everything", nil, "+all,+all:all", true, true, true, true, true},
		{"a team without a grant", []string{"team:reth"}, "-all", false, false, false, false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			idp := oidctest.New(t, oidctest.User{Subject: "u1", Email: "dev@client.example", Groups: tc.groups})
			h := newGrantsHarness(t, grants, "",
				newCloudflareProvider("cfaccess", "panda"),
				newOIDCProvider(idp, "oidc", oidc.Config{TeamRules: teamRules(prefixRule)}),
			)

			var token string
			if tc.groups == nil {
				req := tokenRequest()
				req.Header.Set(cloudflare.DefaultUserHeader, "staff@ethpandaops.io")
				token = h.rawToken(req)
			} else {
				token = h.rawToken(tokenRequest(), h.oidcLogin(idp, "oidc"))
			}
			if got := h.verify(token).Services; got != tc.wantClaim {
				t.Errorf("services claim: got %q, want %q", got, tc.wantClaim)
			}

			// The service gate first, as every resource server has it.
			claims, err := h.serviceVerifier("dora").Verify(token)
			if (err == nil) != tc.wantUse {
				t.Fatalf("dora Verify: err=%v, want accepted=%t", err, tc.wantUse)
			}
			if _, err := h.serviceVerifier("spamoor").Verify(token); (err == nil) != tc.wantOther {
				t.Errorf("spamoor Verify: err=%v, want accepted=%t", err, tc.wantOther)
			}
			if !tc.wantUse {
				// Rejected at the gate; the feature checks agree anyway.
				claims = h.verify(token)
			}

			if got := claims.HasFeature("dora", "roll", auth.FeatureDefaultDeny); got != tc.wantRoll {
				t.Errorf("HasFeature(dora, roll, deny) = %t, want %t", got, tc.wantRoll)
			}
			if got := claims.HasFeature("dora", "hold", auth.FeatureDefaultDeny); got != tc.wantHold {
				t.Errorf("HasFeature(dora, hold, deny) = %t, want %t", got, tc.wantHold)
			}
			if got := claims.HasFeature("dora", "view-logs", auth.FeatureDefaultAllow); got != tc.wantLogs {
				t.Errorf("HasFeature(dora, view-logs, allow) = %t, want %t", got, tc.wantLogs)
			}
			if got := claims.HasFeature("dora", auth.FeatureBasic, auth.FeatureDefaultDeny); got != tc.wantUse {
				t.Errorf("HasFeature(dora, basic) = %t, want %t", got, tc.wantUse)
			}

			// And through the middleware a resource server would mount.
			for _, check := range []struct {
				feature string
				def     auth.FeatureDefault
				want    bool
			}{
				{"roll", auth.FeatureDefaultDeny, tc.wantRoll},
				{"view-logs", auth.FeatureDefaultAllow, tc.wantLogs},
			} {
				handler := auth.Middleware(h.serviceVerifier("dora"))(auth.RequireFeature(
					"dora", check.feature, check.def,
					func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) },
				))
				req := httptest.NewRequest(http.MethodPost, "https://dora.test.example/api", nil)
				req.Header.Set("Authorization", "Bearer "+token)
				rr := httptest.NewRecorder()
				handler.ServeHTTP(rr, req)

				want := http.StatusOK
				switch {
				case !tc.wantUse:
					want = http.StatusUnauthorized // refused by the service gate
				case !check.want:
					want = http.StatusForbidden
				}
				if rr.Code != want {
					t.Errorf("RequireFeature(%s): status %d, want %d", check.feature, rr.Code, want)
				}
			}
		})
	}
}

// TestGrants_Features_AbsentSection: without a grants section the
// token has no services claim, which means no constraint — every
// feature is allowed, in both modes.
func TestGrants_Features_AbsentSection(t *testing.T) {
	h := newGrantsHarness(t, nil, "", newCloudflareProvider("cfaccess", "panda"))
	req := tokenRequest()
	req.Header.Set(cloudflare.DefaultUserHeader, "staff@ethpandaops.io")

	claims, err := h.serviceVerifier("dora").Verify(h.rawToken(req))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Services != "" {
		t.Fatalf("services claim: %q", claims.Services)
	}
	if !claims.HasFeature("dora", "roll", auth.FeatureDefaultDeny) ||
		!claims.HasFeature("dora", "view-logs", auth.FeatureDefaultAllow) {
		t.Error("a token without a services claim has no constraint")
	}
}

// TestTeamRules_EndToEnd: one instance with the three kinds of door,
// each resolving teams through its own rules from its own attributes;
// login → /auth/token → verify → teams.
func TestTeamRules_EndToEnd(t *testing.T) {
	idp := oidctest.New(t, oidctest.User{
		Subject: "u1",
		Email:   "alice@client.example",
		Groups:  []string{"team:lighthouse", "team:panda", "team:PANDA", "clients"},
		Claims:  map[string]any{"realm_access": map[string]any{"roles": []string{"validator-ops"}}},
	})

	cf := NamedProvider{Name: "cfaccess", Provider: cloudflare.New(quietLog(), cloudflare.Config{
		VerifyJWT:         false,
		LoginPath:         "/cfaccess/login",
		SessionKey:        testSessionKey("cfaccess"),
		SessionCookieName: "authenticatoor_cfaccess_session",
		TeamRules: []protection.TeamRule{
			{Claim: "principal", Map: map[string][]string{"user": {"panda"}}},
		},
	})}
	oidcDoor := newOIDCProvider(idp, "oidc", oidc.Config{
		TeamRules: teamRules(
			prefixRule,
			protection.TeamRule{Claim: "realm_access.roles", Value: true},
			protection.TeamRule{Claim: "email", Map: map[string][]string{"alice@client.example": {"geth"}}},
		),
	})
	sum := sha1.Sum([]byte("hunter2"))
	htpasswd := filepath.Join(t.TempDir(), "htpasswd")
	if err := os.WriteFile(htpasswd, []byte("alice:{SHA}"+base64.StdEncoding.EncodeToString(sum[:])+"\n"), 0o600); err != nil {
		t.Fatalf("write htpasswd: %v", err)
	}
	basicDoor := NamedProvider{Name: "htpasswd", Provider: basic.New(quietLog(), basic.Config{
		HtpasswdFile:      htpasswd,
		LoginPath:         "/htpasswd/login",
		SessionKey:        testSessionKey("htpasswd"),
		SessionCookieName: "authenticatoor_htpasswd_session",
		TeamRules:         []protection.TeamRule{{Claim: "username", Map: map[string][]string{"alice": {"ops"}}}},
	})}

	h := newTeamsHarness(t, cf, oidcDoor, basicDoor)

	staff := tokenRequest()
	staff.Header.Set(cloudflare.DefaultUserHeader, "staff@ethpandaops.io")
	if claims := h.token(staff); !slices.Equal(claims.Teams, []string{"panda"}) {
		t.Errorf("cloudflare: teams %v", claims.Teams)
	}

	session := h.oidcLogin(idp, "oidc")
	claims := h.token(tokenRequest(), session)
	// The teams claim reports what the IdP says, "panda" included; what
	// that is worth is for the grants to decide, by provider.
	if want := []string{"geth", "lighthouse", "panda", "validator-ops"}; !slices.Equal(claims.Teams, want) {
		t.Errorf("oidc: teams %v, want %v", claims.Teams, want)
	}

	// Each door's rules see only that door's attributes: the oidc
	// session's groups do not reach the basic provider's rules, and a
	// request cannot name attributes itself.
	basicReq := httptest.NewRequest(http.MethodGet, "/auth/token?username=root&groups=team:panda", nil)
	basicReq.SetBasicAuth("alice", "hunter2")
	basicReq.Header.Set("X-Username", "root")
	if claims := h.token(basicReq); !slices.Equal(claims.Teams, []string{"ops"}) {
		t.Errorf("basic: teams %v", claims.Teams)
	}
}

// TestGrants_ProviderQualified_EndToEnd is the split between identity
// and access, through the real handlers: three doors whose identities
// carry the same team name, the same user id and the same attribute
// value; the grants name one door each. Login → /auth/token → verify →
// HasFeature.
func TestGrants_ProviderQualified_EndToEnd(t *testing.T) {
	idp := oidctest.New(t, oidctest.User{
		Subject: "u1", Email: "alice@example.org", Groups: []string{"team:panda", "panda-access"},
	})

	section := issuer.GrantsConfig{Groups: []issuer.GrantGroup{
		{Name: "staff", Members: []string{"cfaccess/team:panda"}, Services: []string{"all:all"}},
		{Name: "alice", Members: []string{"oidc/user:Alice@Example.org"}, Services: []string{"dora:reindex"}},
		{Name: "internal", Members: []string{"oidc/groups:panda-access"}, Services: []string{"assertoor"}},
		{Name: "htpasswd-alice", Members: []string{"htpasswd/username:alice@example.org"}, Services: []string{"spamoor"}},
	}}
	grants := sectionGrants(t, section, "cfaccess", "oidc", "htpasswd")

	// htpasswd users named like the OIDC user's email and like the IdP
	// group; an htpasswd rule that hands out the team "panda" too.
	sum := sha1.Sum([]byte("hunter2"))
	htpasswd := filepath.Join(t.TempDir(), "htpasswd")
	hash := ":{SHA}" + base64.StdEncoding.EncodeToString(sum[:]) + "\n"
	if err := os.WriteFile(htpasswd, []byte("alice@example.org"+hash+"panda-access"+hash), 0o600); err != nil {
		t.Fatalf("write htpasswd: %v", err)
	}
	basicDoor := NamedProvider{Name: "htpasswd", Provider: basic.New(quietLog(), basic.Config{
		HtpasswdFile:      htpasswd,
		LoginPath:         "/htpasswd/login",
		SessionKey:        testSessionKey("htpasswd"),
		SessionCookieName: "authenticatoor_htpasswd_session",
		Teams:             []string{"panda"},
		GrantMembers:      grants.AttributeMembers("htpasswd"),
	})}
	cfDoor := NamedProvider{Name: "cfaccess", Provider: cloudflare.New(quietLog(), cloudflare.Config{
		VerifyJWT:         false,
		LoginPath:         "/cfaccess/login",
		SessionKey:        testSessionKey("cfaccess"),
		SessionCookieName: "authenticatoor_cfaccess_session",
		Teams:             []string{"panda"},
		GrantMembers:      grants.AttributeMembers("cfaccess"),
	})}
	oidcDoor := newOIDCProvider(idp, "oidc", oidc.Config{
		TeamRules:    teamRules(prefixRule),
		GrantMembers: grants.AttributeMembers("oidc"),
	})

	h := newSectionHarness(t, &section, "", cfDoor, oidcDoor, basicDoor)

	cfReq := func(email string) *http.Request {
		r := tokenRequest()
		r.Header.Set(cloudflare.DefaultUserHeader, email)
		return r
	}
	basicReq := func(user string) *http.Request {
		r := tokenRequest()
		r.SetBasicAuth(user, "hunter2")
		return r
	}

	tests := []struct {
		name         string
		claims       *auth.Claims
		wantTeams    []string
		wantServices string
	}{
		{
			"panda through the Cloudflare door: the staff group",
			h.verify(h.rawToken(cfReq("staff@ethpandaops.io"))),
			[]string{"panda"}, "+all,+all:all",
		},
		{
			"panda through the OIDC door: the team is in the token, the staff grant is not",
			h.verify(h.rawToken(tokenRequest(), h.oidcLogin(idp, "oidc"))),
			[]string{"panda"}, "-all,+assertoor,+dora,+dora:reindex",
		},
		{
			"panda through the basic door, named like the OIDC user: its own group only",
			h.verify(h.rawToken(basicReq("alice@example.org"))),
			[]string{"panda"}, "-all,+spamoor",
		},
		{
			"a basic-auth user named like the IdP group",
			h.verify(h.rawToken(basicReq("panda-access"))),
			[]string{"panda"}, "-all",
		},
		{
			"the OIDC user's email through the Cloudflare door: staff by team, not alice's group",
			h.verify(h.rawToken(cfReq("alice@example.org"))),
			[]string{"panda"}, "+all,+all:all",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if !slices.Equal(tc.claims.Teams, tc.wantTeams) {
				t.Errorf("teams: got %v, want %v", tc.claims.Teams, tc.wantTeams)
			}
			if tc.claims.Services != tc.wantServices {
				t.Errorf("services: got %q, want %q", tc.claims.Services, tc.wantServices)
			}
		})
	}

	// The provider name and the matches stay inside the service.
	raw := h.rawToken(tokenRequest(), h.oidcLogin(idp, "oidc"))
	payload, err := base64.RawURLEncoding.DecodeString(strings.Split(raw, ".")[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	for _, leak := range []string{`"provider"`, `"oidc"`, "panda-access", `"match`} {
		if strings.Contains(string(payload), leak) {
			t.Errorf("the token carries %s: %s", leak, payload)
		}
	}
}

// TestGrants_AttributeMembers_Sessions: attribute members are evaluated
// at login for oidc and remembered in the session as matches. A member
// added to the config later needs a new login; a member removed, or a
// group's services changed, takes effect at the next mint. A basic
// door evaluates its members on every request.
func TestGrants_AttributeMembers_Sessions(t *testing.T) {
	idp := oidctest.New(t, oidctest.User{
		Subject: "u1", Email: "alice@example.org", Groups: []string{"panda-access", "auditors"},
		Claims: map[string]any{"realm_access": map[string]any{"roles": []string{"ops"}}},
	})
	sum := sha1.Sum([]byte("hunter2"))
	htpasswd := filepath.Join(t.TempDir(), "htpasswd")
	if err := os.WriteFile(htpasswd, []byte("alice:{SHA}"+base64.StdEncoding.EncodeToString(sum[:])+"\n"), 0o600); err != nil {
		t.Fatalf("write htpasswd: %v", err)
	}

	build := func(section issuer.GrantsConfig) *teamsHarness {
		grants := sectionGrants(t, section, "oidc", "htpasswd")
		return newSectionHarness(t, &section, "",
			newOIDCProvider(idp, "oidc", oidc.Config{GrantMembers: grants.AttributeMembers("oidc")}),
			NamedProvider{Name: "htpasswd", Provider: basic.New(quietLog(), basic.Config{
				HtpasswdFile:      htpasswd,
				LoginPath:         "/htpasswd/login",
				SessionKey:        testSessionKey("htpasswd"),
				SessionCookieName: "authenticatoor_htpasswd_session",
				GrantMembers:      grants.AttributeMembers("htpasswd"),
			})},
		)
	}
	groups := func(g ...issuer.GrantGroup) issuer.GrantsConfig { return issuer.GrantsConfig{Groups: g} }
	internal := issuer.GrantGroup{Name: "internal", Members: []string{"oidc/groups:panda-access"}, Services: []string{"assertoor"}}
	auditors := issuer.GrantGroup{Name: "auditors", Members: []string{"oidc/groups:auditors"}, Services: []string{"buildoor"}}
	ops := issuer.GrantGroup{Name: "ops", Members: []string{"oidc/realm_access.roles:OPS"}, Services: []string{"spamoor"}}
	basicAlice := issuer.GrantGroup{Name: "basic", Members: []string{"htpasswd/username:alice"}, Services: []string{"dora"}}

	before := build(groups(internal, ops))
	session := before.oidcLogin(idp, "oidc")
	services := func(h *teamsHarness, cookies ...*http.Cookie) string {
		return h.verify(h.rawToken(tokenRequest(), cookies...)).Services
	}
	if got := services(before, session); got != "-all,+assertoor,+spamoor" {
		t.Fatalf("at login: %q", got)
	}

	// The session holds the matches — "<attribute>:<value>" — and none
	// of the claims they came from.
	payload, err := base64.RawURLEncoding.DecodeString(strings.Split(session.Value, ".")[1])
	if err != nil {
		t.Fatalf("decode session: %v", err)
	}
	if !strings.Contains(string(payload), `"match":["groups:panda-access","realm_access.roles:ops"]`) {
		t.Errorf("session payload: %s", payload)
	}
	if strings.Contains(string(payload), "auditors") {
		t.Errorf("the session holds a group no member named: %s", payload)
	}

	tests := []struct {
		name    string
		section issuer.GrantsConfig
		want    string
	}{
		{"unchanged", groups(internal, ops), "-all,+assertoor,+spamoor"},
		{"a group's services changed: at the next mint", groups(issuer.GrantGroup{Members: internal.Members, Services: []string{"assertoor", "dora:roll"}}, ops), "-all,+assertoor,+dora,+dora:roll,+spamoor"},
		{"a member removed: at the next mint", groups(ops), "-all,+spamoor"},
		{"all groups removed", groups(), "-all"},
		{"a member added: not for the running session", groups(internal, ops, auditors), "-all,+assertoor,+spamoor"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			after := build(tc.section)
			if got := services(after, session); got != tc.want {
				t.Errorf("services: got %q, want %q", got, tc.want)
			}
		})
	}

	t.Run("a member added: after a new login", func(t *testing.T) {
		after := build(groups(internal, ops, auditors))
		if got := services(after, after.oidcLogin(idp, "oidc")); got != "-all,+assertoor,+buildoor,+spamoor" {
			t.Errorf("services: %q", got)
		}
	})

	t.Run("a basic door evaluates per request, session cookie or not", func(t *testing.T) {
		without := build(groups(internal))
		login := httptest.NewRequest(http.MethodGet, "/htpasswd/login?return_to=%2Fauth%2Ftoken", nil)
		login.SetBasicAuth("alice", "hunter2")
		cookies := liveCookies(without.do(login))
		if len(cookies) != 1 {
			t.Fatalf("login cookies: %v", cookies)
		}
		if got := services(without, cookies[0]); got != "-all" {
			t.Fatalf("before the member exists: %q", got)
		}

		with := build(groups(internal, basicAlice))
		if got := services(with, cookies[0]); got != "-all,+dora" {
			t.Errorf("the same cookie after the member was added: %q", got)
		}
		ambient := tokenRequest()
		ambient.SetBasicAuth("alice", "hunter2")
		if got := with.verify(with.rawToken(ambient)).Services; got != "-all,+dora" {
			t.Errorf("ambient: %q", got)
		}
	})
}

// TestGrants_AmbientAlias: the Cloudflare machine alias carries its
// provider's name, so a member naming that provider reaches a caller
// there — and one naming another Cloudflare provider does not.
func TestGrants_AmbientAlias(t *testing.T) {
	section := issuer.GrantsConfig{Groups: []issuer.GrantGroup{
		{Members: []string{"cfaccess/user:deployer@ethpandaops.io", "cfaccess/principal:user"}, Services: []string{"dora:roll"}},
		{Members: []string{"other/user:deployer@ethpandaops.io"}, Services: []string{"all:all"}},
	}}
	grants := sectionGrants(t, section, "cfaccess", "other")
	door := func(name string) NamedProvider {
		return NamedProvider{Name: name, Provider: cloudflare.New(quietLog(), cloudflare.Config{
			VerifyJWT:         false,
			LoginPath:         "/" + name + "/login",
			SessionKey:        testSessionKey(name),
			SessionCookieName: "authenticatoor_" + name + "_session",
			GrantMembers:      grants.AttributeMembers(name),
		})}
	}
	h := newSectionHarness(t, &section, "", door("cfaccess"), door("other"))

	req := httptest.NewRequest(http.MethodGet, "/cfaccess/token", nil)
	req.Header.Set(cloudflare.DefaultUserHeader, "deployer@ethpandaops.io")
	if got := h.verify(h.rawToken(req)).Services; got != "-all,+dora,+dora:roll" {
		t.Errorf("/cfaccess/token: %q", got)
	}
	req = httptest.NewRequest(http.MethodGet, "/other/token", nil)
	req.Header.Set(cloudflare.DefaultUserHeader, "deployer@ethpandaops.io")
	if got := h.verify(h.rawToken(req)).Services; got != "+all,+all:all" {
		t.Errorf("/other/token: %q", got)
	}
	// principal:user alone, for someone else at the first door.
	req = httptest.NewRequest(http.MethodGet, "/cfaccess/token", nil)
	req.Header.Set(cloudflare.DefaultUserHeader, "someone@ethpandaops.io")
	if got := h.verify(h.rawToken(req)).Services; got != "-all,+dora,+dora:roll" {
		t.Errorf("/cfaccess/token for another person: %q", got)
	}
	req = httptest.NewRequest(http.MethodGet, "/other/token", nil)
	req.Header.Set(cloudflare.DefaultUserHeader, "someone@ethpandaops.io")
	if got := h.verify(h.rawToken(req)).Services; got != "-all" {
		t.Errorf("/other/token for another person: %q", got)
	}
}

// accessVerifier stands in for the Cloudflare JWKS check: it accepts any
// assertion and reports the identity the test put into it.
type accessVerifier struct{}

func (accessVerifier) Verify(_ context.Context, token string) (*cfaccess.Claims, error) {
	attrs, err := protection.TokenAttributes(token)
	if err != nil {
		return nil, err
	}
	claims := &cfaccess.Claims{}
	claims.Email, _ = attrs["email"].(string)
	claims.CommonName, _ = attrs["common_name"].(string)
	return claims, nil
}

// unstartedCloudflare is a Cloudflare provider whose Start does nothing:
// the real one fetches the team's JWKS, which the stub verifier
// replaces.
type unstartedCloudflare struct{ *cloudflare.Provider }

func (unstartedCloudflare) Start(context.Context) error { return nil }

// accessAssertion builds a Cf-Access-Jwt-Assertion value with the given
// claims.
func accessAssertion(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return "e30." + base64.RawURLEncoding.EncodeToString(payload) + ".c2ln"
}

// TestDevnetExample is the complete example of docs/config.md ("A
// complete devnet"): the providers are built from the settings printed
// there and the grants section is read from the docs file itself. The
// rows are the claims table of the docs; teams and the services claim
// are asserted exactly as printed, and the test fails if the docs table
// and this one drift apart.
func TestDevnetExample(t *testing.T) {
	section, docTable := docsDevnetExample(t)

	newIdP := func(email string, groups ...string) *oidctest.IdP {
		return oidctest.New(t, oidctest.User{Subject: "sub-" + email, Email: email, Groups: groups})
	}

	tests := []struct {
		name         string
		cloudflare   map[string]any // claims of the Access assertion; nil: use the oidc door
		idp          *oidctest.IdP
		wantTeams    []string
		wantServices string
	}{
		{
			"A person through Cloudflare Access",
			map[string]any{"email": "staff@ethpandaops.io"}, nil,
			[]string{"panda"}, "+all,+all:all",
		},
		{
			"A service token through Cloudflare Access",
			map[string]any{"common_name": "abc123.access"}, nil,
			nil, "-all",
		},
		{
			"Staff via `oidc`, groups `team:ethpandaops`, `panda-access`",
			nil, newIdP("staff@ethpandaops.io", "team:ethpandaops", "panda-access"),
			[]string{"ethpandaops"}, "+all,+all:all",
		},
		{
			"`alice@example.org` via `oidc`, group `team:lighthouse`",
			nil, newIdP("alice@example.org", "team:lighthouse"),
			[]string{"lighthouse"}, "-all,+dora,+dora:reindex,+spamoor,+spamoor:user*",
		},
		{
			"`bob@example.org` via `oidc`, group `team:lighthouse`",
			nil, newIdP("bob@example.org", "team:lighthouse"),
			[]string{"lighthouse"}, "-all,+dora,+spamoor,+spamoor:user*",
		},
		{
			"`carol@example.org` via `oidc`, no `team:` group",
			nil, newIdP("carol@example.org", "clients"),
			[]string{"geth"}, "-all,+dora,+spamoor,+spamoor:user*",
		},
		{
			"`dave@example.org` via `oidc`, group `panda-access` only",
			nil, newIdP("dave@example.org", "panda-access"),
			nil, "-all,+assertoor",
		},
		{
			"Someone via `oidc` with group `team:panda`",
			nil, newIdP("mallory@example.org", "team:panda"),
			[]string{"panda"}, "-all",
		},
	}

	if len(docTable) != len(tests) {
		t.Fatalf("the docs table has %d rows, this test %d", len(docTable), len(tests))
	}

	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// The row as the docs print it.
			row := docTable[i]
			wantTeamsCell := "*(none)*"
			if tc.wantTeams != nil {
				wantTeamsCell = "`[\"" + strings.Join(tc.wantTeams, "\", \"") + "\"]`"
			}
			if row[0] != tc.name || row[1] != wantTeamsCell || row[2] != "`"+tc.wantServices+"`" {
				t.Errorf("docs row %d is %q, this test expects [%q %q %q]", i, row, tc.name, wantTeamsCell, "`"+tc.wantServices+"`")
			}

			idp := tc.idp
			if idp == nil {
				idp = newIdP("unused@example.org")
			}
			grants := sectionGrants(t, section, "cfaccess", "oidc")

			cfProvider := cloudflare.New(quietLog(), cloudflare.Config{
				VerifyJWT:          true,
				TeamDomain:         "team.cloudflareaccess.example",
				AudTag:             "aud",
				AllowServiceTokens: true,
				LoginPath:          "/cfaccess/login",
				SessionKey:         testSessionKey("cfaccess"),
				SessionCookieName:  "authenticatoor_cfaccess_session",
				TeamRules: []protection.TeamRule{
					{Claim: "principal", Map: map[string][]string{"user": {"panda"}}},
				},
				GrantMembers: grants.AttributeMembers("cfaccess"),
			})
			cfProvider.SetVerifier(accessVerifier{})

			oidcDoor := newOIDCProvider(idp, "oidc", oidc.Config{
				TeamRules: []protection.TeamRule{
					{Claim: "groups", Prefix: "team:"},
					{Claim: "email", Map: map[string][]string{"carol@example.org": {"geth"}}},
				},
				GrantMembers: grants.AttributeMembers("oidc"),
			})

			full := newSectionHarness(t, &section, "",
				NamedProvider{Name: "cfaccess", Provider: unstartedCloudflare{cfProvider}}, oidcDoor)

			var token string
			if tc.cloudflare != nil {
				req := tokenRequest()
				req.Header.Set(cfaccess.DefaultJWTHeader, accessAssertion(t, tc.cloudflare))
				token = full.rawToken(req)
			} else {
				token = full.rawToken(tokenRequest(), full.oidcLogin(idp, "oidc"))
			}
			claims := full.verify(token)
			if !slices.Equal(claims.Teams, tc.wantTeams) {
				t.Errorf("teams: got %v, want %v", claims.Teams, tc.wantTeams)
			}
			if claims.Services != tc.wantServices {
				t.Errorf("services: got %q, want %q", claims.Services, tc.wantServices)
			}
		})
	}
}

// docsDevnetExample reads the "A complete devnet" section of
// docs/config.md: the grants section of its YAML example, and the rows
// of its claims table (cells trimmed).
func docsDevnetExample(t *testing.T) (issuer.GrantsConfig, [][]string) {
	t.Helper()
	doc, err := os.ReadFile("../../docs/config.md")
	if err != nil {
		t.Fatalf("read docs: %v", err)
	}
	_, rest, found := strings.Cut(string(doc), "### A complete devnet")
	if !found {
		t.Fatal("docs/config.md has no \"A complete devnet\" section")
	}
	_, rest, _ = strings.Cut(rest, "```yaml\n")
	example, rest, found := strings.Cut(rest, "```")
	if !found {
		t.Fatal("the section has no yaml block")
	}
	example = strings.NewReplacer(
		"<devnet>", "devnet-1", "<team>", "ethpandaops",
		"<central-idp>", "idp.example.org", "<oidc-relay>", "relay.example.org",
	).Replace(example)
	file := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(file, []byte(example), 0o600); err != nil {
		t.Fatalf("write example: %v", err)
	}
	cfg, err := config.Load(file)
	if err != nil {
		t.Fatalf("the docs example does not load: %v", err)
	}
	if cfg.Grants == nil {
		t.Fatal("the docs example has no grants section")
	}

	var rows [][]string
	section, _, _ := strings.Cut(rest, "\n### ")
	for _, line := range strings.Split(section, "\n") {
		if !strings.HasPrefix(line, "| ") || strings.HasPrefix(line, "| Who") || strings.HasPrefix(line, "| ---") {
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		for i := range cells {
			cells[i] = strings.TrimSpace(cells[i])
		}
		rows = append(rows, cells)
	}
	return *cfg.Grants, rows
}

// TestGrants_UnverifiedEmail_EndToEnd: a user of an IdP that does not
// confirm email addresses claims the address of someone who has a
// "user:" member and an email-keyed team. Nothing follows from it: the
// token's subject is the IdP's own, it has no email claim, no team and
// no grant. The genuine owner of the address — same IdP, verified —
// gets all of it.
func TestGrants_UnverifiedEmail_EndToEnd(t *testing.T) {
	section := issuer.GrantsConfig{Groups: []issuer.GrantGroup{
		{Members: []string{"oidc/user:alice@example.org"}, Services: []string{"dora:reindex"}},
		{Members: []string{"oidc/email:alice@example.org"}, Services: []string{"spamoor"}},
		{Members: []string{"oidc/team:lighthouse"}, Services: []string{"assertoor"}},
	}}
	grants := sectionGrants(t, section, "oidc")
	rules := teamRules(protection.TeamRule{Claim: "email", Map: map[string][]string{"alice@example.org": {"lighthouse"}}})

	tests := []struct {
		name         string
		claims       map[string]any
		wantSub      string
		wantEmail    string
		wantTeams    []string
		wantServices string
	}{
		{"verified", nil, "alice@example.org", "alice@example.org", []string{"lighthouse"}, "-all,+assertoor,+dora,+dora:reindex,+spamoor"},
		{"email_verified: false", map[string]any{"email_verified": false}, "sub-of-mallory", "", nil, "-all"},
		{"email_verified absent", map[string]any{"email_verified": nil}, "sub-of-mallory", "", nil, "-all"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			idp := oidctest.New(t, oidctest.User{Subject: "sub-of-mallory", Email: "alice@example.org", Claims: tc.claims})
			h := newSectionHarness(t, &section, "", newOIDCProvider(idp, "oidc", oidc.Config{
				TeamRules: rules, GrantMembers: grants.AttributeMembers("oidc"),
			}))
			raw := h.rawToken(tokenRequest(), h.oidcLogin(idp, "oidc"))
			claims := h.verify(raw)
			if claims.Subject != tc.wantSub || claims.Email != tc.wantEmail {
				t.Errorf("identity: sub=%q email=%q, want %q / %q", claims.Subject, claims.Email, tc.wantSub, tc.wantEmail)
			}
			if !slices.Equal(claims.Teams, tc.wantTeams) || claims.Services != tc.wantServices {
				t.Errorf("teams=%v services=%q, want %v / %q", claims.Teams, claims.Services, tc.wantTeams, tc.wantServices)
			}
			if tc.wantEmail == "" {
				payload, _ := base64.RawURLEncoding.DecodeString(strings.Split(raw, ".")[1])
				if strings.Contains(string(payload), "alice@example.org") {
					t.Errorf("the unverified address is in the token: %s", payload)
				}
			}
		})
	}
}
