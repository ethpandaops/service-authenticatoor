package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/ethpandaops/service-authenticatoor/pkg/auth"
	"github.com/ethpandaops/service-authenticatoor/pkg/issuer"
	"github.com/ethpandaops/service-authenticatoor/pkg/protection"
	"github.com/ethpandaops/service-authenticatoor/pkg/protection/oidc"
	"github.com/ethpandaops/service-authenticatoor/pkg/protection/oidc/oidctest"
)

// cliAudience is the IdP client of the non-browser client.
const cliAudience = "devnet-cli"

func bearerOn() *oidc.BearerConfig { return &oidc.BearerConfig{Audiences: []string{cliAudience}} }

// bearerGet requests path with the token as bearer credential.
func bearerGet(path, token string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

// identityClaims are the claims of a minted token that say who its
// user is and what they may do.
type identityClaims struct {
	Subject  string
	Email    string
	Teams    []string
	Services string
	Scope    string
	Audience []string
}

func identityOf(c *auth.Claims) identityClaims {
	return identityClaims{
		Subject: c.Subject, Email: c.Email, Teams: c.Teams,
		Services: c.Services, Scope: c.Scope, Audience: c.Audience,
	}
}

// TestBearer_SameTokenAsBrowserLogin: a client presenting the IdP's
// token to /<name>/token gets a token with the identity, teams and
// services of the same user's browser login through that provider —
// for a team grant, a user grant, an attribute grant, and for an email
// the IdP does not vouch for.
func TestBearer_SameTokenAsBrowserLogin(t *testing.T) {
	section := issuer.GrantsConfig{Groups: []issuer.GrantGroup{
		{Members: []string{"corp/team:panda"}, Services: []string{"dora:reindex"}},
		{Members: []string{"corp/user:alice@example.org"}, Services: []string{"spamoor"}},
		{Members: []string{"corp/groups:panda-access"}, Services: []string{"assertoor"}},
		{Members: []string{"other/team:panda", "other/user:alice@example.org"}, Services: []string{"all:all"}},
	}}
	grants := sectionGrants(t, section, "corp", "other")
	groups := []string{"team:panda", "panda-access"}

	tests := []struct {
		name         string
		user         oidctest.User
		wantSub      string
		wantTeams    []string
		wantServices string
	}{
		{
			"verified email", oidctest.User{Subject: "u1", Email: "alice@example.org", Groups: groups},
			"alice@example.org", []string{"everyone", "panda"}, "-all,+assertoor,+dora,+dora:reindex,+spamoor",
		},
		{
			// The IdP's sub is the subject; the user: grant for the
			// address does not match.
			"unverified email",
			oidctest.User{Subject: "u1", Email: "alice@example.org", Groups: groups, Claims: map[string]any{"email_verified": false}},
			"u1", []string{"everyone", "panda"}, "-all,+assertoor,+dora,+dora:reindex",
		},
		{
			"no groups", oidctest.User{Subject: "u1", Email: "alice@example.org"},
			"alice@example.org", []string{"everyone"}, "-all,+spamoor",
		},
		{
			"authenticated, nothing granted", oidctest.User{Subject: "u2", Email: "bob@example.org"},
			"bob@example.org", []string{"everyone"}, "-all",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			idp := oidctest.New(t, tc.user)
			h := newSectionHarness(t, &section, "", newOIDCProvider(idp, "corp", oidc.Config{
				Teams: []string{"everyone"}, TeamRules: teamRules(prefixRule),
				GrantMembers: grants.AttributeMembers("corp"), Bearer: bearerOn(),
			}), newBasicProvider(t, "other"))

			browser := identityOf(h.token(tokenRequest(), h.oidcLogin(idp, "corp")))

			rr := h.do(bearerGet("/corp/token", idp.Token(t, cliAudience)))
			if rr.Code != http.StatusOK {
				t.Fatalf("/corp/token: status %d, body %s", rr.Code, rr.Body.String())
			}
			if cookies := rr.Result().Cookies(); len(cookies) != 0 {
				t.Errorf("the bearer path set cookies: %v", cookies)
			}
			if got := rr.Header().Get("Cache-Control"); got != "no-store" {
				t.Errorf("Cache-Control %q", got)
			}
			var resp map[string]any
			if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode: %v", err)
			}
			keys := make([]string, 0, len(resp))
			for k := range resp {
				keys = append(keys, k)
			}
			slices.Sort(keys)
			if !slices.Equal(keys, []string{"expr", "now", "token", "user"}) {
				t.Errorf("response fields %v", keys)
			}
			if resp["user"] != tc.wantSub {
				t.Errorf("user %v, want %q", resp["user"], tc.wantSub)
			}
			token, _ := resp["token"].(string)
			bearer := identityOf(h.verify(token))

			if bearer.Subject != browser.Subject || bearer.Email != browser.Email ||
				!slices.Equal(bearer.Teams, browser.Teams) || bearer.Services != browser.Services ||
				bearer.Scope != browser.Scope || !slices.Equal(bearer.Audience, browser.Audience) {
				t.Errorf("tokens differ:\nbrowser %+v\n bearer %+v", browser, bearer)
			}
			if bearer.Subject != tc.wantSub || !slices.Equal(bearer.Teams, tc.wantTeams) || bearer.Services != tc.wantServices {
				t.Errorf("bearer token: %+v, want sub %q teams %v services %q", bearer, tc.wantSub, tc.wantTeams, tc.wantServices)
			}
		})
	}
}

// TestBearer_Responses: what the token alias answers when it issues no
// token — a status and a Bearer challenge, never a redirect to a login
// and never a cookie.
func TestBearer_Responses(t *testing.T) {
	idp := oidctest.New(t, oidctest.User{Subject: "u1", Email: "alice@example.org", Groups: []string{"sigp"}})
	h := newTeamsHarness(t,
		newOIDCProvider(idp, "oidc", oidc.Config{AllowedGroups: []string{"ethpandaops"}, Bearer: bearerOn()}),
		newBasicProvider(t, "htpasswd"),
	)

	tests := []struct {
		name      string
		token     string
		status    int
		challenge string
	}{
		{"no header", "", http.StatusUnauthorized, "Bearer"},
		{"garbage", "garbage", http.StatusUnauthorized, `Bearer error="invalid_token"`},
		{"wrong audience", idp.Token(t, "authenticatoor"), http.StatusUnauthorized, `Bearer error="invalid_token"`},
		{"not in allowedGroups", idp.Token(t, cliAudience), http.StatusForbidden, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rr := h.do(bearerGet("/oidc/token", tc.token))
			if rr.Code != tc.status {
				t.Errorf("status %d, want %d (body %s)", rr.Code, tc.status, rr.Body.String())
			}
			if got := rr.Header().Get("WWW-Authenticate"); got != tc.challenge {
				t.Errorf("WWW-Authenticate %q, want %q", got, tc.challenge)
			}
			if loc := rr.Header().Get("Location"); loc != "" {
				t.Errorf("redirected to %q", loc)
			}
			if cookies := rr.Result().Cookies(); len(cookies) != 0 {
				t.Errorf("cookies: %v", cookies)
			}
		})
	}

	// In an allowed group the same request is answered.
	idp.SetUser(oidctest.User{Subject: "u1", Email: "alice@example.org", Groups: []string{"ethpandaops"}})
	if rr := h.do(bearerGet("/oidc/token", idp.Token(t, cliAudience))); rr.Code != http.StatusOK {
		t.Errorf("allowed user: status %d", rr.Code)
	}
	// Only GET, as for every token alias.
	req := bearerGet("/oidc/token", idp.Token(t, cliAudience))
	req.Method = http.MethodPost
	if rr := h.do(req); rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: status %d", rr.Code)
	}
}

// TestBearer_Off: without the bearer block the provider has no token
// alias — the path is answered like any path nobody serves — and a
// bearer token on /auth/token is ignored.
func TestBearer_Off(t *testing.T) {
	idp := oidctest.New(t, oidctest.User{Subject: "u1", Email: "alice@example.org"})
	h := newTeamsHarness(t, newOIDCProvider(idp, "oidc", oidc.Config{}))

	for _, method := range []string{http.MethodGet, http.MethodPost} {
		req := bearerGet("/oidc/token", idp.Token(t, cliAudience))
		req.Method = method
		got := h.do(req)
		nowhere := h.do(httptest.NewRequest(method, "/oidc/nowhere", nil))
		if got.Code != http.StatusNotFound || got.Code != nowhere.Code || got.Body.String() != nowhere.Body.String() {
			t.Errorf("%s /oidc/token: %d %q, an unserved path: %d %q",
				method, got.Code, got.Body.String(), nowhere.Code, nowhere.Body.String())
		}
	}

	rr := h.do(bearerGet("/auth/token", idp.Token(t, "authenticatoor")))
	if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/oidc/login?return_to=%2Fauth%2Ftoken" {
		t.Errorf("/auth/token with a bearer token: %d → %q", rr.Code, rr.Header().Get("Location"))
	}
}

// TestBearer_AuthToken: with the bearer block, /auth/token takes the
// header too — the way the cloudflare provider's ambient headers work
// on /auth/* — through the same check.
func TestBearer_AuthToken(t *testing.T) {
	idp := oidctest.New(t, oidctest.User{Subject: "u1", Email: "alice@example.org", Groups: []string{"team:panda"}})
	h := newGrantsHarness(t, map[string][]string{"panda": {"dora"}}, "",
		newOIDCProvider(idp, "oidc", oidc.Config{TeamRules: teamRules(prefixRule), Bearer: bearerOn()}))

	rr := h.do(bearerGet("/auth/token", idp.Token(t, cliAudience)))
	if rr.Code != http.StatusOK || len(rr.Result().Cookies()) != 0 {
		t.Fatalf("/auth/token: status %d, cookies %v", rr.Code, rr.Result().Cookies())
	}
	var resp tokenResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if c := h.verify(resp.Token); c.Subject != "alice@example.org" || c.Services != "-all,+dora" {
		t.Errorf("token: sub %q services %q", c.Subject, c.Services)
	}

	rr = h.do(bearerGet("/auth/token", idp.Token(t, "authenticatoor")))
	if rr.Code != http.StatusUnauthorized || rr.Header().Get("Location") != "" ||
		rr.Header().Get("WWW-Authenticate") != `Bearer error="invalid_token"` {
		t.Errorf("bad token: %d, location %q, challenge %q",
			rr.Code, rr.Header().Get("Location"), rr.Header().Get("WWW-Authenticate"))
	}
	// A browser without the header still goes to the login.
	if rr := h.do(tokenRequest()); rr.Code != http.StatusFound {
		t.Errorf("no credentials: status %d", rr.Code)
	}
}

// TestBearer_CloudflareAliasUnchanged: the token alias of a provider
// that has no challenge to offer answers as it always did.
func TestBearer_CloudflareAliasUnchanged(t *testing.T) {
	h := newTeamsHarness(t, newCloudflareProvider("cfaccess"))
	rr := h.do(httptest.NewRequest(http.MethodGet, "/cfaccess/token", nil))
	if rr.Code != http.StatusUnauthorized || rr.Body.String() != "unauthorized\n" || rr.Header().Get("WWW-Authenticate") != "" {
		t.Errorf("status %d body %q challenge %q", rr.Code, rr.Body.String(), rr.Header().Get("WWW-Authenticate"))
	}
}

var _ protection.AmbientSwitch = (*oidc.Provider)(nil)
