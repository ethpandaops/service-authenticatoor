package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
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
			"in no group: no token through either", oidctest.User{Subject: "u2", Email: "bob@example.org"},
			"bob@example.org", []string{"everyone"}, noToken,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			idp := oidctest.New(t, tc.user)
			h := newSectionHarness(t, &section, "", newOIDCProvider(idp, "corp", oidc.Config{
				Teams: []string{"everyone"}, TeamRules: teamRules(prefixRule),
				GrantMembers: grants.AttributeMembers("corp"), Bearer: bearerOn(),
			}), newBasicProvider(t, "other"))

			if tc.wantServices == noToken {
				viaBrowser := h.mint(tokenRequest(), h.oidcLogin(idp, "corp"))
				if viaBrowser.Services != noToken || viaBrowser.Subject != tc.wantSub ||
					!slices.Equal(viaBrowser.Teams, tc.wantTeams) {
					t.Errorf("browser: %+v", viaBrowser)
				}
				rr := h.do(bearerGet("/corp/token", idp.Token(t, cliAudience)))
				assertNotGranted(t, rr)
				if got := rr.Header().Get("WWW-Authenticate"); got != "" {
					t.Errorf("a refusal for want of a grant carries a challenge: %q", got)
				}
				if cookies := rr.Result().Cookies(); len(cookies) != 0 {
					t.Errorf("the bearer path set cookies: %v", cookies)
				}
				return
			}
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
	// Only GET, as for every token alias — and no CORS: the alias is
	// not for scripts in a browser, so a preflight is a 405 like any
	// other method, and no answer carries an Access-Control header.
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodHead, http.MethodOptions} {
		req := bearerGet("/oidc/token", idp.Token(t, cliAudience))
		req.Method = method
		req.Header.Set("Origin", "https://app.test.example")
		req.Header.Set("Access-Control-Request-Method", http.MethodGet)
		rr := h.do(req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: status %d", method, rr.Code)
		}
		if strings.Contains(rr.Body.String(), "eyJ") {
			t.Errorf("%s: the answer carries a token", method)
		}
	}
	req := bearerGet("/oidc/token", idp.Token(t, cliAudience))
	req.Header.Set("Origin", "https://app.test.example")
	rr := h.do(req)
	if rr.Code != http.StatusOK {
		t.Errorf("GET with an Origin: status %d", rr.Code)
	}
	for name := range rr.Header() {
		if strings.HasPrefix(name, "Access-Control-") {
			t.Errorf("the alias sent %s: %s", name, rr.Header().Get(name))
		}
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

// TestBearer_AuthToken: the bearer block changes nothing on /auth/*.
// A request there that carries Authorization: Bearer is answered as if
// the header were not there — by the session cookie, or with the
// redirect to the login — whether the token is one the alias accepts
// or not, and wherever the provider stands among several.
func TestBearer_AuthToken(t *testing.T) {
	idp := oidctest.New(t, oidctest.User{Subject: "u1", Email: "alice@example.org", Groups: []string{"team:panda"}})
	oidcDoor := func(bearer *oidc.BearerConfig) NamedProvider {
		return newOIDCProvider(idp, "oidc", oidc.Config{TeamRules: teamRules(prefixRule), Bearer: bearer})
	}
	grants := map[string][]string{"panda": {"dora"}}

	orders := map[string]func(*testing.T, *oidc.BearerConfig) []NamedProvider{
		"alone": func(_ *testing.T, b *oidc.BearerConfig) []NamedProvider { return []NamedProvider{oidcDoor(b)} },
		"first of two": func(t *testing.T, b *oidc.BearerConfig) []NamedProvider {
			return []NamedProvider{oidcDoor(b), newBasicProvider(t, "htpasswd")}
		},
		"second of two": func(t *testing.T, b *oidc.BearerConfig) []NamedProvider {
			return []NamedProvider{newBasicProvider(t, "htpasswd"), oidcDoor(b)}
		},
	}
	tokens := map[string]string{
		"a token the alias accepts": idp.Token(t, cliAudience),
		"a token it refuses":        idp.Token(t, "authenticatoor"),
		"garbage":                   "garbage",
	}
	paths := []string{"/auth/token", "/auth/userinfo", "/auth/login?return_to=https%3A%2F%2Fapp.test.example%2F"}

	for order, providers := range orders {
		t.Run(order, func(t *testing.T) {
			on := newGrantsHarness(t, grants, "", providers(t, bearerOn())...)
			off := newGrantsHarness(t, grants, "", providers(t, nil)...)
			session := on.oidcLogin(idp, "oidc")

			for name, token := range tokens {
				for _, path := range paths {
					// Without a session: exactly what an instance without
					// the bearer block answers, and what the same request
					// gets without the header.
					got, before := on.do(bearerGet(path, token)), off.do(bearerGet(path, token))
					plain := on.do(httptest.NewRequest(http.MethodGet, path, nil))
					for what, want := range map[string]*httptest.ResponseRecorder{"bearer off": before, "no header": plain} {
						if got.Code != want.Code || got.Header().Get("Location") != want.Header().Get("Location") ||
							got.Body.String() != want.Body.String() {
							t.Errorf("%s, %s: %d → %q, but with %s: %d → %q", name, path,
								got.Code, got.Header().Get("Location"), what, want.Code, want.Header().Get("Location"))
						}
					}
					if got.Code != http.StatusFound || got.Header().Get("WWW-Authenticate") != "" {
						t.Errorf("%s, %s: status %d, challenge %q; want the redirect to the login",
							name, path, got.Code, got.Header().Get("WWW-Authenticate"))
					}
				}

				// With a session the cookie decides, also next to a bad
				// token.
				rr := on.do(bearerGet("/auth/token", token), session)
				if rr.Code != http.StatusOK {
					t.Fatalf("%s next to a session: status %d", name, rr.Code)
				}
				var resp tokenResponse
				if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
					t.Fatalf("decode: %v", err)
				}
				if c := on.verify(resp.Token); c.Subject != "alice@example.org" || c.Services != "-all,+dora" {
					t.Errorf("%s next to a session: sub %q services %q", name, c.Subject, c.Services)
				}
			}

			// The alias is where the token counts.
			if rr := on.do(bearerGet("/oidc/token", tokens["a token the alias accepts"])); rr.Code != http.StatusOK {
				t.Errorf("/oidc/token: status %d", rr.Code)
			}
		})
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
