package server

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"

	"github.com/ethpandaops/service-authenticatoor/pkg/auth"
	"github.com/ethpandaops/service-authenticatoor/pkg/cfaccess"
	"github.com/ethpandaops/service-authenticatoor/pkg/issuer"
	"github.com/ethpandaops/service-authenticatoor/pkg/protection"
	"github.com/ethpandaops/service-authenticatoor/pkg/protection/basic"
	"github.com/ethpandaops/service-authenticatoor/pkg/protection/cloudflare"
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

// TestGrants_SubjectThatLooksLikeAnEmail_EndToEnd: some IdPs can be set
// up to use an email address as the id_token's "sub" — an address
// nobody verified. A "user:" member that names an address is about who
// owns it, so such a subject must not get that member's grants: not
// when the token has no email claim at all, and not when it has one
// that is not verified. The owner of the address, verified, does.
//
// Every case goes login → session cookie → /auth/token, so what the
// session remembers about the subject is covered too.
func TestGrants_SubjectThatLooksLikeAnEmail_EndToEnd(t *testing.T) {
	section := issuer.GrantsConfig{Groups: []issuer.GrantGroup{
		{Members: []string{"oidc/user:alice@example.org"}, Services: []string{"spamoor:plugins"}},
		{Members: []string{"oidc/user:sub-123"}, Services: []string{"assertoor"}},
		// Naming the claim is the way to grant by a raw IdP subject
		// that is an address: the operator then says "the sub claim",
		// not "the user who owns this address".
		{Members: []string{"oidc/sub:carol@example.org"}, Services: []string{"dora"}},
	}}
	grants := sectionGrants(t, section, "oidc")

	const owner = "-all,+spamoor,+spamoor:plugins"
	tests := []struct {
		name         string
		user         oidctest.User
		trust        bool
		wantSub      string
		wantEmail    string
		wantServices string
	}{
		{
			"sub is the address, no email claim",
			oidctest.User{Subject: "alice@example.org"},
			false, "alice@example.org", "", noToken,
		},
		{
			"sub is the address, email_verified: false",
			oidctest.User{Subject: "alice@example.org", Email: "alice@example.org", Claims: map[string]any{"email_verified": false}},
			false, "alice@example.org", "", noToken,
		},
		{
			"sub is the address, email_verified absent",
			oidctest.User{Subject: "alice@example.org", Email: "alice@example.org", Claims: map[string]any{"email_verified": nil}},
			false, "alice@example.org", "", noToken,
		},
		{
			"sub is the address in another case",
			oidctest.User{Subject: "Alice@Example.ORG"},
			false, "Alice@Example.ORG", "", noToken,
		},
		{
			"sub is the address, another verified email",
			oidctest.User{Subject: "alice@example.org", Email: "mallory@example.org"},
			false, "mallory@example.org", "mallory@example.org", noToken,
		},
		{
			"the verified owner of the address",
			oidctest.User{Subject: "sub-999", Email: "alice@example.org"},
			false, "alice@example.org", "alice@example.org", owner,
		},
		{
			"sub and verified email are the same address",
			oidctest.User{Subject: "alice@example.org", Email: "alice@example.org"},
			false, "alice@example.org", "alice@example.org", owner,
		},
		{
			"an unverified email the operator chose to trust",
			oidctest.User{Subject: "sub-999", Email: "alice@example.org", Claims: map[string]any{"email_verified": false}},
			true, "alice@example.org", "alice@example.org", owner,
		},
		{
			"a raw subject without an @ still matches user:",
			oidctest.User{Subject: "sub-123"},
			false, "sub-123", "", "-all,+assertoor",
		},
		{
			"a raw subject that is an address matches the sub claim when a member names it",
			oidctest.User{Subject: "carol@example.org"},
			false, "carol@example.org", "", "-all,+dora",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			idp := oidctest.New(t, tc.user)
			h := newSectionHarness(t, &section, "", newOIDCProvider(idp, "oidc", oidc.Config{
				GrantMembers: grants.AttributeMembers("oidc"), TrustUnverifiedEmail: tc.trust,
			}))
			claims := h.mint(tokenRequest(), h.oidcLogin(idp, "oidc"))
			if claims.Subject != tc.wantSub || claims.Email != tc.wantEmail {
				t.Errorf("identity: sub=%q email=%q, want %q / %q", claims.Subject, claims.Email, tc.wantSub, tc.wantEmail)
			}
			if claims.Services != tc.wantServices {
				t.Errorf("services: %q, want %q", claims.Services, tc.wantServices)
			}
		})
	}
}

// TestGrants_SharedCloudflareDoor_EndToEnd: a Cloudflare provider that
// verifies assertions but has no audTag — the deployed shape — may be
// named in grants. A person and a service token coming through it both
// get what the group grants; with service tokens named by principal,
// not by a team.
func TestGrants_SharedCloudflareDoor_EndToEnd(t *testing.T) {
	section := issuer.GrantsConfig{Groups: []issuer.GrantGroup{{
		Name:     "staff",
		Members:  []string{"authentik/team:ethpandaops", "cfaccess/principal:user", "cfaccess/principal:service"},
		Services: []string{"all:all"},
	}}}
	grants := sectionGrants(t, section, "authentik", "cfaccess")

	idp := oidctest.New(t, oidctest.User{Subject: "sub-1", Email: "dev@example.org", Groups: []string{"team:lighthouse"}})
	authentik := newOIDCProvider(idp, "authentik", oidc.Config{
		TeamRules:    []protection.TeamRule{{Claim: "groups", Prefix: "team:"}},
		GrantMembers: grants.AttributeMembers("authentik"),
	})
	cf := cloudflare.New(quietLog(), cloudflare.Config{
		VerifyJWT:          true,
		TeamDomain:         "ethpandaops.cloudflareaccess.example",
		AudTag:             "", // not set, as deployed
		AllowServiceTokens: true,
		LoginPath:          "/cfaccess/login",
		SessionKey:         testSessionKey("cfaccess"),
		SessionCookieName:  "authenticatoor_cfaccess_session",
		GrantMembers:       grants.AttributeMembers("cfaccess"),
	})
	cf.SetVerifier(accessVerifier{})
	h := newSectionHarness(t, &section, "", authentik, NamedProvider{Name: "cfaccess", Provider: unstartedCloudflare{cf}})

	const all = "+all,+all:all"
	for name, assertion := range map[string]map[string]any{
		"a person":        {"email": "staff@ethpandaops.io", "aud": []string{"some-application"}},
		"a service token": {"common_name": "0123456789abcdef.access", "aud": []string{"another-application"}},
	} {
		req := tokenRequest()
		req.Header.Set(cfaccess.DefaultJWTHeader, accessAssertion(t, assertion))
		claims := h.verify(h.rawToken(req))
		if claims.Services != all {
			t.Errorf("%s through Cloudflare Access: services %q, want %q", name, claims.Services, all)
		}
		if claims.Teams != nil {
			t.Errorf("%s: teams %v", name, claims.Teams)
		}
	}

	// The other door is still told apart: a client developer through
	// the IdP is not staff, and — named by no group — gets no token.
	claims := h.mint(tokenRequest(), h.oidcLogin(idp, "authentik"))
	if !slices.Equal(claims.Teams, []string{"lighthouse"}) || claims.Services != noToken {
		t.Errorf("a client developer through the IdP: teams %v services %q", claims.Teams, claims.Services)
	}

	// Without any credential nobody is anybody.
	rr := h.do(httptest.NewRequest(http.MethodGet, "/auth/token", nil))
	if rr.Code == http.StatusOK {
		t.Errorf("an unauthenticated request got a token: %s", rr.Body.String())
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
		{"a team no group names: no token", grants, "", []string{"team:reth"}, noToken, nil},
		{"no teams at all: no token", grants, "", []string{}, noToken, nil},
		{
			"a team whose services the instance denies: a token for nothing", grants, "-all,+spamoor",
			[]string{"team:lighthouse"}, "-all", nil,
		},
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

			if tc.wantClaim == noToken {
				// Authenticated, and named by no group: nothing is
				// minted that a verifier could accept.
				assertNotGranted(t, h.do(tokenRequest(), h.oidcLogin(idp, "oidc")))
				return
			}

			var token string
			if tc.groups == nil {
				req := tokenRequest()
				req.Header.Set(cloudflare.DefaultUserHeader, "staff@ethpandaops.io")
				token = h.rawToken(req)
			} else {
				token = h.rawToken(tokenRequest(), h.oidcLogin(idp, "oidc"))
			}

			// A member of a group is authenticated whatever it is
			// granted: the token itself is valid for a verifier that
			// does not gate on a service.
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
		{"services taken away, the team still named", map[string][]string{"lighthouse": {}}, "-all"},
		{"the group removed: no token", map[string][]string{"geth": {"dora"}}, noToken},
		{"every group removed: no token", map[string][]string{}, noToken},
		{"section removed", nil, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			after := newGrantsHarness(t, tc.teamServices, "", provider())
			claims := after.mint(tokenRequest(), session)
			if claims.Services != tc.want {
				t.Errorf("services: got %q, want %q", claims.Services, tc.want)
			}
			if !slices.Equal(claims.Teams, []string{"lighthouse"}) {
				t.Errorf("teams: %v", claims.Teams)
			}
		})
	}
}

// TestGrants_Features_AbsentSection: without a grants section the
// token has no services claim, which means basic access to every
// service and nothing more — the service gate passes, a default-allow
// feature is allowed, a default-deny feature is not.
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
	if !claims.HasFeature("dora", auth.FeatureBasic, auth.FeatureDefaultDeny) {
		t.Error("a token without a services claim has basic access to every service")
	}
	if !claims.HasFeature("dora", "view-logs", auth.FeatureDefaultAllow) {
		t.Error("a token without a services claim has the default-allow features")
	}
	if claims.HasFeature("dora", "roll", auth.FeatureDefaultDeny) {
		t.Error("a token without a services claim must not hold a default-deny feature")
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
		return h.mint(tokenRequest(), cookies...).Services
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
		{"all groups removed: no token", groups(), noToken},
		{"only a group of another member left: no token", groups(auditors), noToken},
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
		if got := services(without, cookies[0]); got != noToken {
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
	// Nobody names that person at the second door: no token there.
	assertNotGranted(t, h.do(req))
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
		{"email_verified: false", map[string]any{"email_verified": false}, "sub-of-mallory", "", nil, noToken},
		{"email_verified absent", map[string]any{"email_verified": nil}, "sub-of-mallory", "", nil, noToken},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			idp := oidctest.New(t, oidctest.User{Subject: "sub-of-mallory", Email: "alice@example.org", Claims: tc.claims})
			h := newSectionHarness(t, &section, "", newOIDCProvider(idp, "oidc", oidc.Config{
				TeamRules: rules, GrantMembers: grants.AttributeMembers("oidc"),
			}))
			session := h.oidcLogin(idp, "oidc")
			claims := h.mint(tokenRequest(), session)
			if claims.Subject != tc.wantSub || claims.Email != tc.wantEmail {
				t.Errorf("identity: sub=%q email=%q, want %q / %q", claims.Subject, claims.Email, tc.wantSub, tc.wantEmail)
			}
			if !slices.Equal(claims.Teams, tc.wantTeams) || claims.Services != tc.wantServices {
				t.Errorf("teams=%v services=%q, want %v / %q", claims.Teams, claims.Services, tc.wantTeams, tc.wantServices)
			}
			if tc.wantEmail == "" {
				// No token; what the service says about the user must
				// not carry the unverified address either.
				body := h.do(httptest.NewRequest(http.MethodGet, "/auth/userinfo", nil), session).Body.String()
				if strings.Contains(body, "alice@example.org") {
					t.Errorf("the unverified address is in the userinfo answer: %s", body)
				}
			}
		})
	}
}
