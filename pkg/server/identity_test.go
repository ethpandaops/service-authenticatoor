package server

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/ethpandaops/service-authenticatoor/pkg/cfaccess"
	"github.com/ethpandaops/service-authenticatoor/pkg/issuer"
	"github.com/ethpandaops/service-authenticatoor/pkg/protection"
	"github.com/ethpandaops/service-authenticatoor/pkg/protection/cloudflare"
	"github.com/ethpandaops/service-authenticatoor/pkg/protection/oidc"
	"github.com/ethpandaops/service-authenticatoor/pkg/protection/oidc/oidctest"
)

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

// TestGrants_ClaimNamesAreExact_EndToEnd: the standard claims of an
// id_token are read by their exact names. "Email_Verified": true does
// not verify an email, and "Email" is not the email.
func TestGrants_ClaimNamesAreExact_EndToEnd(t *testing.T) {
	section := issuer.GrantsConfig{Groups: []issuer.GrantGroup{
		{Members: []string{"oidc/user:alice@example.org", "oidc/email:alice@example.org"}, Services: []string{"spamoor"}},
	}}
	grants := sectionGrants(t, section, "oidc")

	tests := []struct {
		name string
		user oidctest.User
	}{
		{
			"Email_Verified",
			oidctest.User{Subject: "sub-of-mallory", Email: "alice@example.org", Claims: map[string]any{
				"email_verified": nil, "Email_Verified": true,
			}},
		},
		{
			"EMAIL_VERIFIED next to email_verified: false",
			oidctest.User{Subject: "sub-of-mallory", Email: "alice@example.org", Claims: map[string]any{
				"email_verified": false, "EMAIL_VERIFIED": true, "emailVerified": true,
			}},
		},
		{
			"Email, verified, without an email claim",
			oidctest.User{Subject: "sub-of-mallory", Claims: map[string]any{
				"Email": "alice@example.org", "email_verified": true,
			}},
		},
		{
			"Sub next to sub",
			oidctest.User{Subject: "sub-of-mallory", Claims: map[string]any{"Sub": "alice@example.org", "SUB": "alice@example.org"}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			idp := oidctest.New(t, tc.user)
			h := newSectionHarness(t, &section, "", newOIDCProvider(idp, "oidc", oidc.Config{
				GrantMembers: grants.AttributeMembers("oidc"),
			}))
			claims := h.mint(tokenRequest(), h.oidcLogin(idp, "oidc"))
			if claims.Subject != "sub-of-mallory" || claims.Email != "" || claims.Services != noToken {
				t.Errorf("sub=%q email=%q services=%q, want the IdP subject, no email and no token",
					claims.Subject, claims.Email, claims.Services)
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
