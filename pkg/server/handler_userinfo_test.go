package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ethpandaops/service-authenticatoor/pkg/issuer"
	"github.com/ethpandaops/service-authenticatoor/pkg/protection/cloudflare"
)

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
