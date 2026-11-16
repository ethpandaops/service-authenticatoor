package auth_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/ethpandaops/service-authenticatoor/pkg/auth"
)

func TestNormalizeTeam(t *testing.T) {
	tests := []struct {
		name   string
		in     string
		want   string
		wantOK bool
	}{
		{"plain", "panda", "panda", true},
		{"uppercase is lowered", "Lighthouse", "lighthouse", true},
		{"surrounding whitespace is trimmed", "  geth\t\n", "geth", true},
		{"digits first", "0xteam", "0xteam", true},
		{"dot dash underscore", "eth.dev-ops_1", "eth.dev-ops_1", true},
		{"single character", "a", "a", true},
		{"63 characters", strings.Repeat("a", 63), strings.Repeat("a", 63), true},
		{"64 characters", strings.Repeat("a", 64), "", false},
		{"empty", "", "", false},
		{"only whitespace", "   ", "", false},
		{"leading dash", "-panda", "", false},
		{"leading dot", ".panda", "", false},
		{"leading underscore", "_panda", "", false},
		{"inner whitespace", "core devs", "", false},
		{"colon", "team:panda", "", false},
		{"slash", "a/b", "", false},
		{"comma", "a,b", "", false},
		{"non-ascii", "pändä", "", false},
		{"control character", "pan\x00da", "", false},
		{"no-break space is not trimmed", "panda\u00a0", "", false},
		{"em space is not trimmed", "\u2003panda", "", false},
		{"Kelvin sign is not folded to k", "\u212aurtosis", "", false},
		{"dotted capital I is not folded to i", "\u0130nfra", "", false},
		{"newline inside", "pan\nda", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := auth.NormalizeTeam(tc.in)
			if got != tc.want || ok != tc.wantOK {
				t.Errorf("NormalizeTeam(%q) = %q, %t; want %q, %t", tc.in, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

func TestCanonicalTeams(t *testing.T) {
	many := make([]string, 0, 40)
	for i := range 40 {
		many = append(many, fmt.Sprintf("team-%02d", i))
	}

	tests := []struct {
		name        string
		in          []string
		want        []string
		wantInvalid []string
	}{
		{"nil", nil, nil, nil},
		{"empty", []string{}, nil, nil},
		{"sorted", []string{"panda", "geth", "lighthouse"}, []string{"geth", "lighthouse", "panda"}, nil},
		{"exact duplicates collapse", []string{"panda", "panda"}, []string{"panda"}, nil},
		{
			"nothing is folded: case and whitespace variants are invalid",
			[]string{"Panda", "panda ", " panda", "PANDA", "panda\u00a0", "\u212aurtosis", "panda"},
			[]string{"panda"},
			[]string{"Panda", "panda ", " panda", "PANDA", "panda\u00a0", "\u212aurtosis"},
		},
		{
			"invalid entries are reported as given",
			[]string{"panda", "core devs", "", "-x"},
			[]string{"panda"},
			[]string{"core devs", "", "-x"},
		},
		{"only invalid", []string{"!!"}, nil, []string{"!!"}},
		{"not bounded here", many, many, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, invalid := auth.CanonicalTeams(tc.in)
			if !slices.Equal(got, tc.want) {
				t.Errorf("teams: got %v, want %v", got, tc.want)
			}
			if (got == nil) != (tc.want == nil) {
				t.Errorf("teams nil-ness: got %v, want %v", got == nil, tc.want == nil)
			}
			if !slices.Equal(invalid, tc.wantInvalid) {
				t.Errorf("invalid: got %q, want %q", invalid, tc.wantInvalid)
			}
			for _, team := range got {
				if !auth.ValidTeam(team) {
					t.Errorf("%q is not valid", team)
				}
			}
		})
	}
}

func TestClaims_HasTeam(t *testing.T) {
	withTeams := &auth.Claims{Teams: []string{"lighthouse", "panda"}}

	tests := []struct {
		name   string
		claims *auth.Claims
		team   string
		want   bool
	}{
		{"member", withTeams, "panda", true},
		{"argument is normalized", withTeams, " Panda ", true},
		{"not a member", withTeams, "geth", false},
		{"no prefix match", withTeams, "pand", false},
		{"no superstring match", withTeams, "pandas", false},
		{"invalid name", withTeams, "team:panda", false},
		{"empty name", withTeams, "", false},
		{"token without the claim", &auth.Claims{}, "panda", false},
		{"nil claims", nil, "panda", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.claims.HasTeam(tc.team); got != tc.want {
				t.Errorf("HasTeam(%q) = %t, want %t", tc.team, got, tc.want)
			}
		})
	}
}

func TestClaims_HasAnyTeam(t *testing.T) {
	withTeams := &auth.Claims{Teams: []string{"lighthouse", "panda"}}

	tests := []struct {
		name   string
		claims *auth.Claims
		teams  []string
		want   bool
	}{
		{"first matches", withTeams, []string{"panda", "geth"}, true},
		{"last matches", withTeams, []string{"geth", "LIGHTHOUSE"}, true},
		{"none match", withTeams, []string{"geth", "reth"}, false},
		{"no names", withTeams, nil, false},
		{"token without the claim", &auth.Claims{}, []string{"panda"}, false},
		{"nil claims", nil, []string{"panda"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.claims.HasAnyTeam(tc.teams...); got != tc.want {
				t.Errorf("HasAnyTeam(%v) = %t, want %t", tc.teams, got, tc.want)
			}
		})
	}
}
