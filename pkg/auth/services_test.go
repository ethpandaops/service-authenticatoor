package auth_test

import (
	"testing"

	"github.com/ethpandaops/service-authenticatoor/pkg/auth"
)

func TestServiceAllowed(t *testing.T) {
	cases := []struct {
		name       string
		directives string
		service    string
		want       bool
	}{
		{"empty directives default allow", "", "spamoor", true},
		{"empty service short-circuits to allow", "-all", "", true},
		{"plus all allows", "+all", "spamoor", true},
		{"minus all denies", "-all", "spamoor", false},
		{"plus all minus self denies self", "+all,-spamoor", "spamoor", false},
		{"plus all minus other allows self", "+all,-buildoor", "spamoor", true},
		{"minus all plus self allows self", "-all,+spamoor", "spamoor", true},
		{"minus all plus other denies self", "-all,+buildoor", "spamoor", false},
		{"later wins (allow then deny)", "+spamoor,-spamoor", "spamoor", false},
		{"later wins (deny then allow)", "-spamoor,+spamoor", "spamoor", true},
		{"all overrides earlier specific", "-spamoor,+all", "spamoor", true},
		{"specific overrides earlier all", "+all,-spamoor", "spamoor", false},
		{"unrelated directives default allow", "+buildoor,-monitoring", "spamoor", true},
		{"case insensitive name", "+ALL,-Spamoor", "spamoor", false},
		{"case insensitive service", "+all,-spamoor", "SPAMOOR", false},
		{"whitespace tolerated", " +all , -spamoor ", "spamoor", false},
		{"missing prefix skipped", "all,-spamoor", "spamoor", false},
		{"empty name skipped", "+,-spamoor", "spamoor", false},
		{"single char skipped", "+", "spamoor", true},
		{"only minus all", "-all", "buildoor", false},
		{"complex chain", "-all,+spamoor,+buildoor,-buildoor", "buildoor", false},
		{"complex chain other", "-all,+spamoor,+buildoor,-buildoor", "spamoor", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := auth.ServiceAllowed(tc.directives, tc.service)
			if got != tc.want {
				t.Errorf("ServiceAllowed(%q, %q) = %v, want %v",
					tc.directives, tc.service, got, tc.want)
			}
		})
	}
}
