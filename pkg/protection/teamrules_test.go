package protection

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"

	"github.com/ethpandaops/service-authenticatoor/pkg/auth"
)

// jsonAttributes decodes a JSON object the way TokenAttributes decodes
// a token payload.
func jsonAttributes(t *testing.T, doc string) Attributes {
	t.Helper()
	token := "h." + base64.RawURLEncoding.EncodeToString([]byte(doc)) + ".s"
	attrs, err := TokenAttributes(token)
	if err != nil {
		t.Fatalf("attributes: %v", err)
	}
	return attrs
}

const sampleClaims = `{
	"sub": "u-1",
	"email": "Alice@Example.org",
	"groups": ["team:lighthouse", "team:geth", "ethpandaops", "sigp:core", "Team:Upper", "other"],
	"department": "eng-consensus",
	"scope": "openid team-a team-b  email",
	"level": 3,
	"ratio": 1.5,
	"admin": true,
	"realm_access": {"roles": ["dev", "ops"]},
	"resource_access": {"myapp": {"roles": ["myapp-admin"]}},
	"https://example.org/claims": {"teams": ["url-team"]},
	"a.b": "dotted-key",
	"a": {"b": "nested-key", "c": "only-nested"},
	"nothing": null,
	"object": {"x": "y"},
	"nested_list": [["inner"], {"k": "v"}, "flat", 7, false, null],
	"empty": ""
}`

func TestTeamRules_Resolve(t *testing.T) {
	tests := []struct {
		name         string
		rules        []TeamRule
		want         []string
		wantRejected []string
	}{
		// ─── the rule forms ─────────────────────────────────────────────
		{"prefix", []TeamRule{{Claim: "groups", Prefix: "team:"}}, []string{"geth", "lighthouse"}, []string{"Upper"}},
		{"prefix is case-insensitive, the rest is not folded", []TeamRule{{Claim: "groups", Prefix: "TEAM:"}}, []string{"geth", "lighthouse"}, []string{"Upper"}},
		{"map: exact keys", []TeamRule{{Claim: "groups", Map: map[string][]string{"ethpandaops": {"panda"}, "sigp:core": {"lighthouse"}}}}, []string{"lighthouse", "panda"}, nil},
		{"map: keys are case-insensitive", []TeamRule{{Claim: "groups", Map: map[string][]string{"EthPandaOps": {"panda"}}}}, []string{"panda"}, nil},
		{"map: glob", []TeamRule{{Claim: "groups", Map: map[string][]string{"sigp:*": {"lighthouse"}}}}, []string{"lighthouse"}, nil},
		{"map: several keys match one value", []TeamRule{{Claim: "groups", Map: map[string][]string{"sigp:*": {"lighthouse"}, "*:core": {"core"}}}}, []string{"core", "lighthouse"}, nil},
		{"map: no key matches", []TeamRule{{Claim: "groups", Map: map[string][]string{"nobody": {"panda"}}}}, nil, nil},
		{"regex: one capture group", []TeamRule{{Claim: "department", Regex: "^eng-([a-z0-9-]+)$"}}, []string{"consensus"}, nil},
		{"regex: has to cover the whole value even unanchored", []TeamRule{{Claim: "department", Regex: "ng-([a-z]+)"}}, nil, nil},
		{"regex: unanchored but covering", []TeamRule{{Claim: "department", Regex: "eng-([a-z]+)"}}, []string{"consensus"}, nil},
		{"regex on a list", []TeamRule{{Claim: "groups", Regex: "team:([a-z]+)"}}, []string{"geth", "lighthouse"}, nil},
		{"bare: every value is a team", []TeamRule{{Claim: "realm_access.roles", Value: true}}, []string{"dev", "ops"}, nil},
		{"bare: values that are not team names are rejected", []TeamRule{{Claim: "groups", Value: true}}, []string{"ethpandaops", "other"}, []string{"team:lighthouse", "team:geth", "sigp:core", "Team:Upper"}},
		{"split", []TeamRule{{Claim: "scope", Split: " ", Value: true}}, []string{"email", "openid", "team-a", "team-b"}, nil},
		{"split with a prefix", []TeamRule{{Claim: "scope", Split: " ", Prefix: "team-"}}, []string{"a", "b"}, nil},
		{"email through a map: a team for one user", []TeamRule{{Claim: "email", Map: map[string][]string{"alice@example.org": {"lighthouse"}}}}, []string{"lighthouse"}, nil},
		{"several rules add up", []TeamRule{{Claim: "groups", Prefix: "team:"}, {Claim: "groups", Map: map[string][]string{"ethpandaops": {"panda"}}}, {Claim: "department", Regex: "eng-(.+)"}}, []string{"consensus", "geth", "lighthouse", "panda"}, []string{"Upper"}},

		// ─── paths ──────────────────────────────────────────────────────
		{"nested path", []TeamRule{{Claim: "resource_access.myapp.roles", Value: true}}, []string{"myapp-admin"}, nil},
		{"a key that contains dots", []TeamRule{{Claim: "https://example.org/claims.teams", Value: true}}, []string{"url-team"}, nil},
		{"the longest existing key wins", []TeamRule{{Claim: "a.b", Value: true}}, []string{"dotted-key"}, nil},
		{"falls back to the nested path", []TeamRule{{Claim: "a.c", Value: true}}, []string{"only-nested"}, nil},
		{"missing attribute", []TeamRule{{Claim: "missing", Value: true}}, nil, nil},
		{"missing nested attribute", []TeamRule{{Claim: "realm_access.groups", Value: true}}, nil, nil},
		{"path through a scalar", []TeamRule{{Claim: "department.x", Value: true}}, nil, nil},
		{"path through a list", []TeamRule{{Claim: "groups.0", Value: true}}, nil, nil},
		{"attribute names are case-sensitive", []TeamRule{{Claim: "Groups", Prefix: "team:"}}, nil, nil},

		// ─── value types ────────────────────────────────────────────────
		{"number", []TeamRule{{Claim: "level", Map: map[string][]string{"3": {"level-three"}}}}, []string{"level-three"}, nil},
		{"number as a team", []TeamRule{{Claim: "level", Value: true}}, []string{"3"}, nil},
		{"fraction", []TeamRule{{Claim: "ratio", Map: map[string][]string{"1.5": {"ratio"}}}}, []string{"ratio"}, nil},
		{"bool", []TeamRule{{Claim: "admin", Map: map[string][]string{"true": {"admins"}}}}, []string{"admins"}, nil},
		{"null is ignored", []TeamRule{{Claim: "nothing", Value: true}, {Claim: "nothing", Map: map[string][]string{"*": {"x"}}}}, nil, nil},
		{"an object is ignored, never stringified", []TeamRule{{Claim: "object", Value: true}, {Claim: "object", Map: map[string][]string{"*": {"x"}}}, {Claim: "object", Regex: "(.*)"}}, nil, nil},
		{"a list: only its scalars", []TeamRule{{Claim: "nested_list", Value: true}}, []string{"7", "false", "flat"}, nil},
		{"an empty string is no value", []TeamRule{{Claim: "empty", Map: map[string][]string{"*": {"x"}}}}, nil, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rules := NewTeamRules(tc.rules)
			if rules.Err() != nil {
				t.Fatalf("rules: %v", rules.Err())
			}
			got, rejected := rules.Resolve(jsonAttributes(t, sampleClaims))
			if !slices.Equal(got, tc.want) {
				t.Errorf("teams: got %v, want %v", got, tc.want)
			}
			if !slices.Equal(rejected, tc.wantRejected) {
				t.Errorf("rejected: got %q, want %q", rejected, tc.wantRejected)
			}
		})
	}
}

// TestTeamRules_DerivedNamesAreNotFolded: a name derived from an
// upstream value becomes a team only if it already is one, byte for
// byte. Case variants, padded values and Unicode lookalike forms of an
// existing team are dropped — they must never collapse onto it.
func TestTeamRules_DerivedNamesAreNotFolded(t *testing.T) {
	variants := []string{
		"PANDA", "Panda", "panda ", " panda", "panda\t", "panda\n",
		"panda\u00a0",   // no-break space
		"panda\u2003",   // em space
		"\u212aurtosis", // Kelvin sign for K
		"p\u0430nda",    // Cyrillic a
		"\uff50anda",    // fullwidth p
		"panda\u200b",   // zero-width space
		"panda\x00",     // NUL
		"pan/da", "pan:da", "", "-panda", ".panda",
	}

	forms := []struct {
		name  string
		rule  TeamRule
		value func(variant string) string
	}{
		{"prefix", TeamRule{Claim: "groups", Prefix: "team:"}, func(v string) string { return "team:" + v }},
		{"regex", TeamRule{Claim: "groups", Regex: "(?s)team:(.*)"}, func(v string) string { return "team:" + v }},
		{"bare", TeamRule{Claim: "groups", Value: true}, func(v string) string { return v }},
		{"split", TeamRule{Claim: "groups", Split: ",", Value: true}, func(v string) string { return "x," + v }},
	}
	for _, form := range forms {
		for _, variant := range variants {
			t.Run(fmt.Sprintf("%s/%q", form.name, variant), func(t *testing.T) {
				rules := NewTeamRules([]TeamRule{form.rule})
				if rules.Err() != nil {
					t.Fatalf("rules: %v", rules.Err())
				}
				got, _ := rules.Resolve(Attributes{"groups": []any{form.value(variant)}})
				if slices.Contains(got, "panda") || slices.Contains(got, "kurtosis") {
					t.Errorf("value %q became a privileged-looking team: %v", form.value(variant), got)
				}
				for _, team := range got {
					if !auth.ValidTeam(team) {
						t.Errorf("result %q is not in normal form", team)
					}
				}
			})
		}
	}

	// The genuine value still works.
	rules := NewTeamRules([]TeamRule{{Claim: "groups", Prefix: "team:"}})
	if got, _ := rules.Resolve(Attributes{"groups": []any{"team:panda"}}); !slices.Equal(got, []string{"panda"}) {
		t.Errorf("genuine value: %v", got)
	}
}

// TestTeamRules_MatchingFoldsASCIIOnly: prefixes and map keys compare
// ASCII letters case-insensitively and nothing else — a Kelvin sign is
// not a "k", a dotless i is not an "i".
func TestTeamRules_MatchingFoldsASCIIOnly(t *testing.T) {
	tests := []struct {
		name  string
		rule  TeamRule
		value string
		want  []string
	}{
		{"prefix: ASCII case", TeamRule{Claim: "g", Prefix: "team:"}, "TEAM:panda", []string{"panda"}},
		{"prefix: Kelvin sign is not k", TeamRule{Claim: "g", Prefix: "k:"}, "\u212a:panda", nil},
		{"prefix: long s is not s", TeamRule{Claim: "g", Prefix: "s:"}, "\u017f:panda", nil},
		{"map: ASCII case", TeamRule{Claim: "g", Map: map[string][]string{"staff": {"panda"}}}, "STAFF", []string{"panda"}},
		{"map: Kelvin sign is not k", TeamRule{Claim: "g", Map: map[string][]string{"kurtosis": {"panda"}}}, "\u212aurtosis", nil},
		{"map: dotless i is not i", TeamRule{Claim: "g", Map: map[string][]string{"admin": {"panda"}}}, "adm\u0131n", nil},
		{"map: trailing space is not trimmed", TeamRule{Claim: "g", Map: map[string][]string{"staff": {"panda"}}}, "staff ", nil},
		{"map: no-break space is not trimmed", TeamRule{Claim: "g", Map: map[string][]string{"staff": {"panda"}}}, "staff\u00a0", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rules := NewTeamRules([]TeamRule{tc.rule})
			if rules.Err() != nil {
				t.Fatalf("rules: %v", rules.Err())
			}
			if got, _ := rules.Resolve(Attributes{"g": tc.value}); !slices.Equal(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestGlobMatch(t *testing.T) {
	tests := []struct {
		pattern, value string
		want           bool
	}{
		{"ethpandaops", "ethpandaops", true},
		{"ethpandaops", "ethpandaops-evil", false},
		{"ethpandaops", "ethpandaops:core", false},
		{"ethpandaops", "xethpandaops", false},
		{"ethpandaops", "ethpandaop", false},
		{"ethpandaops:*", "ethpandaops:core", true},
		{"ethpandaops:*", "ethpandaops:", true},
		{"ethpandaops:*", "ethpandaops", false},
		{"ethpandaops:*", "ethpandaops-evil:core", false},
		{"ethpandaops:*", "ethpandaops:a:b/c", true}, // * crosses separators
		{"ethpandaops*", "ethpandaops-evil", true},   // why "org*" is the wrong key for an org
		{"*", "", true},
		{"*", "anything:at/all", true},
		{"", "", true},
		{"", "x", false},
		{"*@example.org", "alice@example.org", true},
		{"*@example.org", "alice@example.org.evil", false},
		{"*@example.org", "@example.org", true},
		{"a*b*c", "abc", true},
		{"a*b*c", "aXbYc", true},
		{"a*b*c", "aXbY", false},
		{"a**c", "ac", true},
		{"a*a*a*b", "aaaaaaaaaaaaaaaaaaaa", false},
		{"*a*", "bab", true},
		{"?", "a", false}, // no single-character wildcard
		{"[a-z]", "a", false},
		{"[a-z]", "[a-z]", true},
	}
	for _, tc := range tests {
		if got := globMatch(tc.pattern, tc.value); got != tc.want {
			t.Errorf("globMatch(%q, %q) = %t, want %t", tc.pattern, tc.value, got, tc.want)
		}
	}
}

// TestTeamRules_NoBacktracking feeds the worst inputs for a backtracking
// matcher — at the maximum lengths the rules accept — through a glob
// and a regex and expects them to finish at once.
func TestTeamRules_NoBacktracking(t *testing.T) {
	longA := strings.Repeat("a", maxRuleValueLen)
	rules := NewTeamRules([]TeamRule{
		{Claim: "g", Map: map[string][]string{strings.Repeat("a*", maxRulePatternLen/2-1) + "b": {"x"}}},
		{Claim: "g", Regex: "(a+)+b"},
		{Claim: "g", Regex: "(a|aa)+c"},
	})
	if rules.Err() != nil {
		t.Fatalf("rules: %v", rules.Err())
	}

	values := make([]any, 0, maxRuleValues)
	for range maxRuleValues {
		values = append(values, longA)
	}
	start := time.Now()
	got, _ := rules.Resolve(Attributes{"g": values})
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("resolve took %s", elapsed)
	}
	if got != nil {
		t.Errorf("unexpected teams: %v", got)
	}
}

// TestTeamRules_InputBounds: oversized values and lists are cut down or
// ignored rather than processed.
func TestTeamRules_InputBounds(t *testing.T) {
	rules := NewTeamRules([]TeamRule{{Claim: "g", Value: true}, {Claim: "s", Split: ",", Value: true}})

	tooLong := strings.Repeat("a", maxRuleValueLen+1)
	if got, rejected := rules.Resolve(Attributes{"g": tooLong}); got != nil || rejected != nil {
		t.Errorf("an oversized value was considered: %v / %d rejected", got, len(rejected))
	}

	many := make([]any, 0, maxRuleValues+500)
	for i := range maxRuleValues + 500 {
		many = append(many, fmt.Sprintf("t%04d", i))
	}
	got, _ := rules.Resolve(Attributes{"g": many})
	if len(got) != maxRuleValues {
		t.Errorf("list: %d values considered, want %d", len(got), maxRuleValues)
	}

	parts := make([]string, 0, maxRuleValues+500)
	for i := range maxRuleValues + 500 {
		parts = append(parts, fmt.Sprintf("s%04d", i))
	}
	got, _ = rules.Resolve(Attributes{"s": strings.Join(parts, ",")})
	if len(got) != maxRuleValues {
		t.Errorf("split: %d values considered, want %d", len(got), maxRuleValues)
	}

	huge := strings.Repeat("a,", maxRuleValueLen*maxRuleValues)
	if got, _ := rules.Resolve(Attributes{"s": huge}); got != nil {
		t.Errorf("an oversized string was split: %d teams", len(got))
	}
}

func TestTeamRules_ConfigErrors(t *testing.T) {
	tests := []struct {
		name    string
		rules   []TeamRule
		wantErr string
	}{
		{"no claim", []TeamRule{{Prefix: "team:"}}, "teamRules[0]: claim is required"},
		{"blank claim", []TeamRule{{Claim: "groups", Value: true}, {Claim: "  ", Value: true}}, "teamRules[1]: claim is required"},
		{"prefix and map", []TeamRule{{Claim: "g", Prefix: "x", Map: map[string][]string{"a": {"b"}}}}, "only one of prefix, map, regex and value may be set"},
		{"prefix and regex", []TeamRule{{Claim: "g", Prefix: "x", Regex: "(a)"}}, "only one of prefix, map, regex and value may be set"},
		{"map and regex", []TeamRule{{Claim: "g", Regex: "(a)", Map: map[string][]string{"a": {"b"}}}}, "only one of prefix, map, regex and value may be set"},
		{"value and prefix", []TeamRule{{Claim: "g", Prefix: "x", Value: true}}, "only one of prefix, map, regex and value may be set"},
		{"no form: not the rule that takes every value", []TeamRule{{Claim: "g"}}, `claim "g": one of prefix, map, regex or "value: true" is required`},
		{"only split", []TeamRule{{Claim: "g", Split: ","}}, `one of prefix, map, regex or "value: true" is required`},
		{"an empty map is no form", []TeamRule{{Claim: "g", Map: map[string][]string{}}}, `one of prefix, map, regex or "value: true" is required`},
		{"regex does not compile", []TeamRule{{Claim: "g", Regex: "(a"}}, `claim "g": regex:`},
		{"regex without a capture group", []TeamRule{{Claim: "g", Regex: "^eng-.+$"}}, "exactly one capture group (the team), has 0"},
		{"regex with two capture groups", []TeamRule{{Claim: "g", Regex: "^(a)-(b)$"}}, "exactly one capture group (the team), has 2"},
		{"regex with a backreference (not RE2)", []TeamRule{{Claim: "g", Regex: `(a)\1`}}, "regex:"},
		{"regex with a lookahead (not RE2)", []TeamRule{{Claim: "g", Regex: "(a)(?=b)"}}, "regex:"},
		{"regex too long", []TeamRule{{Claim: "g", Regex: "(" + strings.Repeat("a", maxRulePatternLen) + ")"}}, "regex is longer than"},
		{"prefix too long", []TeamRule{{Claim: "g", Prefix: strings.Repeat("a", maxRulePatternLen+1)}}, "prefix is longer than"},
		{"map key too long", []TeamRule{{Claim: "g", Map: map[string][]string{strings.Repeat("a", maxRulePatternLen+1): {"x"}}}}, "must be 1-256 bytes long"},
		{"empty map key", []TeamRule{{Claim: "g", Map: map[string][]string{"": {"x"}}}}, `map key "" must be`},
		{"map keys differing by case", []TeamRule{{Claim: "g", Map: map[string][]string{"Staff": {"x"}, "staff": {"y"}}}}, `map keys "Staff" and "staff" are the same key`},
		{"map value is not a team", []TeamRule{{Claim: "g", Map: map[string][]string{"staff": {"core devs"}}}}, `map key "staff": invalid team name(s) ["core devs"]`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateTeamRules(tc.rules)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("got %v, want an error containing %q", err, tc.wantErr)
			}
			// A provider that ignored the error still gets nothing from
			// the rejected rules.
			if got, _ := NewTeamRules(tc.rules).Resolve(Attributes{"g": "a"}); got != nil {
				t.Errorf("rejected rules produced teams: %v", got)
			}
		})
	}
}

func TestTokenAttributes(t *testing.T) {
	payload, _ := json.Marshal(map[string]any{"sub": "u1", "n": 12345678901234567890.0, "groups": []string{"a"}})
	good := "h." + base64.RawURLEncoding.EncodeToString(payload) + ".s"
	attrs, err := TokenAttributes(good)
	if err != nil {
		t.Fatalf("attributes: %v", err)
	}
	if attrs["sub"] != "u1" {
		t.Errorf("sub: %v", attrs["sub"])
	}

	for _, bad := range []string{"", "a.b", "a.b.c.d", "a.!!!.c", "a." + base64.RawURLEncoding.EncodeToString([]byte("[1]")) + ".c"} {
		if _, err := TokenAttributes(bad); err == nil {
			t.Errorf("TokenAttributes(%q): expected an error", bad)
		}
	}
}

// TestTeams covers the provider-facing resolver: static teams, capture
// at login with its warnings, restore from a session, and the silent
// per-request path.
func TestTeams(t *testing.T) {
	teams := NewTeams(
		[]string{"devnet"},
		[]TeamRule{{Claim: "groups", Prefix: "team:"}, {Claim: "groups", Map: map[string][]string{"ethpandaops": {"panda"}}}},
	)
	if teams.Err() != nil {
		t.Fatalf("teams: %v", teams.Err())
	}
	attrs := Attributes{"groups": []any{"team:lighthouse", "team:Geth", "ethpandaops"}}

	log, hook := test.NewNullLogger()
	captured := teams.Capture(log, attrs)
	if !slices.Equal(captured, []string{"lighthouse", "panda"}) {
		t.Errorf("captured: %v", captured)
	}
	entries := hook.AllEntries()
	if len(entries) != 1 || entries[0].Level != logrus.WarnLevel ||
		!strings.Contains(entries[0].Message, "not in normal form") {
		t.Fatalf("login log: %v", entries)
	}
	if rejected, _ := entries[0].Data["rejected"].(string); !strings.Contains(rejected, `"Geth"`) {
		t.Errorf("warning does not name the dropped value: %s", rejected)
	}

	if got := teams.With(captured); !slices.Equal(got, []string{"devnet", "lighthouse", "panda"}) {
		t.Errorf("with: %v", got)
	}

	hook.Reset()
	if got := teams.ForRequest(attrs); !slices.Equal(got, []string{"devnet", "lighthouse", "panda"}) {
		t.Errorf("per request: %v", got)
	}
	if got := teams.ForRequest(nil); !slices.Equal(got, []string{"devnet"}) {
		t.Errorf("per request without attributes: %v", got)
	}
	if n := len(hook.AllEntries()); n != 0 {
		t.Errorf("the per-request path logged %d entries", n)
	}

	if got := (Teams{}).ForRequest(attrs); got != nil {
		t.Errorf("zero value: %v", got)
	}
}

// TestTeamRules_RegexCannotEscapeTheAnchors: the whole-value match used
// to be built by pasting "^(?:" and ")$" around the operator's pattern.
// A pattern with an unbalanced parenthesis broke out of that:
// "team)|(.*" became "^(?:team)|(.*)$", which matches anything and
// captures it. Such patterns are refused now — they are not complete
// expressions on their own — and a pattern with a top-level alternation
// is anchored as a whole.
func TestTeamRules_RegexCannotEscapeTheAnchors(t *testing.T) {
	refused := []string{
		"team)|(.*",    // the reviewer's pattern: ^(?:team)|(.*)$
		"x)|(.*)|(?:y", // balances the pasted parentheses, two groups outside the anchors
		")|(.*",
		"a)(b",
		"(a))|((b)",
		"team:(.*))|(?:",
	}
	for _, pattern := range refused {
		err := ValidateTeamRules([]TeamRule{{Claim: "g", Regex: pattern}})
		if err == nil || !strings.Contains(err.Error(), "regex:") {
			t.Errorf("pattern %q: got %v, want it refused", pattern, err)
		}
		if got, _ := NewTeamRules([]TeamRule{{Claim: "g", Regex: pattern}}).Resolve(Attributes{"g": "panda"}); got != nil {
			t.Errorf("pattern %q produced %v", pattern, got)
		}
	}

	// Legitimate alternations stay inside the anchors.
	tests := []struct {
		pattern string
		value   string
		want    []string
	}{
		{"team:(a)|x", "team:a", []string{"a"}},
		{"team:(a)|x", "x", nil},               // matches, but the group took no part
		{"team:(a)|x", "team:a-and-more", nil}, // the whole value, not a prefix
		{"team:(a)|x", "prefix-x", nil},        // the alternative is anchored too
		{"x|team:(.*)", "evil x", nil},
		{"x|team:(.*)", "team:geth", []string{"geth"}},
		{"(?i)TEAM:([a-z]+)", "team:geth", []string{"geth"}},
		{"^team:([a-z]+)$", "team:geth", []string{"geth"}},
		{"^team:([a-z]+)$", "team:geth\nteam:panda", nil},
		{"(?m)^team:([a-z]+)$", "x\nteam:panda", nil}, // multi-line mode does not let a line stand for the value
		{"(?s)team:(.*)", "team:pan\nda", nil},        // matched, and then not a team name
		{"team:([a-z]+)(?:-dev)?", "team:geth-dev", []string{"geth"}},
	}
	for _, tc := range tests {
		rules := NewTeamRules([]TeamRule{{Claim: "g", Regex: tc.pattern}})
		if rules.Err() != nil {
			t.Errorf("pattern %q: %v", tc.pattern, rules.Err())
			continue
		}
		if got, _ := rules.Resolve(Attributes{"g": tc.value}); !slices.Equal(got, tc.want) {
			t.Errorf("pattern %q on %q: got %v, want %v", tc.pattern, tc.value, got, tc.want)
		}
	}
}
