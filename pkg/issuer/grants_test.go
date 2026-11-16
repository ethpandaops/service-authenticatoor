package issuer

import (
	"errors"
	"fmt"
	"maps"
	"math/rand"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ethpandaops/service-authenticatoor/pkg/auth"
	"github.com/ethpandaops/service-authenticatoor/pkg/protection"
)

// The grant tables of these tests map a team name to its grants. They
// are turned into one group per team, whose single member is that team
// at testProvider. baseTeam is a team every test identity has: its
// entry is what everyone in these tests is granted.
const (
	testProvider = "p"
	baseTeam     = "base"
)

// provs describes providers that accept every attribute path.
func provs(names ...string) []Provider {
	out := make([]Provider, 0, len(names))
	for _, name := range names {
		out = append(out, Provider{Name: name})
	}
	return out
}

// tableGrants turns a test table into a grants section.
func tableGrants(table map[string][]string) GrantsConfig {
	cfg := GrantsConfig{}
	for _, team := range slices.Sorted(maps.Keys(table)) {
		cfg.Groups = append(cfg.Groups, GrantGroup{
			Members:  []string{testProvider + "/team:" + team},
			Services: table[team],
		})
	}
	return cfg
}

// tableOf renders validated grants back in the shape of a test table.
func tableOf(g *ServiceGrants) map[string][]string {
	out := make(map[string][]string, len(g.Groups()))
	for _, group := range g.Groups() {
		team := strings.TrimPrefix(group.Members[0], testProvider+"/team:")
		out[team] = group.Services
	}
	return out
}

// teamsOf is the identity of a user who came through testProvider with
// these teams (and baseTeam).
func teamsOf(teams []string) Identity {
	return Identity{
		Subject:  "alice@example.com",
		Email:    "alice@example.com",
		Teams:    append(slices.Clone(teams), baseTeam),
		Provider: testProvider,
	}
}

// noToken is what directiveOf reports for an identity that no group
// names: there is no claim, because there is no token.
const noToken = "(no token)"

// directiveOf is g.Directive with ErrNotGranted spelled as noToken, so
// that tables can say which identities get a claim and which get no
// token.
func directiveOf(t *testing.T, g *ServiceGrants, id Identity, instanceWide string) string {
	t.Helper()
	claim, err := g.Directive(id, instanceWide)
	switch {
	case errors.Is(err, ErrNotGranted):
		if claim != "" {
			t.Fatalf("a refusal came with the claim %q", claim)
		}
		if g.Member(id) {
			t.Fatalf("Directive refused %+v, which Member says is named", id)
		}
		return noToken
	case err != nil:
		t.Fatalf("directive: %v", err)
	case !g.Member(id):
		t.Fatalf("Directive gave %q to %+v, which Member says no group names", claim, id)
	}
	return claim
}

func mustGrants(t *testing.T, table map[string][]string) *ServiceGrants {
	t.Helper()
	g, err := NewServiceGrants(tableGrants(table), provs(testProvider))
	if err != nil {
		t.Fatalf("grants: %v", err)
	}
	return g
}

func TestNewServiceGrants(t *testing.T) {
	tests := []struct {
		name    string
		in      map[string][]string
		want    map[string][]string
		wantErr string
	}{
		{"empty table grants nothing", map[string][]string{}, map[string][]string{}, ""},
		{"nil table grants nothing", nil, map[string][]string{}, ""},
		{
			"the documented example",
			map[string][]string{"panda": {"all"}, "lighthouse": {"dora"}, baseTeam: {}},
			map[string][]string{"panda": {"all"}, "lighthouse": {"dora"}, baseTeam: {}},
			"",
		},
		{
			"grants are normalized, sorted, de-duplicated",
			map[string][]string{"panda": {"Spamoor", "assertoor", "spamoor "}},
			map[string][]string{"panda": {"assertoor", "spamoor"}},
			"",
		},
		{"a team name is not folded: uppercase", map[string][]string{"Panda": {"all"}}, nil, `"Panda" is not a team name`},
		{"a team name is not folded: padding", map[string][]string{" panda": {"all"}}, nil, `" panda" is not a team name`},
		{"dotted team name", map[string][]string{"eth.dev": {"dora"}}, map[string][]string{"eth.dev": {"dora"}}, ""},
		{"invalid team name", map[string][]string{"core devs": {"all"}}, nil, `"core devs" is not a team name`},
		{"prefixed team name", map[string][]string{"team:panda": {"all"}}, nil, `"team:panda" is not a team name`},
		{"empty team name", map[string][]string{"": {"all"}}, nil, `the value after "team:" is empty`},
		{"no wildcard team", map[string][]string{"pan*": {"all"}}, nil, "there are no wildcards"},
		{"a case variant next to a team is an error, not a second entry", map[string][]string{"panda": {"all"}, "PANDA": {}}, nil, `"PANDA" is not a team name`},
		{"service with underscore", map[string][]string{"panda": {"my_tool"}}, map[string][]string{"panda": {"my_tool"}}, ""},
		{"service starting with an underscore", map[string][]string{"panda": {"_tool"}}, nil, `invalid service name "_tool"`},
		{"service with a directive prefix", map[string][]string{"panda": {"+dora"}}, nil, `invalid service name "+dora"`},
		{"service with a comma", map[string][]string{"panda": {"a,+all"}}, nil, `invalid service name "a,+all"`},
		{"wildcard as a service", map[string][]string{"panda": {"*"}}, nil, `invalid service name "*"`},
		{"empty service", map[string][]string{"panda": {""}}, nil, `invalid service name ""`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g, err := NewServiceGrants(tableGrants(tc.in), provs(testProvider))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error: got %v, want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := tableOf(g); !maps.EqualFunc(got, tc.want, slices.Equal[[]string]) {
				t.Errorf("table: got %v, want %v", got, tc.want)
			}
		})
	}
}

// TestServiceGrants_Directive checks the emitted string and — through
// auth.ServiceAllowed, the function resource servers evaluate it with —
// that it means exactly what was granted, including for a service
// ("buildoor") that no grant and no directive mentions.
func TestServiceGrants_Directive(t *testing.T) {
	table := map[string][]string{
		"panda":      {"all"},
		"lighthouse": {"dora"},
		"geth":       {"spamoor", "assertoor"},
		"nobody":     {},
	}
	withEveryone := map[string][]string{
		"panda":      {"all"},
		"lighthouse": {"dora"},
		baseTeam:     {"assertoor"},
	}
	everyoneAll := map[string][]string{baseTeam: {"all"}}

	const probeServices = "dora spamoor assertoor buildoor"

	tests := []struct {
		name         string
		table        map[string][]string
		teams        []string
		instanceWide string
		want         string
		allowed      string // space-separated subset of probeServices
	}{
		{"one team, one service", table, []string{"lighthouse"}, "", "-all,+dora", "dora"},
		{"one team, several services, sorted", table, []string{"geth"}, "", "-all,+assertoor,+spamoor", "spamoor assertoor"},
		{
			"union across teams", table, []string{"geth", "lighthouse"}, "",
			"-all,+assertoor,+dora,+spamoor", "dora spamoor assertoor",
		},
		{"union is order-independent", table, []string{"lighthouse", "geth"}, "", "-all,+assertoor,+dora,+spamoor", "dora spamoor assertoor"},
		{"all, no instance-wide directive", table, []string{"panda"}, "", "+all", probeServices},
		{"all wins in a union", table, []string{"lighthouse", "panda"}, "", "+all", probeServices},
		{
			"all yields the instance-wide directive", table, []string{"panda"}, "+all,-spamoor",
			"+all,-spamoor", "dora assertoor buildoor",
		},
		{
			"all cannot exceed a restrictive instance-wide directive", table, []string{"panda"}, "-all,+dora",
			"-all,+dora", "dora",
		},
		{
			"upper bound drops a granted service the instance denies", table, []string{"geth"}, "+all,-spamoor",
			"-all,+assertoor", "assertoor",
		},
		{
			"upper bound: instance allows only another service", table, []string{"lighthouse"}, "-all,+spamoor",
			"-all", "",
		},
		{"team with an empty grant", table, []string{"nobody"}, "", "-all", ""},
		{"team with an empty grant, instance-wide set", table, []string{"nobody"}, "+all", "-all", ""},
		{"team with an empty grant next to a team without an entry", table, []string{"reth", "nobody"}, "", "-all", ""},
		{"team without an entry", table, []string{"reth"}, "", noToken, ""},
		{"identity without teams", table, nil, "", noToken, ""},
		{"identity without teams, instance-wide set", table, nil, "+all", noToken, ""},
		{"everyone grant alone", withEveryone, nil, "", "-all,+assertoor", "assertoor"},
		{"everyone grant for an unlisted team", withEveryone, []string{"reth"}, "", "-all,+assertoor", "assertoor"},
		{"everyone grant adds to a team's", withEveryone, []string{"lighthouse"}, "", "-all,+assertoor,+dora", "dora assertoor"},
		{"everyone: all", everyoneAll, nil, "", "+all", probeServices},
		{"everyone: all, bounded by the instance", everyoneAll, nil, "+all,-buildoor", "+all,-buildoor", "dora spamoor assertoor"},
		{"empty table", map[string][]string{}, []string{"panda"}, "", noToken, ""},
		{"empty table, instance-wide set", map[string][]string{}, []string{"panda"}, "+all", noToken, ""},
		{"team names are matched exactly, never folded", table, []string{" Lighthouse ", "LIGHTHOUSE", "lighthouse\u00a0"}, "", noToken, ""},
		{"no prefix matching of team names", table, []string{"pand", "pandas", "lighthouse2"}, "", noToken, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := directiveOf(t, mustGrants(t, tc.table), teamsOf(tc.teams), tc.instanceWide)
			if got != tc.want {
				t.Errorf("directive: got %q, want %q", got, tc.want)
			}
			if got == "" {
				t.Error("an empty directive means basic access to every service; it must never be emitted")
			}
			if got == noToken {
				return // no claim to evaluate
			}
			allowed := strings.Fields(tc.allowed)
			for _, service := range strings.Fields(probeServices) {
				if got, want := auth.ServiceAllowed(got, service), slices.Contains(allowed, service); got != want {
					t.Errorf("ServiceAllowed(%q, %q) = %t, want %t", tc.want, service, got, want)
				}
			}
		})
	}
}

// TestIssuer_ServicesClaim covers the issuer's side: without a grant
// table the claim is the instance-wide string as before; with one it
// follows the token's teams, and an identity that no group names gets
// no token — which is about being named, not about what is granted.
func TestIssuer_ServicesClaim(t *testing.T) {
	grants := map[string][]string{"panda": {"all"}, "lighthouse": {"dora"}, baseTeam: {}}

	tests := []struct {
		name         string
		instanceWide string
		grants       map[string][]string // nil: section absent
		teams        []string
		want         string // "": the claim must be absent from the payload; noToken: ErrNotGranted
	}{
		{"absent section, no instance-wide directive", "", nil, []string{"lighthouse"}, ""},
		{"absent section, instance-wide directive", "+all,-spamoor", nil, []string{"lighthouse"}, "+all,-spamoor"},
		{"absent section, no teams", "+all,-spamoor", nil, nil, "+all,-spamoor"},
		{"granted service", "", grants, []string{"lighthouse"}, "-all,+dora"},
		{"all", "", grants, []string{"panda"}, "+all"},
		{"all, instance-wide directive", "+all,-spamoor", grants, []string{"panda"}, "+all,-spamoor"},
		// baseTeam is named by a group that grants nothing: every
		// identity of this table is a member, so each gets its token.
		{"no teams", "", grants, nil, "-all"},
		{"unlisted team", "", grants, []string{"reth"}, "-all"},
		{"invalid team names grant nothing", "", grants, []string{"panda!", "team:panda"}, "-all"},
		{"named by no group", "", map[string][]string{"panda": {"all"}}, []string{"reth"}, noToken},
		{"named by no group, instance-wide directive", "+all", map[string][]string{"panda": {"all"}}, nil, noToken},
		{"invalid team names name nobody", "", map[string][]string{"panda": {"all"}}, []string{"panda!", "team:panda"}, noToken},
		{"present but empty section", "", map[string][]string{}, []string{"panda"}, noToken},
		{"present but empty section, instance-wide directive", "+all", map[string][]string{}, nil, noToken},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key, err := GenerateRSAKey()
			if err != nil {
				t.Fatalf("genkey: %v", err)
			}
			cfg := Config{
				ActiveKey:       key,
				Issuer:          "https://auth.test.example",
				DefaultAudience: []string{"test.example"},
				Services:        tc.instanceWide,
				TTL:             30 * time.Minute,
			}
			if tc.grants != nil {
				cfg.Grants = mustGrants(t, tc.grants)
			}
			iss, err := NewRS256Issuer(cfg)
			if err != nil {
				t.Fatalf("newissuer: %v", err)
			}

			tok, claims, err := iss.IssueFor(teamsOf(tc.teams), nil)
			if granted := iss.Granted(teamsOf(tc.teams)); granted != (tc.want != noToken) {
				t.Errorf("Granted = %t", granted)
			}
			if tc.want == noToken {
				if !errors.Is(err, ErrNotGranted) || tok != "" || claims != nil {
					t.Fatalf("got token %q, claims %v, err %v; want ErrNotGranted and nothing else", tok, claims, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("issue: %v", err)
			}
			if claims.Services != tc.want {
				t.Errorf("returned claims: got %q, want %q", claims.Services, tc.want)
			}
			raw, present := rawPayload(t, tok)["services"]
			switch {
			case tc.want == "" && present:
				t.Errorf("services claim must be omitted, payload has %v", raw)
			case tc.want != "" && raw != tc.want:
				t.Errorf("payload services: got %v, want %q", raw, tc.want)
			}
		})
	}
}

// legacyServiceAllowed is a verbatim copy of auth.ServiceAllowed as
// released in v0.0.3 (upstream/main, pkg/auth/services.go) — the parser
// in every resource server deployed before feature grants existed. It
// reads a directive with feature segments ("+svc:f1") as an unknown
// service name and skips it. The tests below run every emitted claim
// through it to prove that an authenticatoor upgrade neither locks such
// a server out nor lets anyone in wrongly. Reference only; do not use it
// elsewhere.
func legacyServiceAllowed(directives, service string) bool {
	if directives == "" || service == "" {
		return true
	}
	service = strings.ToLower(strings.TrimSpace(service))
	if service == "" {
		return true
	}

	allowed := true
	for _, raw := range strings.Split(directives, ",") {
		raw = strings.TrimSpace(raw)
		if len(raw) < 2 {
			continue
		}
		op := raw[0]
		if op != '+' && op != '-' {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(raw[1:]))
		if name == "" {
			continue
		}
		if name != "all" && name != service {
			continue
		}
		allowed = op == '+'
	}
	return allowed
}

func TestNewServiceGrants_Features(t *testing.T) {
	tests := []struct {
		name    string
		in      map[string][]string
		want    map[string][]string // the normalized table
		wantErr []string            // substrings of the error
	}{
		{"service with features", map[string][]string{"lh": {"dora:roll:hold"}}, map[string][]string{"lh": {"dora:hold:roll"}}, nil},
		{"every feature of a service", map[string][]string{"lh": {"dora:all"}}, map[string][]string{"lh": {"dora:all"}}, nil},
		{"all subsumes named features", map[string][]string{"lh": {"dora:roll:all", "dora:hold"}}, map[string][]string{"lh": {"dora:all"}}, nil},
		{"entries for one service merge", map[string][]string{"lh": {"dora", "dora:roll", "dora:hold"}}, map[string][]string{"lh": {"dora:hold:roll"}}, nil},
		{"all with a feature", map[string][]string{"ops": {"all:logs"}}, map[string][]string{"ops": {"all:logs"}}, nil},
		{"everything", map[string][]string{"panda": {"all:all"}}, map[string][]string{"panda": {"all:all"}}, nil},
		{
			"all sorts first", map[string][]string{"ops": {"dora:roll", "all", "assertoor"}},
			map[string][]string{"ops": {"all", "assertoor", "dora:roll"}}, nil,
		},
		{"case and whitespace", map[string][]string{"lh": {" Dora : Roll "}}, map[string][]string{"lh": {"dora:roll"}}, nil},
		{"svc:basic is svc", map[string][]string{"lh": {"dora:basic"}}, map[string][]string{"lh": {"dora"}}, nil},
		{"basic next to features", map[string][]string{"lh": {"dora:basic:roll"}}, map[string][]string{"lh": {"dora:roll"}}, nil},
		{"all:basic is all", map[string][]string{"ops": {"all:basic"}}, map[string][]string{"ops": {"all"}}, nil},
		{"basic cannot be denied either", map[string][]string{"lh": {"dora:-basic"}}, nil, []string{"cannot deny"}},
		{"prefix feature", map[string][]string{"lh": {"spamoor:user*"}}, map[string][]string{"lh": {"spamoor:user*"}}, nil},
		{
			"prefix features are kept as written, next to names they cover",
			map[string][]string{"lh": {"spamoor:user*:user-view:u*:user*"}},
			map[string][]string{"lh": {"spamoor:u*:user*:user-view"}}, nil,
		},
		{"all drops prefixes too", map[string][]string{"lh": {"spamoor:user*:all"}}, map[string][]string{"lh": {"spamoor:all"}}, nil},
		{"a lone * is all", map[string][]string{"lh": {"spamoor:*"}}, map[string][]string{"lh": {"spamoor:all"}}, nil},
		{"prefix on all services", map[string][]string{"ops": {"all:log*"}}, map[string][]string{"ops": {"all:log*"}}, nil},
		{"wildcard in the middle", map[string][]string{"lh": {"spamoor:us*er"}}, nil, []string{`invalid feature "us*er"`, "only be the last character"}},
		{"wildcard at the start", map[string][]string{"lh": {"spamoor:*admin"}}, nil, []string{`invalid feature "*admin"`, "last character"}},
		{"two wildcards", map[string][]string{"lh": {"spamoor:u**"}}, nil, []string{`invalid feature "u**"`}},
		{"wildcard service", map[string][]string{"lh": {"spam*:user"}}, nil, []string{`invalid service name "spam*"`}},
		{"lone wildcard service", map[string][]string{"lh": {"*"}}, nil, []string{`invalid service name "*"`}},
		{"denied prefix", map[string][]string{"lh": {"spamoor:-user*"}}, nil, []string{"cannot deny"}},
		{"bare forms are unchanged", map[string][]string{"panda": {"all"}, "lh": {"dora"}}, map[string][]string{"panda": {"all"}, "lh": {"dora"}}, nil},

		{"denied service", map[string][]string{"lh": {"-dora"}}, nil, []string{`invalid grant "-dora"`, "cannot deny", "added up", "order"}},
		{"denied feature", map[string][]string{"lh": {"dora:-roll"}}, nil, []string{`invalid grant "dora:-roll"`, "cannot deny"}},
		{"all except a feature", map[string][]string{"lh": {"dora:all:-roll"}}, nil, []string{`invalid grant "dora:all:-roll"`, "cannot deny"}},
		{"denied all", map[string][]string{"lh": {"-all"}}, nil, []string{"cannot deny"}},
		{"plus sign", map[string][]string{"lh": {"+dora:roll"}}, nil, []string{`invalid service name "+dora"`}},
		{"empty feature", map[string][]string{"lh": {"dora:"}}, nil, []string{`invalid feature name "" in grant "dora:"`}},
		{"empty feature in the middle", map[string][]string{"lh": {"dora::roll"}}, nil, []string{`invalid feature name ""`}},
		{
			"underscores in names", map[string][]string{"lh": {"faucet:drop_100eth", "my_tool:drop_*"}},
			map[string][]string{"lh": {"faucet:drop_100eth", "my_tool:drop_*"}}, nil,
		},
		{"feature starting with an underscore", map[string][]string{"lh": {"dora:_roll"}}, nil, []string{`invalid feature name "_roll"`}},
		{"feature with a dot", map[string][]string{"lh": {"dora:v1.roll"}}, nil, []string{`invalid feature name "v1.roll"`}},
		{"feature with a comma", map[string][]string{"lh": {"dora:roll,+all"}}, nil, []string{`invalid feature name "roll,+all"`}},
		{"empty service before features", map[string][]string{"lh": {":roll"}}, nil, []string{`invalid service name ""`}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g, err := NewServiceGrants(tableGrants(tc.in), provs(testProvider))
			if tc.wantErr != nil {
				if err == nil {
					t.Fatal("expected an error")
				}
				for _, want := range tc.wantErr {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("error %q does not contain %q", err, want)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := tableOf(g); !maps.EqualFunc(got, tc.want, slices.Equal[[]string]) {
				t.Errorf("table: got %v, want %v", got, tc.want)
			}
		})
	}
}

// featureCases are representative grant tables with the exact claim they
// emit and what that claim grants. They are shared by the emission test
// and the old-parser compatibility test.
var featureCases = []struct {
	name         string
	table        map[string][]string
	teams        []string
	instanceWide string
	want         string
	base         string // space-separated services with base access, of featureProbeServices
	grants       string // space-separated "service:feature" pairs granted, of the probe grid
}{
	{
		"bare service: base, no features",
		map[string][]string{"lh": {"dora"}}, []string{"lh"}, "",
		"-all,+dora", "dora", "",
	},
	{
		"svc:basic is the bare service; basic is never emitted",
		map[string][]string{"lh": {"dora:basic"}}, []string{"lh"}, "",
		"-all,+dora", "dora", "",
	},
	{
		"basic written next to a feature",
		map[string][]string{"lh": {"dora:basic:roll"}, "ops": {"all:basic"}}, []string{"lh"}, "",
		"-all,+dora,+dora:roll", "dora", "dora:roll",
	},
	{
		"service with features",
		map[string][]string{"lh": {"dora:roll:hold"}}, []string{"lh"}, "",
		"-all,+dora,+dora:hold:roll", "dora", "dora:hold dora:roll",
	},
	{
		"prefix grant: emitted as written, sorted with the other features",
		map[string][]string{"lh": {"dora:roll:h*"}}, []string{"lh"}, "",
		"-all,+dora,+dora:h*:roll", "dora", "dora:hold dora:roll",
	},
	{
		"prefix grants are not folded: union keeps each as written",
		map[string][]string{"a": {"dora:ho*:hold"}, "b": {"dora:h*"}}, []string{"a", "b"}, "",
		"-all,+dora,+dora:h*:ho*:hold", "dora", "dora:hold",
	},
	{
		"prefix grant on every service",
		map[string][]string{"ops": {"all:lo*"}, "lh": {"dora:lo*:roll"}}, []string{"ops", "lh"}, "",
		"+all,+all:lo*,+dora:roll", "spamoor dora assertoor buildoor",
		"spamoor:logs dora:logs dora:roll assertoor:logs buildoor:logs",
	},
	{
		"service with every feature",
		map[string][]string{"lh": {"dora:all"}}, []string{"lh"}, "",
		"-all,+dora,+dora:all", "dora", "dora:hold dora:roll dora:logs",
	},
	{
		"the brief's example: two services, one with features",
		map[string][]string{"lh": {"spamoor", "dora:hold:roll"}}, []string{"lh"}, "",
		"-all,+dora,+dora:hold:roll,+spamoor", "spamoor dora", "dora:hold dora:roll",
	},
	{
		"union across teams: svc + svc:f1",
		map[string][]string{"a": {"dora"}, "b": {"dora:roll"}}, []string{"a", "b"}, "",
		"-all,+dora,+dora:roll", "dora", "dora:roll",
	},
	{
		"union across teams: svc + svc:f1 + svc:all",
		map[string][]string{"a": {"dora"}, "b": {"dora:roll"}, "c": {"dora:all"}}, []string{"a", "b", "c"}, "",
		"-all,+dora,+dora:all", "dora", "dora:hold dora:roll dora:logs",
	},
	{
		"union across teams: features of different teams add up",
		map[string][]string{"a": {"dora:roll", "spamoor:logs"}, "b": {"dora:hold"}}, []string{"b", "a"}, "",
		"-all,+dora,+dora:hold:roll,+spamoor,+spamoor:logs", "spamoor dora",
		"spamoor:logs dora:hold dora:roll",
	},
	{
		"everyone grant with a feature",
		map[string][]string{baseTeam: {"assertoor:logs"}, "lh": {"dora:roll"}}, []string{"lh"}, "",
		"-all,+assertoor,+assertoor:logs,+dora,+dora:roll", "assertoor dora",
		"assertoor:logs dora:roll",
	},
	{
		"all: base everywhere, no features",
		map[string][]string{"panda": {"all"}}, []string{"panda"}, "",
		"+all", "spamoor dora assertoor buildoor", "",
	},
	{
		"all:all: everything",
		map[string][]string{"panda": {"all:all"}}, []string{"panda"}, "",
		"+all,+all:all", "spamoor dora assertoor buildoor",
		"spamoor:hold spamoor:roll spamoor:logs dora:hold dora:roll dora:logs " +
			"assertoor:hold assertoor:roll assertoor:logs buildoor:hold buildoor:roll buildoor:logs",
	},
	{
		"all:f1: one feature everywhere",
		map[string][]string{"ops": {"all:logs"}}, []string{"ops"}, "",
		"+all,+all:logs", "spamoor dora assertoor buildoor",
		"spamoor:logs dora:logs assertoor:logs buildoor:logs",
	},
	{
		"the brief's example: all plus a service feature",
		map[string][]string{"ops": {"all", "dora:roll"}}, []string{"ops"}, "",
		"+all,+dora:roll", "spamoor dora assertoor buildoor", "dora:roll",
	},
	{
		"all:f1 plus service features: only what goes beyond",
		map[string][]string{"ops": {"all:logs"}, "lh": {"dora:logs:roll", "spamoor:logs"}}, []string{"ops", "lh"}, "",
		"+all,+all:logs,+dora:roll", "spamoor dora assertoor buildoor",
		"spamoor:logs dora:logs dora:roll assertoor:logs buildoor:logs",
	},
	{
		"all plus svc:all",
		map[string][]string{"ops": {"all"}, "lh": {"dora:all"}}, []string{"ops", "lh"}, "",
		"+all,+dora:all", "spamoor dora assertoor buildoor",
		"dora:hold dora:roll dora:logs",
	},
	{
		"all:all subsumes everything else",
		map[string][]string{"panda": {"all:all"}, "lh": {"dora:roll", "spamoor"}}, []string{"lh", "panda"}, "",
		"+all,+all:all", "spamoor dora assertoor buildoor",
		"spamoor:hold spamoor:roll spamoor:logs dora:hold dora:roll dora:logs " +
			"assertoor:hold assertoor:roll assertoor:logs buildoor:hold buildoor:roll buildoor:logs",
	},
	{
		"no grant", map[string][]string{"lh": {"dora:roll"}}, []string{"reth"}, "",
		noToken, "", "",
	},
	{
		"no teams", map[string][]string{"panda": {"all:all"}}, nil, "",
		noToken, "", "",
	},
	{
		"named by a group that grants nothing", map[string][]string{"lh": {}}, []string{"lh"}, "",
		"-all", "", "",
	},

	// ─── the instance-wide upper bound ──────────────────────────────────
	{
		"bound denies a service: no directive at all, so no features",
		map[string][]string{"lh": {"dora:roll", "spamoor:logs"}}, []string{"lh"}, "+all,-spamoor",
		"-all,+dora,+dora:roll", "dora", "dora:roll",
	},
	{
		"bound allows only another service",
		map[string][]string{"lh": {"dora:all"}}, []string{"lh"}, "-all,+spamoor",
		"-all", "", "",
	},
	{
		"all:all under a deny-list bound",
		map[string][]string{"panda": {"all:all"}}, []string{"panda"}, "+all,-spamoor",
		"+all,-spamoor,+all:all,-spamoor", "dora assertoor buildoor",
		"dora:hold dora:roll dora:logs assertoor:hold assertoor:roll assertoor:logs " +
			"buildoor:hold buildoor:roll buildoor:logs",
	},
	{
		"all:all under an allow-list bound",
		map[string][]string{"panda": {"all:all"}}, []string{"panda"}, "-all,+dora,+assertoor",
		"-all,+dora,+assertoor,+assertoor:all,+dora:all", "dora assertoor",
		"dora:hold dora:roll dora:logs assertoor:hold assertoor:roll assertoor:logs",
	},
	{
		"all plus a service feature under a deny-list bound",
		map[string][]string{"ops": {"all", "dora:roll", "spamoor:logs"}}, []string{"ops"}, "+all,-spamoor",
		"+all,-spamoor,+dora:roll", "dora assertoor buildoor", "dora:roll",
	},
	{
		"all without features: the bound as it stands",
		map[string][]string{"panda": {"all"}}, []string{"panda"}, "+all,-spamoor",
		"+all,-spamoor", "dora assertoor buildoor", "",
	},
}

const (
	featureProbeServices = "spamoor dora assertoor buildoor"
	featureProbeFeatures = "hold roll logs"
)

// TestServiceGrants_FeatureDirective pins the exact emitted claim for
// representative tables and checks, with the evaluators a resource
// server uses, that it grants what was configured and nothing else.
func TestServiceGrants_FeatureDirective(t *testing.T) {
	for _, tc := range featureCases {
		t.Run(tc.name, func(t *testing.T) {
			got := directiveOf(t, mustGrants(t, tc.table), teamsOf(tc.teams), tc.instanceWide)
			if got != tc.want {
				t.Fatalf("directive: got %q, want %q", got, tc.want)
			}
			if got == noToken {
				return // no claim to evaluate
			}

			base := strings.Fields(tc.base)
			grants := strings.Fields(tc.grants)
			for _, service := range strings.Fields(featureProbeServices) {
				if got, want := auth.ServiceAllowed(tc.want, service), slices.Contains(base, service); got != want {
					t.Errorf("ServiceAllowed(%q, %q) = %t, want %t", tc.want, service, got, want)
				}
				for _, feature := range strings.Fields(featureProbeFeatures) {
					// Default-deny features need the grant; default-allow
					// features come with base access (the emission never
					// excludes anything).
					want := slices.Contains(grants, service+":"+feature)
					if got := auth.FeatureAllowed(tc.want, service, feature, auth.FeatureDefaultDeny); got != want {
						t.Errorf("FeatureAllowed(%q, %q, %q, deny) = %t, want %t", tc.want, service, feature, got, want)
					}
					wantAllow := slices.Contains(base, service)
					if got := auth.FeatureAllowed(tc.want, service, feature, auth.FeatureDefaultAllow); got != wantAllow {
						t.Errorf("FeatureAllowed(%q, %q, %q, allow) = %t, want %t", tc.want, service, feature, got, wantAllow)
					}
				}
			}
		})
	}
}

// TestServiceGrants_DirectiveIsDeterministic: the claim depends on what
// is granted, not on the order of teams, of entries in a list, or of
// features in an entry.
func TestServiceGrants_DirectiveIsDeterministic(t *testing.T) {
	const want = "-all,+assertoor,+dora,+dora:hold:roll,+spamoor,+spamoor:logs:plugins"

	tables := []map[string][]string{
		{"a": {"dora:hold:roll", "spamoor:plugins"}, "b": {"assertoor", "spamoor:logs"}},
		{"a": {"spamoor:plugins", "dora:roll:hold"}, "b": {"spamoor:logs", "assertoor"}},
		{"a": {"dora:roll", "dora:hold", "dora", "spamoor:plugins:plugins"}, "b": {"spamoor:logs", "spamoor", "assertoor"}},
		{"a": {"assertoor", "spamoor:logs:plugins"}, "b": {"dora:hold:roll"}, baseTeam: {"spamoor"}},
	}
	for i, table := range tables {
		g := mustGrants(t, table)
		for _, teams := range [][]string{{"a", "b"}, {"b", "a"}, {"b", "a", "b", "zzz"}} {
			for range 20 { // map iteration order varies between runs
				if got := directiveOf(t, g, teamsOf(teams), ""); got != want {
					t.Fatalf("table %d, teams %v: got %q, want %q", i, teams, got, want)
				}
			}
		}
	}
}

// TestServiceGrants_OldVerifiersAgreeOnBaseAccess is the upgrade
// guarantee. Every claim this issuer can emit — the representative
// tables above plus a large generated set of grant tables, team
// combinations and instance-wide directives — is evaluated for base
// access by the v0.0.3 parser and by the current one. They must agree
// with each other and with what was configured: base access to a
// service iff it is granted and the instance-wide directive allows it.
// Features are checked against the configuration with the current
// evaluator: a default-deny feature iff it is granted, a default-allow
// feature iff the service is.
func TestServiceGrants_OldVerifiersAgreeOnBaseAccess(t *testing.T) {
	services := []string{"spamoor", "dora", "assertoor", "buildoor", "never-mentioned"}
	features := []string{"hold", "roll", "logs", "log-view", "h", "never-granted"}

	check := func(t *testing.T, table map[string][]string, teams []string, instanceWide string) {
		t.Helper()
		g := mustGrants(t, table)
		claim := directiveOf(t, g, teamsOf(teams), instanceWide)
		if claim == "" {
			t.Fatalf("empty claim for %v %v %q", table, teams, instanceWide)
		}
		// Named by a group, computed independently: one of the
		// identity's teams has an entry, whatever is in it.
		_, named := table[baseTeam]
		for _, team := range teams {
			if _, ok := table[team]; ok {
				named = true
			}
		}
		if named != (claim != noToken) {
			t.Fatalf("named by a group: %t, but the claim is %q (table %v teams %v)", named, claim, table, teams)
		}
		if !named {
			return // no token, so nothing for a verifier to read
		}
		if strings.Contains(claim, auth.FeatureBasic) {
			t.Fatalf("claim %q spells out basic; old verifiers cannot read that", claim)
		}

		// What the configuration says, computed independently of the
		// emission code: walk the raw entries of the identity's teams.
		entries := slices.Clone(table[baseTeam])
		for _, team := range teams {
			entries = append(entries, table[team]...)
		}
		grantedBase := func(service string) bool {
			for _, e := range entries {
				name, _, _ := strings.Cut(e, ":")
				if name == GrantAll || name == service {
					return true
				}
			}
			return false
		}
		grantedFeature := func(service, feature string) bool {
			for _, e := range entries {
				fields := strings.Split(e, ":")
				if fields[0] != GrantAll && fields[0] != service {
					continue
				}
				for _, f := range fields[1:] {
					prefix, isPrefix := strings.CutSuffix(f, "*")
					if f == GrantAll || f == feature || (isPrefix && strings.HasPrefix(feature, prefix)) {
						return true
					}
				}
			}
			return false
		}

		for _, service := range services {
			wantBase := grantedBase(service) && legacyServiceAllowed(instanceWide, service)
			if got := legacyServiceAllowed(claim, service); got != wantBase {
				t.Errorf("v0.0.3 verifier: base access to %s = %t, want %t\n  table %v teams %v bound %q\n  claim %q",
					service, got, wantBase, table, teams, instanceWide, claim)
			}
			if got := auth.ServiceAllowed(claim, service); got != wantBase {
				t.Errorf("current verifier: base access to %s = %t, want %t\n  table %v teams %v bound %q\n  claim %q",
					service, got, wantBase, table, teams, instanceWide, claim)
			}
			for _, def := range []auth.FeatureDefault{auth.FeatureDefaultDeny, auth.FeatureDefaultAllow} {
				if got := auth.FeatureAllowed(claim, service, auth.FeatureBasic, def); got != wantBase {
					t.Errorf("basic on %s (mode %d) = %t, want %t\n  claim %q", service, def, got, wantBase, claim)
				}
			}
			for _, feature := range features {
				want := wantBase && grantedFeature(service, feature)
				if got := auth.FeatureAllowed(claim, service, feature, auth.FeatureDefaultDeny); got != want {
					t.Errorf("default-deny feature %s:%s = %t, want %t\n  table %v teams %v bound %q\n  claim %q",
						service, feature, got, want, table, teams, instanceWide, claim)
				}
				if got := auth.FeatureAllowed(claim, service, feature, auth.FeatureDefaultAllow); got != wantBase {
					t.Errorf("default-allow feature %s:%s = %t, want %t\n  table %v teams %v bound %q\n  claim %q",
						service, feature, got, wantBase, table, teams, instanceWide, claim)
				}
			}
		}
	}

	for _, tc := range featureCases {
		check(t, tc.table, tc.teams, tc.instanceWide)
	}

	entryPool := []string{
		"all", "all:all", "all:logs", "all:hold:roll",
		"spamoor", "spamoor:all", "spamoor:logs", "spamoor:hold:roll",
		"dora", "dora:all", "dora:roll", "dora:hold:logs",
		"assertoor", "assertoor:logs", "buildoor:all",
		"spamoor:basic", "dora:basic:roll", "all:basic", "assertoor:all:basic",
		"spamoor:lo*", "dora:h*:roll", "all:log*", "assertoor:*", "buildoor:b*", "all:ho*:never*",
	}
	bounds := []string{
		"", "", "", "+all", "-all", "+all,-spamoor", "+all,-spamoor,-buildoor", "-all,+dora",
		"-all,+dora,+assertoor", "-spamoor", "+spamoor", "-all,+all", "+all,-all",
		"-all,+spamoor,-spamoor", "+all,-dora,+dora", " +ALL , -Spamoor ", "nonsense,-buildoor",
	}
	teamNames := []string{"t1", "t2", "t3"}

	rng := rand.New(rand.NewSource(20261114))
	for range 5000 {
		table := make(map[string][]string, 4)
		for _, team := range append(slices.Clone(teamNames), baseTeam) {
			if rng.Intn(4) == 0 {
				continue // team without an entry
			}
			n := rng.Intn(4)
			entries := make([]string, 0, n)
			for range n {
				entries = append(entries, entryPool[rng.Intn(len(entryPool))])
			}
			table[team] = entries
		}
		teams := make([]string, 0, 3)
		for _, team := range teamNames {
			if rng.Intn(2) == 0 {
				teams = append(teams, team)
			}
		}
		check(t, table, teams, bounds[rng.Intn(len(bounds))])
		if t.Failed() {
			return // one counterexample is enough
		}
	}
}

// TestIssuer_PlainIssueUnderGrants: the three-argument Issue names no
// provider, and a member of a group always comes through one. On an
// instance with service grants it therefore mints "-all", whatever the
// groups say and whoever the subject is. It is the one path that mints
// for an identity no group names, kept for callers from before
// identities; IssueFor refuses the same identity.
func TestIssuer_PlainIssueUnderGrants(t *testing.T) {
	sections := map[string]GrantsConfig{
		"a team group": {Groups: []GrantGroup{{Members: []string{"oidc/team:panda"}, Services: []string{"all:all"}}}},
		"the subject listed as a user": {Groups: []GrantGroup{
			{Members: []string{"oidc/user:alice@example.com", "cfaccess/user:alice@example.com"}, Services: []string{"all:all"}},
		}},
		"no groups": {},
	}
	for name, section := range sections {
		t.Run(name, func(t *testing.T) {
			grants, err := NewServiceGrants(section, provs("cfaccess", "oidc"))
			if err != nil {
				t.Fatalf("grants: %v", err)
			}
			key, err := GenerateRSAKey()
			if err != nil {
				t.Fatalf("genkey: %v", err)
			}
			iss, err := NewRS256Issuer(Config{
				ActiveKey: key, Issuer: "https://auth.test.example", DefaultAudience: []string{"test.example"},
				Grants: grants, TTL: 30 * time.Minute,
			})
			if err != nil {
				t.Fatalf("newissuer: %v", err)
			}
			_, claims, err := iss.Issue("alice@example.com", "alice@example.com", nil)
			if err != nil {
				t.Fatalf("issue: %v", err)
			}
			if claims.Services != "-all" || claims.Teams != nil {
				t.Errorf("services=%q teams=%v, want \"-all\" and no teams", claims.Services, claims.Teams)
			}
			// The same identity through IssueFor — the path the server
			// mints through — gets nothing.
			id := Identity{Subject: "alice@example.com", Email: "alice@example.com"}
			if tok, _, err := iss.IssueFor(id, nil); !errors.Is(err, ErrNotGranted) || tok != "" {
				t.Errorf("IssueFor without a provider: token %q, err %v; want ErrNotGranted", tok, err)
			}
		})
	}
}

// TestServiceGrants_Members is the core of the split between identity
// and access: a group's member always names the provider it comes
// through, so the same team name or the same user id from another
// provider is another subject.
func TestServiceGrants_Members(t *testing.T) {
	cfg := GrantsConfig{Groups: []GrantGroup{
		{Name: "staff", Members: []string{"cfaccess/team:panda", "oidc/team:ethpandaops"}, Services: []string{"all:all"}},
		{Name: "client-devs", Members: []string{"oidc/team:lighthouse", "oidc/team:geth"}, Services: []string{"dora", "spamoor:user*"}},
		{Members: []string{"oidc/user:alice@example.org"}, Services: []string{"dora:reindex"}},
		{Members: []string{"oidc/user:sub-123", "github/user:octocat"}, Services: []string{"assertoor"}},
		{Name: "documented", Members: []string{"htpasswd/team:ops"}, Services: []string{}},
	}}
	g, err := NewServiceGrants(cfg, provs("cfaccess", "oidc", "github", "htpasswd"))
	if err != nil {
		t.Fatalf("grants: %v", err)
	}

	tests := []struct {
		name string
		id   Identity
		want string
	}{
		{"staff through cloudflare", Identity{Subject: "s@ethpandaops.io", Teams: []string{"panda"}, Provider: "cfaccess"}, "+all,+all:all"},
		{"staff through the IdP, by its own team name", Identity{Subject: "s@ethpandaops.io", Teams: []string{"ethpandaops"}, Provider: "oidc"}, "+all,+all:all"},
		{
			"panda from the OIDC door is not the staff group's panda",
			Identity{Subject: "mallory", Teams: []string{"panda"}, Provider: "oidc"}, noToken,
		},
		{
			"ethpandaops from the Cloudflare door is not the staff group's either",
			Identity{Subject: "mallory", Teams: []string{"ethpandaops"}, Provider: "cfaccess"}, noToken,
		},
		{"panda from a basic-auth door", Identity{Subject: "mallory", Teams: []string{"panda", "ethpandaops", "lighthouse"}, Provider: "htpasswd"}, noToken},
		{"a client team", Identity{Subject: "bob", Teams: []string{"lighthouse"}, Provider: "oidc"}, "-all,+dora,+spamoor,+spamoor:user*"},
		{"two teams of one group", Identity{Subject: "bob", Teams: []string{"geth", "lighthouse"}, Provider: "oidc"}, "-all,+dora,+spamoor,+spamoor:user*"},
		{
			"union of a team group and a user group",
			Identity{Subject: "alice@example.org", Email: "alice@example.org", Teams: []string{"lighthouse"}, Provider: "oidc"},
			"-all,+dora,+dora:reindex,+spamoor,+spamoor:user*",
		},
		{"user by email when the subject differs", Identity{Subject: "sub-999", Email: "alice@example.org", Provider: "oidc"}, "-all,+dora,+dora:reindex"},
		{"user by subject when the email differs", Identity{Subject: "sub-123", Email: "x@example.org", Provider: "oidc"}, "-all,+assertoor"},
		{"user by subject without an email", Identity{Subject: "sub-123", Provider: "oidc"}, "-all,+assertoor"},
		{
			"subject and email in two groups add up",
			Identity{Subject: "sub-123", Email: "alice@example.org", Provider: "oidc"},
			"-all,+assertoor,+dora,+dora:reindex",
		},
		{
			"user ids ignore ASCII case",
			Identity{Subject: "ALICE@Example.ORG", Email: "ALICE@Example.ORG", SubjectIsEmail: true, Provider: "oidc"},
			"-all,+dora,+dora:reindex",
		},
		// A member that names an email address is a statement about
		// who owns the address. A raw provider subject that merely
		// looks like one — an IdP "sub" nobody verified — is not it.
		{
			"a raw subject that looks like an email is not that user",
			Identity{Subject: "alice@example.org", Provider: "oidc"}, noToken,
		},
		{
			"neither in another case",
			Identity{Subject: "ALICE@example.org", Provider: "oidc"}, noToken,
		},
		{
			"a raw email-like subject next to another verified email counts for the email only",
			Identity{Subject: "alice@example.org", Email: "bob@example.org", Provider: "oidc"}, noToken,
		},
		{
			"a subject the provider marked as a verified email is that user",
			Identity{Subject: "alice@example.org", SubjectIsEmail: true, Provider: "oidc"},
			"-all,+dora,+dora:reindex",
		},
		{
			"a raw subject without an @ still matches by subject",
			Identity{Subject: "sub-123", Provider: "oidc"}, "-all,+assertoor",
		},
		{"user ids are exact", Identity{Subject: "alice@example.org.evil", Email: " alice@example.org", Provider: "oidc"}, noToken},
		{"a Kelvin sign is not a k", Identity{Subject: "octo\u212aat", Provider: "github"}, noToken},
		{
			"the same id through another provider is another user",
			Identity{Subject: "alice@example.org", Email: "alice@example.org", Provider: "htpasswd"}, noToken,
		},
		{"the same login through another provider", Identity{Subject: "octocat", Email: "octocat", Provider: "oidc"}, noToken},
		{"the right login through the right provider", Identity{Subject: "octocat", Provider: "github"}, "-all,+assertoor"},
		{"a team name is not a user id", Identity{Subject: "lighthouse", Email: "panda", Provider: "oidc"}, noToken},
		{"a user id is not a team", Identity{Subject: "x", Teams: []string{"sub-123"}, Provider: "oidc"}, noToken},
		{"an identity without a provider is in no group", Identity{Subject: "alice@example.org", Email: "alice@example.org", Teams: []string{"panda", "ethpandaops", "lighthouse"}}, noToken},
		{"a provider that is not configured", Identity{Subject: "alice@example.org", Teams: []string{"panda"}, Provider: "other"}, noToken},
		{"a group that grants nothing still names its members", Identity{Subject: "x", Teams: []string{"ops"}, Provider: "htpasswd"}, "-all"},
		{"no match at all", Identity{Subject: "nobody", Provider: "oidc"}, noToken},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := directiveOf(t, g, tc.id, ""); got != tc.want {
				t.Errorf("directive: got %q, want %q", got, tc.want)
			}
		})
	}

	wantTable := []string{
		"staff: cfaccess/team:panda, oidc/team:ethpandaops → all:all",
		"client-devs: oidc/team:geth, oidc/team:lighthouse → dora, spamoor:user*",
		"grants[2]: oidc/user:alice@example.org → dora:reindex",
		"grants[3]: github/user:octocat, oidc/user:sub-123 → assertoor",
		"documented: htpasswd/team:ops → (nothing)",
	}
	if got := g.Table(); !slices.Equal(got, wantTable) {
		t.Errorf("table:\n got %q\nwant %q", got, wantTable)
	}
	if got, want := g.Providers(), []string{"cfaccess", "github", "htpasswd", "oidc"}; !slices.Equal(got, want) {
		t.Errorf("providers: got %v, want %v", got, want)
	}
}

// TestNewServiceGrants_MemberForms: exactly two member forms, parsed
// strictly; everything else is an error that shows the accepted forms.
func TestNewServiceGrants_MemberForms(t *testing.T) {
	providers := provs("cfaccess", "oidc")
	const forms = `a member is "<provider>/team:<team>", "<provider>/user:<id>" or "<provider>/<attribute>:<value>"`

	tests := []struct {
		name    string
		members []string
		wantErr string // "": valid
	}{
		{"team", []string{"oidc/team:lighthouse"}, ""},
		{"user by email", []string{"oidc/user:alice@example.org"}, ""},
		{"a user id may contain / : @ |", []string{"oidc/user:https://idp.example/users/1", "oidc/user:auth0|abc/def:ghi@x"}, ""},
		{"a user id that looks like a member", []string{"oidc/user:cfaccess/team:panda"}, ""},
		{"a user id starting with team:", []string{"oidc/user:team:panda"}, ""},
		{"the same name as team and as user", []string{"oidc/team:alice", "oidc/user:alice"}, ""},
		{"the same team at two providers", []string{"oidc/team:panda", "cfaccess/team:panda"}, ""},

		{"no members", nil, "members must list at least one member"},
		{"empty list", []string{}, "members must list at least one member"},
		{"empty member", []string{""}, "empty or with surrounding whitespace"},
		{"padded member", []string{" oidc/team:panda"}, "empty or with surrounding whitespace"},
		{"a bare team name", []string{"panda"}, `"panda": no provider: every member names the provider it comes through`},
		{"a bare email", []string{"alice@example.org"}, "no provider"},
		{"the marker without a provider", []string{"team:panda"}, "no provider"},
		{"an unknown provider", []string{"github/team:panda"}, `no provider named "github" (configured: [cfaccess, oidc])`},
		{"a capitalised provider points at the right one", []string{"OIDC/team:x"}, `no provider named "OIDC" — did you mean "oidc"?`},
		{"a capitalised provider, user form", []string{"Oidc/user:alice@example.org"}, `did you mean "oidc"?`},
		{"a wildcard provider", []string{"*/team:panda"}, `no provider named "*"`},
		{"an empty provider", []string{"/team:panda"}, `no provider named ""`},
		{"everyone through a door", []string{"oidc/*"}, `after the provider comes "<attribute>:<value>"`},
		{"everyone through a door, spelled out", []string{"oidc/everyone"}, `after the provider comes "<attribute>:<value>"`},
		{"only the provider", []string{"oidc/"}, `after the provider comes "<attribute>:<value>"`},
		{"the old qualified user form", []string{"oidc/alice@example.org"}, `after the provider comes "<attribute>:<value>"`},
		{"a space after the marker", []string{"oidc/team: panda"}, `" panda" is not a team name`},
		{"an uppercase team is not folded", []string{"oidc/team:Panda"}, `"Panda" is not a team name`},
		{"an empty team", []string{"oidc/team:"}, `the value after "team:" is empty`},
		{"a team wildcard", []string{"oidc/team:*"}, "there are no wildcards"},
		{"a team prefix wildcard", []string{"oidc/team:pan*"}, "there are no wildcards"},
		{"the IdP group instead of the team", []string{"oidc/team:team:panda"}, `"team:panda" is not a team name`},
		{"an empty user id", []string{"oidc/user:"}, `the value after "user:" is empty`},
		{"a padded user id", []string{"oidc/user: alice"}, "the user id has surrounding whitespace"},
		{"a user wildcard", []string{"oidc/user:*@example.org"}, "there are no wildcards"},
		{"the same member twice", []string{"oidc/team:panda", "oidc/team:panda"}, `"oidc/team:panda" and "oidc/team:panda" are the same member`},
		{"the same user twice, by case", []string{"oidc/user:Alice@example.org", "oidc/user:alice@example.org"}, `"oidc/user:Alice@example.org" and "oidc/user:alice@example.org" are the same member`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewServiceGrants(GrantsConfig{Groups: []GrantGroup{{Name: "g", Members: tc.members, Services: []string{"dora"}}}}, providers)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.wantErr != "":
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("got %v, want an error containing %q", err, tc.wantErr)
				}
				if !strings.Contains(err.Error(), "grants[0] (g)") {
					t.Errorf("the error does not name the group: %v", err)
				}
				if !strings.Contains(err.Error(), forms) && !strings.Contains(err.Error(), "the same member") {
					t.Errorf("the error does not show the accepted forms: %v", err)
				}
			}
		})
	}
}

func TestNewServiceGrants_Groups(t *testing.T) {
	providers := provs("oidc")
	member := []string{"oidc/team:panda"}
	tests := []struct {
		name    string
		groups  []GrantGroup
		wantErr string
	}{
		{"no groups", nil, ""},
		{"a group that grants nothing", []GrantGroup{{Members: member, Services: nil}}, ""},
		{"one member in two groups", []GrantGroup{{Name: "a", Members: member, Services: []string{"spamoor"}}, {Name: "b", Members: member, Services: []string{"dora"}}}, ""},
		{"two unnamed groups", []GrantGroup{{Members: member}, {Members: []string{"oidc/team:geth"}}}, ""},
		{"a name used twice", []GrantGroup{{Name: "staff", Members: member}, {Name: "staff", Members: []string{"oidc/team:geth"}}}, `grants[1]: the name "staff" is already used by grants[0]`},
		{"a padded name", []GrantGroup{{Name: " staff", Members: member}}, "has surrounding whitespace"},
		{"an invalid grant", []GrantGroup{{Name: "staff", Members: member, Services: []string{"-dora"}}}, `grants[0] (staff): services: invalid grant "-dora": a grant cannot deny`},
		{"an invalid feature in the second group", []GrantGroup{{Members: member}, {Members: member, Services: []string{"dora:us*er"}}}, `grants[1]: services: invalid feature "us*er"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewServiceGrants(GrantsConfig{Groups: tc.groups}, providers)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("got %v, want an error containing %q", err, tc.wantErr)
			}
		})
	}

	// One member in two groups gets the union.
	g, err := NewServiceGrants(GrantsConfig{Groups: tests[2].groups}, providers)
	if err != nil {
		t.Fatalf("grants: %v", err)
	}
	if got := directiveOf(t, g, Identity{Subject: "x", Teams: []string{"panda"}, Provider: "oidc"}, ""); got != "-all,+dora,+spamoor" {
		t.Errorf("union across groups: %q", got)
	}
}

// TestIssuer_BoundMustNotNameFeatures: with grants, the instance-wide
// directive bounds base access only. A bound with feature segments is
// refused at construction; without grants it is passed through as
// before.
func TestIssuer_BoundMustNotNameFeatures(t *testing.T) {
	key, err := GenerateRSAKey()
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	build := func(services string, grants *ServiceGrants) (*RS256Issuer, error) {
		return NewRS256Issuer(Config{
			ActiveKey: key, Issuer: "https://auth.test.example", DefaultAudience: []string{"test.example"},
			Services: services, Grants: grants, TTL: 30 * time.Minute,
		})
	}
	grants := mustGrants(t, map[string][]string{"panda": {"all"}, "lh": {"spamoor"}})

	for _, bound := range []string{
		"+all,-spamoor:plugins", // took plugins from "all" teams but not from "spamoor" teams
		"-all,+all:hold",        // old verifiers: nothing; new ones: everything
		"+spamoor:all", "-spamoor:basic", "+all:all", " +all , -spamoor:x ",
	} {
		if _, err := build(bound, grants); err == nil || !strings.Contains(err.Error(), "names features") {
			t.Errorf("bound %q with grants: got %v, want a refusal", bound, err)
		}
		iss, err := build(bound, nil)
		if err != nil {
			t.Errorf("bound %q without grants: %v", bound, err)
			continue
		}
		_, claims, err := iss.Issue("alice", "alice", nil)
		if err != nil || claims.Services != strings.TrimSpace(bound) {
			t.Errorf("bound %q without grants: services %q, err %v", bound, claims.Services, err)
		}
	}

	for _, bound := range []string{"", "+all,-spamoor", "-all,+dora"} {
		if _, err := build(bound, grants); err != nil {
			t.Errorf("bound %q with grants: %v", bound, err)
		}
	}
}

// TestIssuer_BlankBoundIsNoBound: a whitespace-only instance-wide
// directive must not be minted as a " " claim, which is not the empty
// claim to a verifier.
func TestIssuer_BlankBoundIsNoBound(t *testing.T) {
	key, err := GenerateRSAKey()
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	for _, blank := range []string{" ", "   ", "\t", " \n "} {
		for name, grants := range map[string]*ServiceGrants{
			"no grants": nil,
			"grants":    mustGrants(t, map[string][]string{"panda": {"all"}}),
		} {
			iss, err := NewRS256Issuer(Config{
				ActiveKey: key, Issuer: "https://auth.test.example", DefaultAudience: []string{"test.example"},
				Services: blank, Grants: grants, TTL: 30 * time.Minute,
			})
			if err != nil {
				t.Fatalf("%s, bound %q: %v", name, blank, err)
			}
			tok, claims, err := iss.IssueFor(teamsOf([]string{"panda"}), nil)
			if err != nil {
				t.Fatalf("issue: %v", err)
			}
			want := ""
			if grants != nil {
				want = "+all"
			}
			if claims.Services != want {
				t.Errorf("%s, bound %q: services %q, want %q", name, blank, claims.Services, want)
			}
			if raw, present := rawPayload(t, tok)["services"]; present != (want != "") {
				t.Errorf("%s, bound %q: payload services %v", name, blank, raw)
			}
			if strings.TrimSpace(claims.Services) != claims.Services {
				t.Errorf("claim with surrounding whitespace: %q", claims.Services)
			}
		}
	}
}

// TestServiceGrants_NeverEmptyAndNeverBlank: with the section present
// the claim is never empty and never just whitespace, whatever the
// grants, the identity and a (colon-free) bound.
func TestServiceGrants_NeverEmptyAndNeverBlank(t *testing.T) {
	tables := []map[string][]string{
		{}, {"panda": {}}, {"panda": {"all"}}, {"panda": {"all:all"}}, {baseTeam: {}}, {baseTeam: {"spamoor"}},
	}
	for _, table := range tables {
		g := mustGrants(t, table)
		for _, teams := range [][]string{nil, {"panda"}, {"other"}} {
			for _, bound := range []string{"", "+all", "-all", "+all,-spamoor", "-all,+spamoor"} {
				// directiveOf fails the test when a refusal comes with a claim.
				if got := directiveOf(t, g, teamsOf(teams), bound); strings.TrimSpace(got) == "" {
					t.Errorf("table %v teams %v bound %q: claim %q", table, teams, bound, got)
				}
			}
		}
	}
}

// TestServiceGrants_AttributeMembers: a member can name any attribute
// the provider verified. The issuer side of it: parsing, what the
// providers are told to look for, and that a match only counts at the
// provider the member names.
func TestServiceGrants_AttributeMembers(t *testing.T) {
	fixed := func(names ...string) func(string, string) error {
		return func(a, _ string) error {
			if !slices.Contains(names, a) {
				return fmt.Errorf("no attribute %q", a)
			}
			return nil
		}
	}
	providers := []Provider{
		{Name: "oidc"},
		{Name: "idp2"},
		{Name: "github", CheckAttribute: fixed("login", "email", "orgs")},
		{Name: "htpasswd", CheckAttribute: fixed("username")},
	}
	cfg := GrantsConfig{Groups: []GrantGroup{
		{Name: "internal", Members: []string{"oidc/groups:panda-access", "github/orgs:EthPandaOps"}, Services: []string{"all"}},
		{Name: "lighthouse", Members: []string{"oidc/groups:team:lighthouse", "oidc/groups:sigp:core"}, Services: []string{"dora"}},
		{Name: "ops", Members: []string{"oidc/realm_access.roles:ops", "htpasswd/username:Alice"}, Services: []string{"spamoor"}},
		{Name: "url", Members: []string{"oidc/department:https://x.example/a:b"}, Services: []string{"assertoor"}},
		{Name: "mixed", Members: []string{"oidc/team:geth", "oidc/user:carol@example.org", "oidc/groups:auditors"}, Services: []string{"buildoor"}},
		{Name: "other-idp", Members: []string{"idp2/groups:panda-access"}, Services: []string{"all:all"}},
	}}
	g, err := NewServiceGrants(cfg, providers)
	if err != nil {
		t.Fatalf("grants: %v", err)
	}

	// What each provider has to look for: attribute members only, the
	// value with its ASCII letters lowercased.
	wantLookFor := map[string][]protection.AttributeMember{
		"oidc": {
			{Attribute: "groups", Value: "panda-access"},
			{Attribute: "groups", Value: "team:lighthouse"},
			{Attribute: "groups", Value: "sigp:core"},
			{Attribute: "realm_access.roles", Value: "ops"},
			{Attribute: "department", Value: "https://x.example/a:b"},
			{Attribute: "groups", Value: "auditors"},
		},
		"idp2":     {{Attribute: "groups", Value: "panda-access"}},
		"github":   {{Attribute: "orgs", Value: "ethpandaops"}},
		"htpasswd": {{Attribute: "username", Value: "alice"}},
		"unknown":  nil,
	}
	for provider, want := range wantLookFor {
		if got := g.AttributeMembers(provider); !slices.Equal(got, want) {
			t.Errorf("AttributeMembers(%s): got %v, want %v", provider, got, want)
		}
	}
	if got := (*ServiceGrants)(nil).AttributeMembers("oidc"); got != nil {
		t.Errorf("nil grants: %v", got)
	}

	key := protection.MatchKey
	tests := []struct {
		name string
		id   Identity
		want string
	}{
		{"an IdP group", Identity{Subject: "a", Provider: "oidc", Matches: []string{key("groups", "panda-access")}}, "+all"},
		{"a value containing a colon", Identity{Subject: "a", Provider: "oidc", Matches: []string{key("groups", "team:lighthouse")}}, "-all,+dora"},
		{"a value containing : and /", Identity{Subject: "a", Provider: "oidc", Matches: []string{key("department", "https://x.example/a:b")}}, "-all,+assertoor"},
		{"a nested path", Identity{Subject: "a", Provider: "oidc", Matches: []string{key("realm_access.roles", "ops")}}, "-all,+spamoor"},
		{"values ignore ASCII case", Identity{Subject: "a", Provider: "github", Matches: []string{key("orgs", "ethpandaops")}}, "+all"},
		{"a fixed-set provider", Identity{Subject: "alice", Provider: "htpasswd", Matches: []string{key("username", "alice")}}, "-all,+spamoor"},
		{
			"union of team, user and attribute members",
			Identity{Subject: "x", Email: "carol@example.org", Teams: []string{"geth"}, Provider: "oidc", Matches: []string{key("groups", "sigp:core"), key("realm_access.roles", "ops")}},
			"-all,+buildoor,+dora,+spamoor",
		},
		{"one group through its attribute member alone", Identity{Subject: "x", Provider: "oidc", Matches: []string{key("groups", "auditors")}}, "-all,+buildoor"},
		{
			"the same match at another provider is another subject",
			Identity{Subject: "a", Provider: "idp2", Matches: []string{key("groups", "panda-access")}}, "+all,+all:all",
		},
		{
			"a match of provider A does not count at provider B",
			Identity{Subject: "a", Provider: "github", Matches: []string{key("groups", "panda-access"), key("username", "alice")}}, noToken,
		},
		{"an oidc match presented by a basic-auth identity", Identity{Subject: "a", Provider: "htpasswd", Matches: []string{key("groups", "panda-access")}}, noToken},
		{"a match without a provider", Identity{Subject: "a", Matches: []string{key("groups", "panda-access")}}, noToken},
		{"a match the config does not name (any more)", Identity{Subject: "a", Provider: "oidc", Matches: []string{key("groups", "removed-group")}}, noToken},
		{"a team name is not an attribute match", Identity{Subject: "a", Provider: "oidc", Teams: []string{"panda-access", "auditors"}}, noToken},
		{"an attribute match is not a team", Identity{Subject: "a", Provider: "oidc", Matches: []string{"team:geth", key("team", "geth")}}, noToken},
		{"an attribute match is not a user", Identity{Subject: "a", Provider: "oidc", Matches: []string{"user:carol@example.org"}}, noToken},
		{"the value is not a prefix", Identity{Subject: "a", Provider: "oidc", Matches: []string{key("groups", "panda-access-evil"), key("groups", "panda")}}, noToken},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := directiveOf(t, g, tc.id, ""); got != tc.want {
				t.Errorf("directive: got %q, want %q", got, tc.want)
			}
		})
	}

	if got := g.Table()[1]; got != "lighthouse: oidc/groups:sigp:core, oidc/groups:team:lighthouse → dora" {
		t.Errorf("table line: %q", got)
	}
}

// TestNewServiceGrants_AttributeMemberForms: parsing of
// "<provider>/<attribute>:<value>" and its errors.
func TestNewServiceGrants_AttributeMemberForms(t *testing.T) {
	fixed := func(names ...string) func(string, string) error {
		return func(a, _ string) error {
			if !slices.Contains(names, a) {
				return fmt.Errorf("no attribute %q", a)
			}
			return nil
		}
	}
	cloudflare := func(a, _ string) error {
		if slices.Contains([]string{"principal", "email", "sub", "common_name", "country"}, a) ||
			strings.HasPrefix(a, "custom.") {
			return nil
		}
		return fmt.Errorf("no attribute %q", a)
	}
	providers := []Provider{
		{Name: "oidc"},
		{Name: "cfaccess", CheckAttribute: cloudflare},
		{Name: "github", CheckAttribute: fixed("login", "email", "orgs")},
		{Name: "htpasswd", CheckAttribute: fixed("username")},
		{Name: "anyauth", CheckAttribute: fixed("username")},
	}

	tests := []struct {
		name    string
		member  string
		wantErr string // "": valid
	}{
		{"oidc: a list claim", "oidc/groups:panda-access", ""},
		{"oidc: a nested path", "oidc/realm_access.roles:admin", ""},
		{"oidc: a deeper path", "oidc/resource_access.myapp.roles:admin", ""},
		{"oidc: any path at all", "oidc/whatever.the.idp.sends:x", ""},
		{"oidc: the value keeps its colons and slashes", "oidc/groups:sigp:core/devs@x", ""},
		{"oidc: email", "oidc/email:alice@example.org", ""},
		{"cloudflare: principal", "cfaccess/principal:user", ""},
		{"cloudflare: a custom claim", "cfaccess/custom.department:eng", ""},
		{"github: orgs", "github/orgs:ethpandaops", ""},
		{"github: login", "github/login:octocat", ""},
		{"basic: username", "htpasswd/username:alice", ""},
		{"any: username", "anyauth/username:alice", ""},

		{"github has no groups", "github/groups:ethpandaops", `can never match at the provider "github": no attribute "groups"`},
		{"github has no teams attribute", "github/org:ethpandaops", `can never match at the provider "github": no attribute "org"`},
		{"basic has no email", "htpasswd/email:alice@example.org", `can never match at the provider "htpasswd": no attribute "email"`},
		{"any has no groups", "anyauth/groups:x", `can never match at the provider "anyauth": no attribute "groups"`},
		{"cloudflare has no groups", "cfaccess/groups:staff", `can never match at the provider "cfaccess": no attribute "groups"`},
		{"cloudflare: custom needs a name", "cfaccess/custom:x", `no attribute "custom"`},
		{"attribute names are case-sensitive for fixed sets", "github/Orgs:ethpandaops", `no attribute "Orgs"`},
		// Only the exact names team and user are reserved; where the
		// attributes are a fixed set, their near misses are attributes
		// the provider does not have.
		{"a plural team at a fixed set", "github/teams:panda", `no attribute "teams"`},
		{"a capitalised user at a fixed set", "htpasswd/User:alice", `no attribute "User"`},
		{"an unknown provider", "gitlab/groups:x", `no provider named "gitlab" (configured: [oidc, cfaccess, github, htpasswd, anyauth])`},
		{"a capitalised provider", "OIDC/groups:x", `did you mean "oidc"?`},
		{"an empty attribute", "oidc/:x", `the attribute before the ":" is empty`},
		{"an empty value", "oidc/groups:", `the value after "groups:" is empty`},
		{"no colon at all", "oidc/groups", `after the provider comes "<attribute>:<value>"`},
		{"a padded attribute", "oidc/ groups:x", "has surrounding whitespace"},
		{"a glob value", "oidc/groups:team:*", "there are no wildcards"},
		{"a glob in the middle", "oidc/groups:sigp*core", "turn it into a team with a teamRules entry"},
		{"too long", "oidc/groups:" + strings.Repeat("x", 300), "longer than 300 bytes"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewServiceGrants(GrantsConfig{Groups: []GrantGroup{{Members: []string{tc.member}, Services: []string{"dora"}}}}, providers)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("got %v, want an error containing %q", err, tc.wantErr)
			}
		})
	}

	// "team" and "user" are reserved: they never reach a provider as
	// attributes, even where the provider has claims of that name.
	g, err := NewServiceGrants(GrantsConfig{Groups: []GrantGroup{
		{Members: []string{"oidc/team:panda", "oidc/user:alice"}, Services: []string{"all"}},
	}}, providers)
	if err != nil {
		t.Fatalf("grants: %v", err)
	}
	if got := g.AttributeMembers("oidc"); got != nil {
		t.Errorf("reserved names reached the provider as attributes: %v", got)
	}

	// Exactly "team" and "user" are reserved, as documented. "teams",
	// "users" and other spellings are attributes like any other: an
	// id_token can have a claim called "teams".
	g, err = NewServiceGrants(GrantsConfig{Groups: []GrantGroup{{
		Members:  []string{"oidc/teams:panda", "oidc/users:alice", "oidc/Team:panda", "oidc/USER:alice"},
		Services: []string{"all"},
	}}}, providers)
	if err != nil {
		t.Fatalf("near misses of the reserved names are attributes: %v", err)
	}
	want := []protection.AttributeMember{
		{Attribute: "teams", Value: "panda"}, {Attribute: "users", Value: "alice"},
		{Attribute: "Team", Value: "panda"}, {Attribute: "USER", Value: "alice"},
	}
	if got := g.AttributeMembers("oidc"); !slices.Equal(got, want) {
		t.Errorf("attribute members: got %v, want %v", got, want)
	}
	if got := directiveOf(t, g, Identity{Provider: "oidc", Teams: []string{"panda"}, Subject: "alice"}, ""); got != noToken {
		t.Errorf("an attribute member named like a reserved one was read as it: %q", got)
	}

	// The same attribute member differing only by the case of its value
	// is one member.
	_, err = NewServiceGrants(GrantsConfig{Groups: []GrantGroup{
		{Members: []string{"oidc/groups:Staff", "oidc/groups:staff"}, Services: []string{"all"}},
	}}, providers)
	if err == nil || !strings.Contains(err.Error(), "are the same member") {
		t.Errorf("case-variant values: %v", err)
	}
}

// wellFormedDirective is what the issuer may emit when there is no
// instance-wide bound: "-all", or a positive directive whose segments
// are feature names, prefixes or "all".
var wellFormedDirective = regexp.MustCompile(`^(-all|\+(all|[a-z0-9][a-z0-9_-]*)(:(all|[a-z0-9][a-z0-9_-]*\*?))*)$`)

// TestServiceGrants_NeverEmitsMalformedSegments: a verifier skips a
// directive with any malformed segment as a whole. The issuer must
// therefore never emit one — over random grant tables, every directive
// of every claim is well formed, carries no denial with segments and
// never spells out "basic".
func TestServiceGrants_NeverEmitsMalformedSegments(t *testing.T) {
	entryPool := []string{
		"all", "all:all", "all:logs", "all:hold:roll", "all:basic", "all:lo*", "all:*",
		"spamoor", "spamoor:all", "spamoor:logs", "spamoor:hold:roll", "spamoor:basic", "spamoor:user*:u*",
		"dora", "dora:all", "dora:roll", "dora:h*:roll:basic", "dora:*",
		"assertoor", "assertoor:all:basic", "buildoor:b*",
	}
	teamNames := []string{"t1", "t2", "t3", baseTeam}

	rng := rand.New(rand.NewSource(8))
	for range 5000 {
		table := make(map[string][]string, 4)
		for _, team := range teamNames {
			n := rng.Intn(4)
			entries := make([]string, 0, n)
			for range n {
				entries = append(entries, entryPool[rng.Intn(len(entryPool))])
			}
			table[team] = entries
		}
		teams := make([]string, 0, 3)
		for _, team := range teamNames[:3] {
			if rng.Intn(2) == 0 {
				teams = append(teams, team)
			}
		}
		claim := directiveOf(t, mustGrants(t, table), teamsOf(teams), "")
		for i, d := range strings.Split(claim, ",") {
			if !wellFormedDirective.MatchString(d) {
				t.Fatalf("claim %q: directive %q is not well formed (table %v, teams %v)", claim, d, table, teams)
			}
			if strings.Contains(d, auth.FeatureBasic) {
				t.Fatalf("claim %q spells out basic", claim)
			}
			if strings.HasPrefix(d, "-") && i != 0 {
				t.Fatalf("claim %q: a denial after the first directive", claim)
			}
		}
	}
}

// TestIssuer_NotGranted is the rule that an identity no group names
// gets no token. It is about being named: a member of a group that
// grants nothing, or only what the instance-wide directive denies,
// still gets its token (with "-all"); with an empty section nobody is
// named; without a section everybody gets a token as before.
func TestIssuer_NotGranted(t *testing.T) {
	groups := []GrantGroup{
		{Name: "staff", Members: []string{"oidc/team:panda"}, Services: []string{"all"}},
		{Name: "listed", Members: []string{"oidc/team:listed", "cf/user:carol@example.org"}, Services: []string{}},
		{Name: "dora", Members: []string{"oidc/groups:dora-users"}, Services: []string{"dora"}},
	}
	listed := &GrantsConfig{Groups: groups}
	empty := &GrantsConfig{Groups: []GrantGroup{}}
	doraMatch := protection.MatchKey("groups", "dora-users")

	tests := []struct {
		name         string
		section      *GrantsConfig // nil: no grants section
		instanceWide string
		id           Identity
		want         string // the services claim, or noToken
	}{
		{"named, granted", listed, "", Identity{Subject: "a", Teams: []string{"panda"}, Provider: "oidc"}, "+all"},
		{"named by a group without services", listed, "", Identity{Subject: "a", Teams: []string{"listed"}, Provider: "oidc"}, "-all"},
		{
			"named as a user by a group without services", listed, "",
			Identity{Subject: "carol@example.org", Email: "carol@example.org", SubjectIsEmail: true, Provider: "cf"}, "-all",
		},
		{
			"named, and the instance denies all it is granted", listed, "-all,+spamoor",
			Identity{Subject: "a", Matches: []string{doraMatch}, Provider: "oidc"}, "-all",
		},
		{"named by no group", listed, "", Identity{Subject: "mallory", Teams: []string{"reth"}, Provider: "oidc"}, noToken},
		{"named by no group, instance-wide +all", listed, "+all", Identity{Subject: "mallory", Provider: "oidc"}, noToken},
		{"the team of a group through another provider", listed, "", Identity{Subject: "a", Teams: []string{"panda"}, Provider: "cf"}, noToken},
		{"no provider", listed, "", Identity{Subject: "a", Teams: []string{"panda"}, Matches: []string{doraMatch}}, noToken},
		{"a team name that is not in normal form", listed, "", Identity{Subject: "a", Teams: []string{"Panda"}, Provider: "oidc"}, noToken},
		{"empty section: nobody is named", empty, "", Identity{Subject: "a", Teams: []string{"panda"}, Provider: "oidc"}, noToken},
		{"empty section, instance-wide +all", empty, "+all", Identity{Subject: "a", Provider: "oidc"}, noToken},
		{"no section: a token without the claim", nil, "", Identity{Subject: "mallory", Provider: "oidc"}, ""},
		{"no section, no provider", nil, "+all,-spamoor", Identity{Subject: "mallory"}, "+all,-spamoor"},
	}
	key, err := GenerateRSAKey()
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{
				ActiveKey: key, Issuer: "https://auth.test.example", DefaultAudience: []string{"test.example"},
				Services: tc.instanceWide, TTL: 30 * time.Minute,
			}
			if tc.section != nil {
				grants, err := NewServiceGrants(*tc.section, provs("oidc", "cf"))
				if err != nil {
					t.Fatalf("grants: %v", err)
				}
				cfg.Grants = grants
			}
			iss, err := NewRS256Issuer(cfg)
			if err != nil {
				t.Fatalf("newissuer: %v", err)
			}

			tok, claims, err := iss.IssueFor(tc.id, nil)
			if granted := iss.Granted(tc.id); granted != (tc.want != noToken) {
				t.Errorf("Granted = %t", granted)
			}
			if tc.want == noToken {
				if !errors.Is(err, ErrNotGranted) {
					t.Fatalf("err = %v, want ErrNotGranted", err)
				}
				if tok != "" || claims != nil {
					t.Fatalf("a refusal came with token %q, claims %v", tok, claims)
				}
				return
			}
			if err != nil {
				t.Fatalf("issue: %v", err)
			}
			if raw, present := rawPayload(t, tok)["services"]; claims.Services != tc.want ||
				(tc.want == "" && present) || (tc.want != "" && raw != tc.want) {
				t.Errorf("services: claims %q, payload %v (present %t), want %q", claims.Services, raw, present, tc.want)
			}
		})
	}
}
