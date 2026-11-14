package auth_test

import (
	"math/rand"
	"strings"
	"testing"
	"time"

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

// legacyServiceAllowed is a verbatim copy of ServiceAllowed as released
// in v0.0.3 (upstream/main, pkg/auth/services.go), before directives
// could carry feature grants. Deployed resource servers evaluate the
// "services" claim with it. It is kept here only as the reference the
// current implementation is compared against; do not use it elsewhere.
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

// What a directive list says about one feature; see FeatureAllowed.
const (
	unset    = "unset"
	granted  = "granted"
	excluded = "excluded"
)

// TestFeatureAllowed_Grammar covers every documented directive form.
// Each row states what the list means for the queried service (base
// access) and feature (unset / granted / excluded); the expected answer
// in both modes follows from the truth table pinned literally in
// TestFeatureAllowed_TruthTable.
func TestFeatureAllowed_Grammar(t *testing.T) {
	cases := []struct {
		name       string
		directives string
		service    string
		feature    string
		wantBase   bool
		wantState  string
	}{
		// ─── the documented forms ───────────────────────────────────────
		{"+svc: base, nothing about features", "+spamoor", "spamoor", "plugins", true, unset},
		{"+svc:all: every feature", "+spamoor:all", "spamoor", "plugins", true, granted},
		{"+svc:f1:f2: first", "+spamoor:f1:f2", "spamoor", "f1", true, granted},
		{"+svc:f1:f2: second", "+spamoor:f1:f2", "spamoor", "f2", true, granted},
		{"+svc:f1:f2: another", "+spamoor:f1:f2", "spamoor", "f3", true, unset},
		{"+svc:all:-f: the exception", "+spamoor:all:-plugins", "spamoor", "plugins", true, excluded},
		{"+svc:all:-f: the rest", "+spamoor:all:-plugins", "spamoor", "txpool", true, granted},
		{"+svc:-f: excluded, base granted", "+spamoor:-plugins", "spamoor", "plugins", true, excluded},
		{"+svc:-f: the rest stays unset", "+spamoor:-plugins", "spamoor", "txpool", true, unset},
		{"+all:f: any service", "+all:feata", "buildoor", "feata", true, granted},
		{"+all:f: another feature", "+all:feata", "buildoor", "featb", true, unset},
		{"-svc: base gone", "-spamoor", "spamoor", "plugins", false, unset},
		{"-svc after a grant: base and feature gone", "+spamoor:all,-spamoor", "spamoor", "plugins", false, unset},
		{"-svc:f: the feature", "-spamoor:f1", "spamoor", "f1", true, excluded},
		{"-svc:f: the others", "-spamoor:f1", "spamoor", "f2", true, unset},
		{"-svc:f after +svc:all: the feature", "+spamoor:all,-spamoor:f1", "spamoor", "f1", true, excluded},
		{"-svc:f after +svc:all: the others", "+spamoor:all,-spamoor:f1", "spamoor", "f2", true, granted},

		// ─── basic: the reserved name of base access ────────────────────
		{"+svc:basic is +svc", "-all,+spamoor:basic", "spamoor", "plugins", true, unset},
		{"+svc:basic:f", "-all,+spamoor:basic:plugins", "spamoor", "plugins", true, granted},
		{"-svc:basic is -svc", "+spamoor:all,-spamoor:basic", "spamoor", "plugins", false, unset},
		{"-svc:basic forgets features like -svc", "+spamoor:f1,-spamoor:basic,+spamoor", "spamoor", "f1", true, unset},
		{"-svc:f:basic is still the denial", "+spamoor:all,-spamoor:f1:basic", "spamoor", "f2", false, unset},
		{"-all:basic is -all", "+spamoor,-all:basic", "spamoor", "plugins", false, unset},
		{"+svc:-basic: malformed, the directive grants nothing", "-all,+spamoor:-basic", "spamoor", "plugins", false, unset},
		{"+svc:all:-basic: malformed, the directive grants nothing", "-all,+spamoor:all:-basic", "spamoor", "plugins", false, unset},
		{"+svc:f:-basic: not even the feature before it", "-all,+spamoor,+spamoor:plugins:-basic", "spamoor", "plugins", true, unset},
		{"-svc:-basic: malformed, the directive denies nothing", "+spamoor:all,-spamoor:-basic", "spamoor", "plugins", true, granted},
		{"-svc:f leaves basic alone", "-all,+spamoor,-spamoor:plugins", "spamoor", "txpool", true, unset},
		{"all does not need to name basic", "-all,+spamoor:all", "spamoor", "txpool", true, granted},

		// ─── defaults ───────────────────────────────────────────────────
		{"nothing matches the service", "+buildoor:all", "spamoor", "plugins", true, unset},
		{"only a denial elsewhere", "-buildoor", "spamoor", "plugins", true, unset},
		{"-all", "-all", "spamoor", "plugins", false, unset},
		{"+all: base everywhere", "+all", "spamoor", "plugins", true, unset},
		{"+all:all: everything", "+all:all", "spamoor", "plugins", true, granted},

		// ─── interaction with -all,+svc ─────────────────────────────────
		{"-all,+svc: the service", "-all,+spamoor", "spamoor", "plugins", true, unset},
		{"-all,+svc: another service", "-all,+spamoor", "buildoor", "plugins", false, unset},
		{"-all,+svc,+svc:f: the feature", "-all,+spamoor,+spamoor:plugins", "spamoor", "plugins", true, granted},
		{"-all,+svc,+svc:f: another feature", "-all,+spamoor,+spamoor:plugins", "spamoor", "txpool", true, unset},
		{"-all,+svc,+svc:f: another service", "-all,+spamoor,+spamoor:plugins", "buildoor", "plugins", false, unset},
		{"-all,+svc,-svc:f", "-all,+spamoor,-spamoor:plugins", "spamoor", "plugins", true, excluded},
		{"feature directive implies base", "-all,+spamoor:plugins", "spamoor", "plugins", true, granted},
		{"exclusion segment still implies base", "-all,+spamoor:-plugins", "spamoor", "plugins", true, excluded},
		{"+all:f implies base everywhere", "-all,+all:feata", "buildoor", "feata", true, granted},
		{"+all,+all:all", "+all,+all:all", "buildoor", "anything", true, granted},

		// ─── order: later wins ──────────────────────────────────────────
		{"+svc:all,-svc:f", "+spamoor:all,-spamoor:f", "spamoor", "f", true, excluded},
		{"-svc:f,+svc:all", "-spamoor:f,+spamoor:all", "spamoor", "f", true, granted},
		{"+svc:all:-f", "+spamoor:all:-f", "spamoor", "f", true, excluded},
		{"+svc:-f:all", "+spamoor:-f:all", "spamoor", "f", true, granted},
		{"+svc:-all:f: the feature", "+spamoor:-all:plugins", "spamoor", "plugins", true, granted},
		{"+svc:-all:f: another", "+spamoor:-all:plugins", "spamoor", "txpool", true, excluded},
		{"grant then exclusion", "+spamoor:f1,-spamoor:f1", "spamoor", "f1", true, excluded},
		{"exclusion then grant", "-spamoor:f1,+spamoor:f1", "spamoor", "f1", true, granted},
		{"denial then grant", "-spamoor,+spamoor:f1", "spamoor", "f1", true, granted},
		{"grant, denial, bare re-allow: forgotten", "+spamoor:f1,-spamoor,+spamoor", "spamoor", "f1", true, unset},
		{"exclusion, denial, bare re-allow: forgotten", "-spamoor:f1,-spamoor,+spamoor", "spamoor", "f1", true, unset},
		{"a bare positive keeps an earlier grant", "+spamoor:f1,+spamoor", "spamoor", "f1", true, granted},
		{"a bare positive keeps an earlier exclusion", "-spamoor:f1,+spamoor", "spamoor", "f1", true, excluded},
		{"a later positive adds features", "+spamoor:f1,+spamoor:f2", "spamoor", "f1", true, granted},
		{"-svc:all excludes every feature, base stays", "+spamoor:f1:f2,-spamoor:all", "spamoor", "f2", true, excluded},
		{"-all after grants", "+spamoor:all,-all", "spamoor", "plugins", false, unset},

		// ─── +all:f and -all:f across services ──────────────────────────
		{"+all:f then +svc:g: the service", "+all:feata,+spamoor:featb", "spamoor", "featb", true, granted},
		{"+all:f then +svc:g: keeps the all feature", "+all:feata,+spamoor:featb", "spamoor", "feata", true, granted},
		{"+all:f then +svc:g: other services", "+all:feata,+spamoor:featb", "buildoor", "featb", true, unset},
		{"+svc:f then +all:-f", "+spamoor:f1,+all:-f1", "spamoor", "f1", true, excluded},
		{"-all:f excludes everywhere", "-all:feata", "spamoor", "feata", true, excluded},
		{"-all:f excludes everywhere: another service", "-all:feata", "buildoor", "feata", true, excluded},
		{"-all:f leaves base and other features", "+all:all,-all:feata", "spamoor", "featb", true, granted},
		{"-all:f after +all:all", "+all:all,-all:feata", "buildoor", "feata", true, excluded},
		{"-all:f then +svc:f: that service again", "-all:feata,+spamoor:feata", "spamoor", "feata", true, granted},
		{"-all:f then +svc:f: the others stay excluded", "-all:feata,+spamoor:feata", "buildoor", "feata", true, excluded},
		{"+all:all:-f then a service: f for it only", "+all:all:-featb,+spamoor:featb", "buildoor", "featb", true, excluded},

		// ─── wildcards: a trailing * is a prefix ────────────────────────
		{"prefix: the bare name", "+spamoor:user*", "spamoor", "user", true, granted},
		{"prefix: a longer name", "+spamoor:user*", "spamoor", "userxyz", true, granted},
		{"prefix: with a dash", "+spamoor:user*", "spamoor", "user-admin", true, granted},
		{"prefix: not a shorter name", "+spamoor:user*", "spamoor", "use", true, unset},
		{"prefix: not another name", "+spamoor:user*", "spamoor", "admin-user", true, unset},
		{"prefix: another service", "-all,+spamoor:user*", "buildoor", "user", false, unset},
		{"prefix on all services", "+all:user*", "buildoor", "user-view", true, granted},
		{"prefix exclusion", "+spamoor:all,-spamoor:user*", "spamoor", "user-admin", true, excluded},
		{"prefix exclusion: the rest", "+spamoor:all,-spamoor:user*", "spamoor", "plugins", true, granted},
		{"prefix exclusion inside a positive directive", "+spamoor:all:-user*", "spamoor", "user", true, excluded},
		{"prefix exclusion inside: the rest", "+spamoor:all:-user*", "spamoor", "plugins", true, granted},
		{"prefix then exact exclusion: the excluded one", "+spamoor:user*,-spamoor:user-admin", "spamoor", "user-admin", true, excluded},
		{"prefix then exact exclusion: the others", "+spamoor:user*,-spamoor:user-admin", "spamoor", "user-view", true, granted},
		{"exact exclusion then prefix: both allowed", "-spamoor:user-admin,+spamoor:user*", "spamoor", "user-admin", true, granted},
		{"exact exclusion then prefix: the other", "-spamoor:user-admin,+spamoor:user*", "spamoor", "user-view", true, granted},
		{"segments: prefix then exclusion", "+spamoor:user*:-user-admin", "spamoor", "user-admin", true, excluded},
		{"segments: exclusion then prefix", "+spamoor:-user-admin:user*", "spamoor", "user-admin", true, granted},
		{"a lone * is all", "+spamoor:*", "spamoor", "anything", true, granted},
		{"a lone -* is -all", "+spamoor:f1:-*", "spamoor", "f1", true, excluded},
		{"-svc:* excludes every feature, base stays", "+spamoor:all,-spamoor:*", "spamoor", "f1", true, excluded},
		{"prefix case and whitespace", "+spamoor: User* ", "spamoor", "USER-view", true, granted},
		{"prefix never removes basic", "-all,+spamoor,-spamoor:b*", "spamoor", "backup", true, excluded},
		{"prefix b* grants b-features, basic comes from the directive", "-all,+spamoor:b*", "spamoor", "backup", true, granted},
		{"prefix basi* is not basic", "+spamoor,-spamoor:basi*", "spamoor", "plugins", true, unset},
		{"prefix basic* is a prefix, not the reserved name", "+spamoor:all,-spamoor:basic*", "spamoor", "basic-stats", true, excluded},
		{"prefix al* is not all", "+spamoor:al*", "spamoor", "plugins", true, unset},
		{"prefix al* covers names starting al", "+spamoor:al*", "spamoor", "alerts", true, granted},

		// ─── malformed wildcards: the whole directive is skipped ────────
		{"* in the middle: grants nothing", "-all,+spamoor:us*er", "spamoor", "user", false, unset},
		{"* in the middle: not the other segments either", "-all,+spamoor:us*er:f1", "spamoor", "f1", false, unset},
		{"* in the middle: nor a segment before it", "-all,+spamoor,+spamoor:f1:us*er", "spamoor", "f1", true, unset},
		{"* at the start", "-all,+spamoor:*admin:f1", "spamoor", "f1", false, unset},
		{"two stars", "-all,+spamoor:u**", "spamoor", "user", false, unset},
		{"malformed wildcard in a negative directive: no denial, no exclusion", "+spamoor:all,-spamoor:us*er:f1", "spamoor", "f1", true, granted},
		{"malformed exclusion wildcard: the directive grants nothing", "+spamoor:all:-us*er", "spamoor", "user", true, unset},
		{"malformed exclusion wildcard: not even basic", "-all,+spamoor:all:-us*er", "spamoor", "plugins", false, unset},
		{"wildcard in the service position", "-all,+spam*:f1", "spamoor", "f1", false, unset},
		{"wildcard as the whole service", "-all,+*:f1", "spamoor", "f1", false, unset},
		{"bare wildcard service is a literal name, as before", "-all,+spam*", "spamoor", "f1", false, unset},

		// ─── malformed entries are skipped ──────────────────────────────
		{"no prefix", "spamoor:all", "spamoor", "plugins", true, unset},
		{"empty service name", "+:all", "spamoor", "plugins", true, unset},
		{"trailing colon: positive", "-all,+spamoor:", "spamoor", "plugins", false, unset},
		{"trailing colon: negative is not a denial", "+spamoor:all,-spamoor:", "spamoor", "plugins", true, granted},
		{"empty segment in the middle", "-all,+spamoor::plugins", "spamoor", "plugins", false, unset},
		{"a lone sign as a segment", "-all,+spamoor:-", "spamoor", "plugins", false, unset},
		{"an empty segment after basic: not a denial", "+spamoor:all,-spamoor:basic:", "spamoor", "plugins", true, granted},
		{"an empty segment after a feature and basic", "+spamoor:all,-spamoor:f1:basic::", "spamoor", "f1", true, granted},
		{"an empty segment before basic", "+spamoor:all,-spamoor::basic", "spamoor", "plugins", true, granted},
		{"a malformed wildcard after basic: not a denial", "+spamoor:all,-spamoor:basic:us*er", "spamoor", "plugins", true, granted},
		{"signed segment in a negative directive", "+spamoor:all,-spamoor:-x", "spamoor", "x", true, granted},
		{"signed segment in a negative directive: base", "-spamoor:-x", "spamoor", "x", true, unset},
		{"a signed segment makes the negative directive malformed: nothing excluded", "+spamoor:all,-spamoor:-x:y", "spamoor", "y", true, granted},
		{"a signed segment before basic: not a denial", "+spamoor:all,-spamoor:-x:basic", "spamoor", "y", true, granted},
		{"malformed entries between good ones", "-all,nonsense,+spamoor:f1,+", "spamoor", "f1", true, granted},

		// ─── case and whitespace ────────────────────────────────────────
		{"case in the claim", "+SpaMoor:PluGins", "spamoor", "plugins", true, granted},
		{"case in the query", "+spamoor:plugins", "SPAMOOR", "Plugins", true, granted},
		{"whitespace everywhere", " -all , + spamoor : f1 : - f2 ", " spamoor ", " f1 ", true, granted},
		{"whitespace: exclusion segment", " -all , + spamoor : all : - f2 ", "spamoor", "f2", true, excluded},

		// ─── exact names only ───────────────────────────────────────────
		{"no prefix matching of features", "+spamoor:plugins", "spamoor", "plug", true, unset},
		{"no prefix matching of services", "+spamoor:all", "spam", "plugins", true, unset},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := auth.ServiceAllowed(tc.directives, tc.service); got != tc.wantBase {
				t.Errorf("ServiceAllowed(%q, %q) = %t, want %t", tc.directives, tc.service, got, tc.wantBase)
			}
			wantDeny := tc.wantBase && tc.wantState == granted
			wantAllow := tc.wantBase && tc.wantState != excluded
			checkFeature(t, tc.directives, tc.service, tc.feature, wantDeny, wantAllow)

			// "basic" is base access, in both modes.
			checkFeature(t, tc.directives, tc.service, "basic", tc.wantBase, tc.wantBase)
			checkFeature(t, tc.directives, tc.service, " Basic ", tc.wantBase, tc.wantBase)

			// Never a feature without base access, in either mode.
			if !tc.wantBase {
				for _, def := range []auth.FeatureDefault{auth.FeatureDefaultDeny, auth.FeatureDefaultAllow} {
					if auth.FeatureAllowed(tc.directives, tc.service, tc.feature, def) {
						t.Errorf("mode %d allows %s:%s without base access (%q)", def, tc.service, tc.feature, tc.directives)
					}
				}
			}
		})
	}
}

// checkFeature asserts the answer in both modes, through the function
// and through the Claims method.
func checkFeature(t *testing.T, directives, service, feature string, wantDeny, wantAllow bool) {
	t.Helper()
	claims := &auth.Claims{Services: directives}
	for _, m := range []struct {
		name string
		def  auth.FeatureDefault
		want bool
	}{
		{"FeatureDefaultDeny", auth.FeatureDefaultDeny, wantDeny},
		{"FeatureDefaultAllow", auth.FeatureDefaultAllow, wantAllow},
	} {
		if got := auth.FeatureAllowed(directives, service, feature, m.def); got != m.want {
			t.Errorf("FeatureAllowed(%q, %q, %q, %s) = %t, want %t",
				directives, service, feature, m.name, got, m.want)
		}
		if got := claims.HasFeature(service, feature, m.def); got != m.want {
			t.Errorf("Claims.HasFeature(%q, %q, %s) = %t, want %t", service, feature, m.name, got, m.want)
		}
	}
}

// TestFeatureAllowed_TruthTable is the documented table, literally: base
// access denied / allowed × feature unset / granted / excluded × both
// modes. A token without the claim is the row "allowed, unset".
func TestFeatureAllowed_TruthTable(t *testing.T) {
	cases := []struct {
		name       string
		directives string
		wantBase   bool
		wantDeny   bool
		wantAllow  bool
	}{
		{"base denied, unset", "-all", false, false, false},
		{"base denied, granted before the denial", "+dora:roll,-dora", false, false, false},
		{"base denied, granted for every service before the denial", "+all:roll,-dora", false, false, false},
		{"base denied, excluded before the denial", "-dora:roll,-dora", false, false, false},
		{"base denied by -all, granted before", "+dora:all,-all", false, false, false},
		{"base allowed, unset", "-all,+dora", true, false, true},
		{"base allowed by default, unset", "+spamoor", true, false, true},
		{"base allowed, granted", "-all,+dora,+dora:roll", true, true, true},
		{"base allowed, granted by all", "-all,+dora,+dora:all", true, true, true},
		{"base allowed, excluded", "-all,+dora,-dora:roll", true, false, false},
		{"base allowed, excluded inside a grant of all", "+dora:all:-roll", true, false, false},
		{"empty claim: base allowed, unset", "", true, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := auth.ServiceAllowed(tc.directives, "dora"); got != tc.wantBase {
				t.Fatalf("ServiceAllowed(%q) = %t, want %t", tc.directives, got, tc.wantBase)
			}
			checkFeature(t, tc.directives, "dora", "roll", tc.wantDeny, tc.wantAllow)
			if !tc.wantBase && (tc.wantDeny || tc.wantAllow) {
				t.Fatal("test bug: a row allows a feature without base access")
			}
		})
	}
}

// TestFeatureAllowed_Arguments covers queries that do not name a
// service and a feature in the ordinary way.
func TestFeatureAllowed_Arguments(t *testing.T) {
	cases := []struct {
		name       string
		directives string
		service    string
		feature    string
		wantDeny   bool
		wantAllow  bool
	}{
		// The empty claim is basic access to every service and nothing
		// more: the service gate is open, a feature reads as under "+all".
		{"empty claim", "", "spamoor", "plugins", false, true},
		{"empty claim, empty feature", "", "spamoor", "", true, true},
		{"empty claim, blank feature", "", "spamoor", "  ", true, true},
		{"empty claim, empty service", "", "", "plugins", false, false},
		{"empty claim, blank service", "", "   ", "plugins", false, false},
		{"empty claim, empty service, basic", "", "", "basic", true, true},
		{"empty claim, empty service and feature", "", "", "", true, true},
		{"empty claim, reserved feature name", "", "spamoor", "all", false, false},
		{"empty claim, wildcard feature", "", "spamoor", "user*", false, false},
		{"empty claim, lone * as the feature", "", "spamoor", "*", false, false},
		{"empty claim, signed feature", "", "spamoor", "-plugins", false, false},
		{"empty claim, feature with a colon", "", "spamoor", "a:b", false, false},
		{"empty claim, feature with a comma", "", "spamoor", "a,+all", false, false},
		{"empty claim, service with a colon", "", "spamoor:plugins", "x", false, false},
		{"empty claim, wildcard service", "", "spam*", "f1", false, false},
		{"empty claim, service all", "", "all", "f1", false, true},
		{"empty claim, case and whitespace", "", " SPAMOOR ", " Plugins ", false, true},

		// The same queries under "+all", which the empty claim reads like.
		{"+all", "+all", "spamoor", "plugins", false, true},
		{"+all, reserved feature name", "+all", "spamoor", "all", false, false},
		{"+all, empty service", "+all", "", "plugins", false, false},

		// A whitespace or garbage claim reads the same for a feature.
		{"whitespace claim: base by default, nothing granted", " ", "spamoor", "plugins", false, true},
		{"garbage claim: base by default, nothing granted", "nonsense", "spamoor", "plugins", false, true},

		// An empty feature asks for the service itself.
		{"empty feature, service allowed", "-all,+spamoor", "spamoor", "", true, true},
		{"empty feature, service denied", "-all,+spamoor", "buildoor", "", false, false},
		{"blank feature, service allowed", "-all,+spamoor", "spamoor", "  ", true, true},

		// "basic" asks for the service itself too.
		{"basic, service allowed", "-all,+spamoor", "spamoor", "basic", true, true},
		{"basic, service denied", "-all,+spamoor", "buildoor", "basic", false, false},
		{"basic, service nothing mentions: allowed by default", "+spamoor,+buildoor", "other", "basic", true, true},
		{"basic under the empty claim", "", "spamoor", "basic", true, true},
		{"basic under the empty claim, spelled otherwise", "", "spamoor", " Basic ", true, true},

		// An empty service is refused, although ServiceAllowed lets it through.
		{"empty service, basic", "+all:all", "", "basic", false, false},
		{"empty service", "+all:all", "", "plugins", false, false},
		{"blank service", "+all:all", "   ", "plugins", false, false},
		{"empty service and feature", "+all:all", "", "", false, false},

		// Names that cannot be a feature or a service.
		{"reserved feature name all", "+spamoor:all", "spamoor", "all", false, false},
		{"signed feature", "+spamoor:-plugins", "spamoor", "-plugins", false, false},
		{"feature with a colon", "+spamoor:a:b", "spamoor", "a:b", false, false},
		{"feature with a comma", "+spamoor:a", "spamoor", "a,+all", false, false},
		{"service with a colon", "+all:all", "spamoor:plugins", "x", false, false},

		// Wildcards exist in directives only.
		{"wildcard feature query", "+spamoor:user*", "spamoor", "user*", false, false},
		{"wildcard feature query against all", "+all:all", "spamoor", "user*", false, false},
		{"lone * as the feature", "+spamoor:all", "spamoor", "*", false, false},
		{"wildcard service query", "+all:all", "spam*", "f1", false, false},

		// The pseudo-service all matches only all-directives.
		{"service all, all directive", "+all:f1", "all", "f1", true, true},
		{"service all, specific directive", "+spamoor:f1", "all", "f1", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			checkFeature(t, tc.directives, tc.service, tc.feature, tc.wantDeny, tc.wantAllow)
		})
	}

	var none *auth.Claims
	if none.HasFeature("spamoor", "plugins", auth.FeatureDefaultAllow) {
		t.Error("nil claims must not allow anything")
	}
	bare := &auth.Claims{}
	if !bare.HasFeature("spamoor", auth.FeatureBasic, auth.FeatureDefaultDeny) {
		t.Error("claims without a services claim have basic access to every service")
	}
	if !bare.HasFeature("spamoor", "plugins", auth.FeatureDefaultAllow) {
		t.Error("claims without a services claim have the default-allow features")
	}
	if bare.HasFeature("spamoor", "plugins", auth.FeatureDefaultDeny) {
		t.Error("claims without a services claim must not hold a default-deny feature")
	}
}

// emptyClaimWant states the rule for a token without a services claim,
// independently of the implementation: basic access to every service
// and nothing more. The service gate ("basic" or an empty feature) is
// open whatever is asked. Any other feature is allowed under
// default-allow and denied under default-deny, and refused in both
// modes when the service or the feature cannot be a query name.
func emptyClaimWant(service, feature string) (wantDeny, wantAllow bool) {
	name := func(s string) (string, bool) {
		s = strings.ToLower(strings.TrimSpace(s))
		for _, c := range []string{":", ",", "*"} {
			if strings.Contains(s, c) {
				return s, false
			}
		}
		return s, s != "" && !strings.HasPrefix(s, "-") && !strings.HasPrefix(s, "+")
	}
	f, featureOK := name(feature)
	if f == "" || f == "basic" {
		return true, true
	}
	if _, serviceOK := name(service); !serviceOK || !featureOK || f == "all" {
		return false, false
	}
	return false, true
}

// TestFeatureAllowed_EmptyClaimIsBasicAccessOnly runs every combination
// of a set of services and features — ordinary, reserved, malformed,
// in odd case and whitespace — against the empty directive string and
// compares with the rule (emptyClaimWant). For every feature but the
// service gate the answer must also be the one "+all" gives.
func TestFeatureAllowed_EmptyClaimIsBasicAccessOnly(t *testing.T) {
	services := []string{
		"spamoor", "SPAMOOR", " spamoor ", "my-service", "other", "all", "basic", "x",
		"", "   ", "*", "spam*", "spamoor:plugins", "a,b", "-spamoor", "+spamoor",
	}
	features := []string{
		"plugins", "PLUGINS", " plugins ", "f1", "user-admin", "roll", "basics", "allx", "b",
		"", "  ", "basic", " Basic ", "BASIC", "all", "ALL", " all ",
		"*", "user*", "us*er", "a:b", "a,b", "a,+all", "-plugins", "+plugins", "-", "+", ":", ",",
	}
	plain, refused, gate := 0, 0, 0
	for _, service := range services {
		if !auth.ServiceAllowed("", service) {
			t.Errorf("ServiceAllowed(\"\", %q) = false: the empty claim allows every service", service)
		}
		for _, feature := range features {
			wantDeny, wantAllow := emptyClaimWant(service, feature)
			checkFeature(t, "", service, feature, wantDeny, wantAllow)

			switch {
			case wantDeny:
				gate++
				continue // the service gate; "+all" refuses it for an empty service
			case wantAllow:
				plain++
			default:
				refused++
			}
			// The rule, said the other way: exactly as under "+all".
			checkFeature(t, "+all", service, feature, wantDeny, wantAllow)
		}
	}
	if plain == 0 || refused == 0 || gate == 0 {
		t.Fatalf("the cases are one-sided: plain=%d refused=%d gate=%d", plain, refused, gate)
	}
}

// TestServiceAllowed_SameAsV003WithoutColons proves exactly this much:
// for every directive list WITHOUT a ":" — the only kind the v0.0.3
// parser understood — base-access evaluation is unchanged. It runs the
// cases of the original test table, those of the grant-grammar branch,
// and a large generated set built from every kind of fragment that
// parser distinguishes (signs, names, "all", case, whitespace,
// malformed entries).
//
// It says nothing about lists with a ":", which the generator leaves
// out by construction. Those can read differently for old and new
// verifiers; see TestServiceAllowed_DiffersFromV003WithColons for the
// differences, and the issuer's
// TestServiceGrants_OldVerifiersAgreeOnBaseAccess for the guarantee
// that holds there: everything the issuer emits reads the same.
func TestServiceAllowed_SameAsV003WithoutColons(t *testing.T) {
	type query struct{ directives, service string }
	queries := []query{
		{"", "spamoor"},
		{"-all", ""},
		{"+all", "spamoor"},
		{"-all", "spamoor"},
		{"+all,-spamoor", "spamoor"},
		{"+all,-buildoor", "spamoor"},
		{"-all,+spamoor", "spamoor"},
		{"-all,+buildoor", "spamoor"},
		{"+spamoor,-spamoor", "spamoor"},
		{"-spamoor,+spamoor", "spamoor"},
		{"-spamoor,+all", "spamoor"},
		{"+buildoor,-monitoring", "spamoor"},
		{"+ALL,-Spamoor", "spamoor"},
		{"+all,-spamoor", "SPAMOOR"},
		{" +all , -spamoor ", "spamoor"},
		{"all,-spamoor", "spamoor"},
		{"+,-spamoor", "spamoor"},
		{"+", "spamoor"},
		{"-all", "buildoor"},
		{"-all,+spamoor,+buildoor,-buildoor", "buildoor"},
		{"-all,+spamoor,+buildoor,-buildoor", "spamoor"},
		{"-all,+spamoor", "   "},
		{"-all,+spamoor", " spamoor "},
		{"-all", "all"},
		{"+all,-all", "all"},
		{"-spamoor", "all"},
		{" ", "spamoor"},
		{",,,", "spamoor"},
	}

	fragments := []string{
		"+all", "-all", "+ALL", "-All", "+spamoor", "-spamoor", "+Spamoor", "-SPAMOOR",
		"+buildoor", "-buildoor", "+dora", "-dora", "+my-service", "-x",
		" +spamoor ", " - spamoor", "+ all", "-\tall", "", " ", "+", "-", "all", "spamoor",
		"*", "+*", "-*", "++spamoor", "--all", "+-spamoor", "+spamoor+buildoor", "+spamoor buildoor",
	}
	services := []string{"spamoor", "SPAMOOR", " spamoor ", "buildoor", "dora", "my-service", "other", "all", "x", "*", ""}

	rng := rand.New(rand.NewSource(20261114))
	for range 20000 {
		n := rng.Intn(7)
		parts := make([]string, 0, n)
		for range n {
			parts = append(parts, fragments[rng.Intn(len(fragments))])
		}
		queries = append(queries, query{strings.Join(parts, ","), services[rng.Intn(len(services))]})
	}

	for _, q := range queries {
		if strings.Contains(q.directives, ":") {
			t.Fatalf("test bug: %q is not a legacy directive list", q.directives)
		}
		want := legacyServiceAllowed(q.directives, q.service)
		if got := auth.ServiceAllowed(q.directives, q.service); got != want {
			t.Errorf("ServiceAllowed(%q, %q) = %t, v0.0.3 says %t", q.directives, q.service, got, want)
		}
	}
}

// TestFeatureAllowed_NeverWithoutBaseAccess checks, over generated
// directive lists in the full grammar, the formula behind
// FeatureAllowed: a feature is never allowed without base access to its
// service in either mode, default-deny never allows what default-allow
// refuses, and an empty feature is the base question. The empty claim
// is one of the lists: it obeys the same formula, and default-deny
// allows nothing under it.
func TestFeatureAllowed_NeverWithoutBaseAccess(t *testing.T) {
	fragments := []string{
		"+all", "-all", "+spamoor", "-spamoor", "+buildoor", "-buildoor",
		"+all:all", "+all:f1", "+all:-f1", "+all:all:-f2", "-all:f1", "-all:all",
		"+spamoor:all", "+spamoor:f1", "+spamoor:f1:f2", "+spamoor:-f1", "+spamoor:all:-f1",
		"-spamoor:f1", "-spamoor:all", "-spamoor:-f1", "+spamoor:", "-spamoor:", "+buildoor:f2",
		"+spamoor:basic", "-spamoor:basic", "+spamoor:-basic", "+spamoor:all:-basic", "-all:basic",
		"+all:basic:f1", "-spamoor:f1:basic", "-buildoor:-basic",
		"+spamoor:f*", "-spamoor:f*", "+all:all:-f*", "+spamoor:*", "-all:*", "+spamoor:f*1", "-spamoor:b*",
		"nonsense", "",
	}
	rng := rand.New(rand.NewSource(7))
	allowedDeny, allowedAllow, refusedForBase := 0, 0, 0
	for range 20000 {
		n := 1 + rng.Intn(6)
		parts := make([]string, 0, n)
		for range n {
			parts = append(parts, fragments[rng.Intn(len(fragments))])
		}
		directives := strings.Join(parts, ",")
		for _, service := range []string{"spamoor", "buildoor", "other"} {
			base := auth.ServiceAllowed(directives, service)
			if got := auth.FeatureAllowed(directives, service, "", auth.FeatureDefaultDeny); got != base {
				t.Errorf("%q: empty feature on %s = %t, base access = %t", directives, service, got, base)
			}
			for _, def := range []auth.FeatureDefault{auth.FeatureDefaultDeny, auth.FeatureDefaultAllow} {
				if got := auth.FeatureAllowed(directives, service, auth.FeatureBasic, def); got != base {
					t.Errorf("%q: basic on %s (mode %d) = %t, ServiceAllowed = %t", directives, service, def, got, base)
				}
			}
			for _, feature := range []string{"f1", "f2", "f3"} {
				deny := auth.FeatureAllowed(directives, service, feature, auth.FeatureDefaultDeny)
				allow := auth.FeatureAllowed(directives, service, feature, auth.FeatureDefaultAllow)
				if (deny || allow) && !base {
					t.Errorf("%q allows %s:%s without base access (deny=%t allow=%t)",
						directives, service, feature, deny, allow)
				}
				if deny && !allow {
					t.Errorf("%q: %s:%s allowed under default-deny but not under default-allow",
						directives, service, feature)
				}
				if strings.Trim(directives, ",") == "" && (deny || !allow) {
					// No directive at all — the empty claim, or only
					// separators: basic access, the feature unset.
					t.Errorf("%q: %s:%s deny=%t allow=%t, want basic access and nothing more",
						directives, service, feature, deny, allow)
				}
				if deny {
					allowedDeny++
				}
				if allow {
					allowedAllow++
				}
				if !base {
					refusedForBase++
				}
			}
		}
	}
	if allowedDeny == 0 || allowedAllow == allowedDeny || refusedForBase == 0 {
		t.Fatalf("the generator is not exercising the cases: deny=%d allow=%d noBase=%d",
			allowedDeny, allowedAllow, refusedForBase)
	}
	t.Logf("default-deny allowed %d, default-allow allowed %d, %d refused for lack of base access",
		allowedDeny, allowedAllow, refusedForBase)
}

// TestFeatureAllowed_BasicIsServiceAllowed generates directive lists
// from the grammar — signs, services, "all", every kind of segment
// including basic, whitespace, case and malformed entries — and asserts
// that asking for the feature "basic" is asking ServiceAllowed, in both
// modes, for services the list names and for ones it does not. The
// empty claim is included.
func TestFeatureAllowed_BasicIsServiceAllowed(t *testing.T) {
	signs := []string{"+", "-", "+", "-", "", " + ", "++"}
	names := []string{"spamoor", "buildoor", "dora", "all", "ALL", " Spamoor ", "", "basic"}
	segments := []string{
		"", "", "", ":basic", ":-basic", ":all", ":-all", ":f1", ":-f1", ":f1:f2", ":all:-f1", ":-f1:all",
		":basic:f1", ":f1:basic", ":all:-basic", ":-basic:f1", ":", "::f1", ":-", ": Basic ", ":BASIC",
		":b*", ":-b*", ":basic*", ":-basi*", ":*", ":-*", ":f*", ":us*er", ":*x", ":all:-b*",
	}
	services := []string{"spamoor", "buildoor", "dora", "unmentioned", "all", "basic", " SPAMOOR "}

	rng := rand.New(rand.NewSource(11))
	directiveLists := []string{"", "+spamoor,+buildoor", "-all", "+all"}
	for range 30000 {
		n := rng.Intn(6)
		parts := make([]string, 0, n)
		for range n {
			parts = append(parts,
				signs[rng.Intn(len(signs))]+names[rng.Intn(len(names))]+segments[rng.Intn(len(segments))])
		}
		directiveLists = append(directiveLists, strings.Join(parts, ","))
	}

	allowed, denied := 0, 0
	for _, directives := range directiveLists {
		for _, service := range services {
			want := auth.ServiceAllowed(directives, service)
			if want {
				allowed++
			} else {
				denied++
			}
			for _, def := range []auth.FeatureDefault{auth.FeatureDefaultDeny, auth.FeatureDefaultAllow} {
				if got := auth.FeatureAllowed(directives, service, auth.FeatureBasic, def); got != want {
					t.Errorf("FeatureAllowed(%q, %q, basic, mode %d) = %t, ServiceAllowed = %t",
						directives, service, def, got, want)
				}
			}
		}
	}
	if allowed == 0 || denied == 0 {
		t.Fatalf("the generator is one-sided: allowed=%d denied=%d", allowed, denied)
	}
}

// TestServiceAllowed_DiffersFromV003WithColons records the differences
// between this evaluator and the v0.0.3 one for directive lists that
// contain a ":". They are inherent in "a positive directive grants
// basic access": the old parser takes "+spamoor:x" for a service named
// "spamoor:x" and skips it. No claim this repository's issuer emits is
// affected — it always writes the bare directive too and emits no
// denial with segments — but a claim written by hand is, unless it
// repeats the bare directive.
func TestServiceAllowed_DiffersFromV003WithColons(t *testing.T) {
	cases := []struct {
		name       string
		directives string
		service    string
		v003       bool
		current    bool
	}{
		{"a feature directive alone grants basic access now", "-all,+spamoor:x", "spamoor", false, true},
		{"+all with a feature grants basic access everywhere now", "-all,+all:x", "spamoor", false, true},
		{"-a:b was a denial of a service named a:b", "-a:b", "a:b", false, true},
		{"-spamoor:basic denies the service now", "-spamoor:basic", "spamoor", true, false},

		// The same intent written the compatible way reads the same.
		{"compatible: the bare directive repeated", "-all,+spamoor,+spamoor:x", "spamoor", true, true},
		{"compatible: +all repeated", "-all,+all,+all:x", "spamoor", true, true},
		{"compatible: a plain denial", "-spamoor", "spamoor", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := legacyServiceAllowed(tc.directives, tc.service); got != tc.v003 {
				t.Errorf("v0.0.3: ServiceAllowed(%q, %q) = %t, want %t", tc.directives, tc.service, got, tc.v003)
			}
			if got := auth.ServiceAllowed(tc.directives, tc.service); got != tc.current {
				t.Errorf("current: ServiceAllowed(%q, %q) = %t, want %t", tc.directives, tc.service, got, tc.current)
			}
		})
	}
}

// TestDirectives_OddInputTerminates throws structurally hostile claims
// at both evaluators: very long lists, runs of separators, signs and
// wildcards, non-UTF-8 bytes. Nothing may panic or take long.
func TestDirectives_OddInputTerminates(t *testing.T) {
	inputs := []string{
		strings.Repeat(",", 100000),
		strings.Repeat(":", 100000),
		strings.Repeat("+", 100000),
		strings.Repeat("-all,", 50000),
		"+spamoor" + strings.Repeat(":x", 50000),
		"+spamoor:" + strings.Repeat("*", 50000),
		"+spamoor:" + strings.Repeat("a*", 20000),
		"+" + strings.Repeat("a", 100000) + ":" + strings.Repeat("b", 100000),
		strings.Repeat("+all:all:-all,", 20000),
		"+spamoor:\xff\xfe,-\x00:\x00,+\u212a:\u212a*",
		"+spamoor:-:-:-,-spamoor:basic:basic:,+:,-:,+*:*,-*",
		" \t\n,\t :\n ",
	}
	start := time.Now()
	for _, in := range inputs {
		for _, service := range []string{"spamoor", "x", "all", "*", ""} {
			auth.ServiceAllowed(in, service)
			for _, feature := range []string{"x", "basic", "all", "a", ""} {
				auth.FeatureAllowed(in, service, feature, auth.FeatureDefaultDeny)
				auth.FeatureAllowed(in, service, feature, auth.FeatureDefaultAllow)
			}
		}
	}
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Errorf("odd inputs took %s", elapsed)
	}
}
