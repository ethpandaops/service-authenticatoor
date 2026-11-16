// Package directivecases holds the test tables for the evaluation of the
// "services" claim: the directive lists, queries and generator fragments
// that pkg/auth runs against ServiceAllowed and FeatureAllowed. They live
// here, outside a _test file, so that the tests of the browser client's
// port of the evaluator (pkg/server) run the very same rows instead of a
// copy. Nothing but tests imports this package.
package directivecases

import "strings"

// What a directive list says about one feature; see auth.FeatureAllowed.
const (
	Unset    = "unset"
	Granted  = "granted"
	Excluded = "excluded"

	unset    = Unset
	granted  = Granted
	excluded = Excluded
)

// ServiceCase is one row of the base-access table.
type ServiceCase struct {
	Name       string
	Directives string
	Service    string
	Want       bool
}

// Service is the table for ServiceAllowed.
var Service = []ServiceCase{
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

// GrammarCase states what a directive list means for the queried service
// (base access) and feature (Unset / Granted / Excluded).
type GrammarCase struct {
	Name       string
	Directives string
	Service    string
	Feature    string
	WantBase   bool
	WantState  string
}

// Grammar covers every documented directive form.
var Grammar = []GrammarCase{
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

// TruthTableCase is one row of the documented truth table, asked for the
// feature TruthTableFeature of the service TruthTableService.
type TruthTableCase struct {
	Name       string
	Directives string
	WantBase   bool
	WantDeny   bool
	WantAllow  bool
}

// The query every TruthTable row is asked.
const (
	TruthTableService = "dora"
	TruthTableFeature = "roll"
)

// TruthTable is the documented table, literally: base access denied /
// allowed × feature unset / granted / excluded × both modes.
var TruthTable = []TruthTableCase{
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

// ArgumentCase is a query with the expected answer in both modes.
type ArgumentCase struct {
	Name       string
	Directives string
	Service    string
	Feature    string
	WantDeny   bool
	WantAllow  bool
}

// Arguments covers queries that do not name a service and a feature in
// the ordinary way.
var Arguments = []ArgumentCase{
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

// EmptyClaimServices and EmptyClaimFeatures are combined, every one with
// every other, against the empty directive string.
var (
	EmptyClaimServices = []string{
		"spamoor", "SPAMOOR", " spamoor ", "my-service", "other", "all", "basic", "x",
		"", "   ", "*", "spam*", "spamoor:plugins", "a,b", "-spamoor", "+spamoor",
	}
	EmptyClaimFeatures = []string{
		"plugins", "PLUGINS", " plugins ", "f1", "user-admin", "roll", "basics", "allx", "b",
		"", "  ", "basic", " Basic ", "BASIC", "all", "ALL", " all ",
		"*", "user*", "us*er", "a:b", "a,b", "a,+all", "-plugins", "+plugins", "-", "+", ":", ",",
	}
)

// Query is a base-access question.
type Query struct{ Directives, Service string }

// LegacyQueries are directive lists without a ":" — the only kind the
// v0.0.3 evaluator understood.
var LegacyQueries = []Query{
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

// LegacyFragments and LegacyServices feed the generator of directive
// lists without a ":".
var (
	LegacyFragments = []string{
		"+all", "-all", "+ALL", "-All", "+spamoor", "-spamoor", "+Spamoor", "-SPAMOOR",
		"+buildoor", "-buildoor", "+dora", "-dora", "+my-service", "-x",
		" +spamoor ", " - spamoor", "+ all", "-\tall", "", " ", "+", "-", "all", "spamoor",
		"*", "+*", "-*", "++spamoor", "--all", "+-spamoor", "+spamoor+buildoor", "+spamoor buildoor",
	}
	LegacyServices = []string{"spamoor", "SPAMOOR", " spamoor ", "buildoor", "dora", "my-service", "other", "all", "x", "*", ""}
)

// FeatureFragments feed the generator of directive lists in the full
// grammar; the lists are queried for FeatureServices × FeatureFeatures.
var (
	FeatureFragments = []string{
		"+all", "-all", "+spamoor", "-spamoor", "+buildoor", "-buildoor",
		"+all:all", "+all:f1", "+all:-f1", "+all:all:-f2", "-all:f1", "-all:all",
		"+spamoor:all", "+spamoor:f1", "+spamoor:f1:f2", "+spamoor:-f1", "+spamoor:all:-f1",
		"-spamoor:f1", "-spamoor:all", "-spamoor:-f1", "+spamoor:", "-spamoor:", "+buildoor:f2",
		"+spamoor:basic", "-spamoor:basic", "+spamoor:-basic", "+spamoor:all:-basic", "-all:basic",
		"+all:basic:f1", "-spamoor:f1:basic", "-buildoor:-basic",
		"+spamoor:f*", "-spamoor:f*", "+all:all:-f*", "+spamoor:*", "-all:*", "+spamoor:f*1", "-spamoor:b*",
		"nonsense", "",
	}
	FeatureServices = []string{"spamoor", "buildoor", "other"}
	FeatureFeatures = []string{"f1", "f2", "f3"}
)

// BasicSigns, BasicNames and BasicSegments are concatenated, one of each,
// into the directives of generated lists; BasicLists are fixed lists run
// next to the generated ones, and BasicServices the services queried.
var (
	BasicSigns    = []string{"+", "-", "+", "-", "", " + ", "++"}
	BasicNames    = []string{"spamoor", "buildoor", "dora", "all", "ALL", " Spamoor ", "", "basic"}
	BasicSegments = []string{
		"", "", "", ":basic", ":-basic", ":all", ":-all", ":f1", ":-f1", ":f1:f2", ":all:-f1", ":-f1:all",
		":basic:f1", ":f1:basic", ":all:-basic", ":-basic:f1", ":", "::f1", ":-", ": Basic ", ":BASIC",
		":b*", ":-b*", ":basic*", ":-basi*", ":*", ":-*", ":f*", ":us*er", ":*x", ":all:-b*",
	}
	BasicServices = []string{"spamoor", "buildoor", "dora", "unmentioned", "all", "basic", " SPAMOOR "}
	BasicLists    = []string{"", "+spamoor,+buildoor", "-all", "+all"}
)

// V003DiffCase records how a directive list with a ":" reads for the
// v0.0.3 evaluator and for the current one.
type V003DiffCase struct {
	Name       string
	Directives string
	Service    string
	V003       bool
	Current    bool
}

// V003Diff lists the differences to the v0.0.3 evaluator.
var V003Diff = []V003DiffCase{
	{"a feature directive alone grants basic access now", "-all,+spamoor:x", "spamoor", false, true},
	{"+all with a feature grants basic access everywhere now", "-all,+all:x", "spamoor", false, true},
	{"-a:b was a denial of a service named a:b", "-a:b", "a:b", false, true},
	{"-spamoor:basic denies the service now", "-spamoor:basic", "spamoor", true, false},

	// The same intent written the compatible way reads the same.
	{"compatible: the bare directive repeated", "-all,+spamoor,+spamoor:x", "spamoor", true, true},
	{"compatible: +all repeated", "-all,+all,+all:x", "spamoor", true, true},
	{"compatible: a plain denial", "-spamoor", "spamoor", false, false},
}

// OddInputs are structurally hostile claims: very long lists, runs of
// separators, signs and wildcards, non-UTF-8 bytes. OddServices and
// OddFeatures are the queries they are run with.
var (
	OddInputs = []string{
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
	OddServices = []string{"spamoor", "x", "all", "*", ""}
	OddFeatures = []string{"x", "basic", "all", "a", ""}
)
