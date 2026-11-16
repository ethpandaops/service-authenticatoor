package auth_test

import (
	"math/rand"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ethpandaops/service-authenticatoor/internal/directivecases"
	"github.com/ethpandaops/service-authenticatoor/pkg/auth"
)

func TestServiceAllowed(t *testing.T) {
	cases := directivecases.Service

	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			got := auth.ServiceAllowed(tc.Directives, tc.Service)
			if got != tc.Want {
				t.Errorf("ServiceAllowed(%q, %q) = %v, want %v",
					tc.Directives, tc.Service, got, tc.Want)
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
	granted  = directivecases.Granted
	excluded = directivecases.Excluded
)

// TestFeatureAllowed_Grammar covers every documented directive form.
// Each row states what the list means for the queried service (base
// access) and feature (unset / granted / excluded); the expected answer
// in both modes follows from the truth table pinned literally in
// TestFeatureAllowed_TruthTable.
func TestFeatureAllowed_Grammar(t *testing.T) {
	cases := directivecases.Grammar
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			if got := auth.ServiceAllowed(tc.Directives, tc.Service); got != tc.WantBase {
				t.Errorf("ServiceAllowed(%q, %q) = %t, want %t", tc.Directives, tc.Service, got, tc.WantBase)
			}
			wantDeny := tc.WantBase && tc.WantState == granted
			wantAllow := tc.WantBase && tc.WantState != excluded
			checkFeature(t, tc.Directives, tc.Service, tc.Feature, wantDeny, wantAllow)

			// "basic" is base access, in both modes.
			checkFeature(t, tc.Directives, tc.Service, "basic", tc.WantBase, tc.WantBase)
			checkFeature(t, tc.Directives, tc.Service, " Basic ", tc.WantBase, tc.WantBase)

			// Never a feature without base access, in either mode.
			if !tc.WantBase {
				for _, def := range []auth.FeatureDefault{auth.FeatureDefaultDeny, auth.FeatureDefaultAllow} {
					if auth.FeatureAllowed(tc.Directives, tc.Service, tc.Feature, def) {
						t.Errorf("mode %d allows %s:%s without base access (%q)", def, tc.Service, tc.Feature, tc.Directives)
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
	cases := directivecases.TruthTable
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			if got := auth.ServiceAllowed(tc.Directives, directivecases.TruthTableService); got != tc.WantBase {
				t.Fatalf("ServiceAllowed(%q) = %t, want %t", tc.Directives, got, tc.WantBase)
			}
			checkFeature(t, tc.Directives, directivecases.TruthTableService, directivecases.TruthTableFeature, tc.WantDeny, tc.WantAllow)
			if !tc.WantBase && (tc.WantDeny || tc.WantAllow) {
				t.Fatal("test bug: a row allows a feature without base access")
			}
		})
	}
}

// TestFeatureAllowed_Arguments covers queries that do not name a
// service and a feature in the ordinary way.
func TestFeatureAllowed_Arguments(t *testing.T) {
	cases := directivecases.Arguments
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			checkFeature(t, tc.Directives, tc.Service, tc.Feature, tc.WantDeny, tc.WantAllow)
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
	services := directivecases.EmptyClaimServices
	features := directivecases.EmptyClaimFeatures
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
	queries := slices.Clone(directivecases.LegacyQueries)
	fragments := directivecases.LegacyFragments
	services := directivecases.LegacyServices

	rng := rand.New(rand.NewSource(20261114))
	for range 20000 {
		n := rng.Intn(7)
		parts := make([]string, 0, n)
		for range n {
			parts = append(parts, fragments[rng.Intn(len(fragments))])
		}
		queries = append(queries, directivecases.Query{
			Directives: strings.Join(parts, ","),
			Service:    services[rng.Intn(len(services))],
		})
	}

	for _, q := range queries {
		if strings.Contains(q.Directives, ":") {
			t.Fatalf("test bug: %q is not a legacy directive list", q.Directives)
		}
		want := legacyServiceAllowed(q.Directives, q.Service)
		if got := auth.ServiceAllowed(q.Directives, q.Service); got != want {
			t.Errorf("ServiceAllowed(%q, %q) = %t, v0.0.3 says %t", q.Directives, q.Service, got, want)
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
	fragments := directivecases.FeatureFragments
	rng := rand.New(rand.NewSource(7))
	allowedDeny, allowedAllow, refusedForBase := 0, 0, 0
	for range 20000 {
		n := 1 + rng.Intn(6)
		parts := make([]string, 0, n)
		for range n {
			parts = append(parts, fragments[rng.Intn(len(fragments))])
		}
		directives := strings.Join(parts, ",")
		for _, service := range directivecases.FeatureServices {
			base := auth.ServiceAllowed(directives, service)
			if got := auth.FeatureAllowed(directives, service, "", auth.FeatureDefaultDeny); got != base {
				t.Errorf("%q: empty feature on %s = %t, base access = %t", directives, service, got, base)
			}
			for _, def := range []auth.FeatureDefault{auth.FeatureDefaultDeny, auth.FeatureDefaultAllow} {
				if got := auth.FeatureAllowed(directives, service, auth.FeatureBasic, def); got != base {
					t.Errorf("%q: basic on %s (mode %d) = %t, ServiceAllowed = %t", directives, service, def, got, base)
				}
			}
			for _, feature := range directivecases.FeatureFeatures {
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
	signs := directivecases.BasicSigns
	names := directivecases.BasicNames
	segments := directivecases.BasicSegments
	services := directivecases.BasicServices

	rng := rand.New(rand.NewSource(11))
	directiveLists := slices.Clone(directivecases.BasicLists)
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
	cases := directivecases.V003Diff
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			if got := legacyServiceAllowed(tc.Directives, tc.Service); got != tc.V003 {
				t.Errorf("v0.0.3: ServiceAllowed(%q, %q) = %t, want %t", tc.Directives, tc.Service, got, tc.V003)
			}
			if got := auth.ServiceAllowed(tc.Directives, tc.Service); got != tc.Current {
				t.Errorf("current: ServiceAllowed(%q, %q) = %t, want %t", tc.Directives, tc.Service, got, tc.Current)
			}
		})
	}
}

// TestDirectives_OddInputTerminates throws structurally hostile claims
// at both evaluators: very long lists, runs of separators, signs and
// wildcards, non-UTF-8 bytes. Nothing may panic or take long.
func TestDirectives_OddInputTerminates(t *testing.T) {
	inputs := directivecases.OddInputs
	start := time.Now()
	for _, in := range inputs {
		for _, service := range directivecases.OddServices {
			auth.ServiceAllowed(in, service)
			for _, feature := range directivecases.OddFeatures {
				auth.FeatureAllowed(in, service, feature, auth.FeatureDefaultDeny)
				auth.FeatureAllowed(in, service, feature, auth.FeatureDefaultAllow)
			}
		}
	}
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Errorf("odd inputs took %s", elapsed)
	}
}
