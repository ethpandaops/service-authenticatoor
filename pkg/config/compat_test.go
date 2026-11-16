package config

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/ethpandaops/service-authenticatoor/pkg/issuer"
)

// The files under testdata/compat are configs that versions before this
// one accepted. They are kept as they were written then:
//
//	helm-master-*.yaml   what the authenticatoor chart of
//	                     ethereum-helm-charts (master) renders: with its
//	                     default values, and with every optional value set
//	v0.0.N-example.yaml  config.example.yaml of the release
//	v0.0.N-hack-local    .hack/local/config.yaml of the release
//	v0.0.N-docs-NN.yaml  the YAML blocks of docs/config.md of the release
//	v0.0.N-readme-NN     the YAML blocks of README.md of the release
//	main-*               the same, from the main branch this version
//	                     was built on
//	deprecated-*.yaml,   written for this test: keys that a release
//	legacy-all-blocks    documented or read and that are gone since
//
// A file that is byte-identical to one of an earlier release is not
// repeated. golden.json holds, for each file, what the main branch
// before this version made of it: the resolved config and the claims of
// a token it issued.
//
// A deployment gets the new binary before it gets a new config. Every
// one of these files therefore has to load, resolve to the same
// providers and settings, and yield a token with the same claims.

var (
	compatHasIssuer  = regexp.MustCompile(`(?m)^issuer:`)
	compatHasSigning = regexp.MustCompile(`(?m)^signing:`)
)

// compatConfig returns the path of a loadable copy of a fixture. The
// snippets taken from the documentation show one section each; they get
// the two required settings they leave out, exactly as they did when
// golden.json was made.
func compatConfig(t *testing.T, fixture string) string {
	t.Helper()
	body, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	text := string(body)
	if !compatHasIssuer.MatchString(text) {
		text = "issuer: \"https://auth.example.com\"\n" + text
	}
	if !compatHasSigning.MatchString(text) {
		text += "\nsigning:\n  rs256:\n    privateKeyFile: \"/etc/authenticatoor/keys/private.pem\"\n"
	}
	return writeTempConfig(t, text)
}

// compatTrim drops what golden.json does not record: empty values
// (but never a boolean — an explicit false is a setting).
func compatTrim(v any) any {
	switch value := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(value))
		for k, item := range value {
			item = compatTrim(item)
			switch typed := item.(type) {
			case nil:
				continue
			case string:
				if typed == "" {
					continue
				}
			case float64:
				if typed == 0 {
					continue
				}
			case []any:
				if len(typed) == 0 {
					continue
				}
			case map[string]any:
				if len(typed) == 0 {
					continue
				}
			}
			out[k] = item
		}
		return out
	case []any:
		out := make([]any, 0, len(value))
		for _, item := range value {
			out = append(out, compatTrim(item))
		}
		return out
	default:
		return v
	}
}

// compatGeneric turns a value into the generic form golden.json has.
func compatGeneric(t *testing.T, v any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	trimmed, _ := compatTrim(out).(map[string]any)
	return trimmed
}

// compatMissing lists where got lacks, or differs from, what want
// holds. got may hold more: settings that did not exist before.
func compatMissing(path string, want, got any) []string {
	switch w := want.(type) {
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok {
			return []string{path + ": want a map, got " + reflect.TypeOf(got).String()}
		}
		var out []string
		for k, item := range w {
			child, present := g[k]
			if !present {
				out = append(out, path+"."+k+": missing")
				continue
			}
			out = append(out, compatMissing(path+"."+k, item, child)...)
		}
		return out
	case []any:
		g, ok := got.([]any)
		if !ok || len(g) != len(w) {
			return []string{path + ": lists differ"}
		}
		var out []string
		for i := range w {
			out = append(out, compatMissing(path+"[]", w[i], g[i])...)
		}
		return out
	default:
		if !reflect.DeepEqual(want, got) {
			return []string{path + ": differs"}
		}
		return nil
	}
}

// TestLoad_ConfigsOfReleasedVersions: see the comment at the top of
// this file.
func TestLoad_ConfigsOfReleasedVersions(t *testing.T) {
	const dir = "testdata/compat"
	raw, err := os.ReadFile(filepath.Join(dir, "golden.json"))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var golden map[string]struct {
		Config map[string]any `json:"config"`
		Claims map[string]any `json:"claims"`
	}
	if err := json.Unmarshal(raw, &golden); err != nil {
		t.Fatalf("golden: %v", err)
	}
	fixtures, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil || len(fixtures) < 20 {
		t.Fatalf("fixtures: %d (%v)", len(fixtures), err)
	}
	if len(golden) != len(fixtures) {
		t.Fatalf("%d fixtures, %d golden entries", len(fixtures), len(golden))
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("key: %v", err)
	}

	// Deprecation warnings each fixture is expected to produce; none
	// for all the others.
	deprecations := map[string][]string{
		"deprecated-anyauth-loginpath.yaml": {"anyAuth.loginPath"},
		"deprecated-github-sessionsecret.yaml": {
			"githubOAuth.sessionSecret ", "githubOAuth.sessionSecretFile ",
		},
		"legacy-all-blocks.yaml": {"anyAuth.loginPath", "githubOAuth.sessionSecretFile"},
	}

	for _, fixture := range fixtures {
		name := filepath.Base(fixture)
		t.Run(name, func(t *testing.T) {
			want, ok := golden[name]
			if !ok {
				t.Fatal("no golden entry")
			}
			cfg, err := Load(compatConfig(t, fixture))
			if err != nil {
				t.Fatalf("a config that earlier versions accepted does not load: %v", err)
			}

			// The same resolved config: providers, their names and
			// types, paths and cookie names, every setting.
			got := compatGeneric(t, cfg)
			if diff := compatMissing("config", map[string]any(want.Config), got); len(diff) > 0 {
				slices.Sort(diff)
				t.Errorf("the resolved config changed:\n  %s", strings.Join(diff, "\n  "))
			}

			// Nothing but what is expected is complained about.
			if len(cfg.DeprecationWarnings) != len(deprecations[name]) {
				t.Errorf("deprecation warnings: %v", cfg.DeprecationWarnings)
			}
			for i, part := range deprecations[name] {
				if i < len(cfg.DeprecationWarnings) && !strings.Contains(cfg.DeprecationWarnings[i], part) {
					t.Errorf("deprecation warning %d: %q, want %q in it", i, cfg.DeprecationWarnings[i], part)
				}
			}
			for _, w := range cfg.Warnings {
				// Two notes are due on such configs: what happens to
				// unverified emails at an oidc provider, and that a
				// Cloudflare door without audTag is shared.
				if !strings.Contains(w, "oidc.trustUnverifiedEmail is not set") {
					t.Errorf("unexpected warning: %s", w)
				}
			}
			if cfg.Grants != nil {
				t.Error("a config without a grants section got one")
			}

			// The same token. An identity as the first provider hands
			// it to the issuer: with its provider name, without teams.
			iss, err := issuer.NewRS256Issuer(issuer.Config{
				ActiveKey:       key,
				ActiveKeyID:     cfg.Signing.RS256.KeyID,
				Issuer:          cfg.Issuer,
				DefaultAudience: cfg.Audience,
				Scope:           cfg.ScopePattern,
				TTL:             cfg.TokenTTL,
			})
			if err != nil {
				t.Fatalf("issuer: %v", err)
			}
			_, claims, err := iss.IssueFor(issuer.Identity{
				Subject:        "alice@example.org",
				Email:          "alice@example.org",
				SubjectIsEmail: true,
				Provider:       cfg.Providers[0].Name,
			}, nil)
			if err != nil {
				t.Fatalf("issue: %v", err)
			}
			minted := compatGeneric(t, claims)
			minted["ttl"] = minted["exp"].(float64) - minted["iat"].(float64)
			for _, volatile := range []string{"iat", "nbf", "exp", "jti"} {
				delete(minted, volatile)
			}
			if !reflect.DeepEqual(minted, map[string]any(want.Claims)) {
				t.Errorf("token claims changed:\n  got  %v\n  want %v", minted, want.Claims)
			}
		})
	}
}
