package config

import (
	"reflect"
	"strings"
	"testing"

	"github.com/ethpandaops/service-authenticatoor/pkg/protection"
)

// TestLoad_CaseVariantKeys: the loader reads keys case-insensitively
// and would merge two spellings of one key — in an order that differs
// from one start to the next. Every such pair is a startup error that
// names both spellings, wherever it is. These load real files.
func TestLoad_CaseVariantKeys(t *testing.T) {
	cf := `
cloudflareAccess:
  teamDomain: "test.cloudflareaccess.com"
`
	oidcProvider := `
providers:
  - name: oidc
    type: oidc
    oidc:
      issuerURL: "https://idp.example.com"
      callbackURL: "https://auth.demo.example.com/oidc/callback"
      clientId: "id"
      clientSecret: "secret"
`
	tests := []struct {
		name    string
		body    string
		wantErr string
	}{
		{
			"the grants section written twice",
			cf + "grants: []\nGrants:\n  - members: [\"cfaccess/team:panda\"]\n    services: [all]\n",
			`keys "grants" and "Grants" at the top level are the same key`,
		},
		{
			"an empty grants key next to a filled one in another case",
			cf + "grants:\nGRANTS:\n  - members: [\"cfaccess/team:panda\"]\n    services: [all]\n",
			`keys "grants" and "GRANTS" at the top level are the same key`,
		},
		{
			"keys of a grants group",
			cf + "grants:\n  - members: [\"cfaccess/team:panda\"]\n    services: [all]\n    Services: []\n",
			`keys "services" and "Services" in grants[0] are the same key`,
		},
		{
			"an exact duplicate",
			cf + "grants:\n  - members: [\"cfaccess/team:panda\"]\n    services: [all]\n    services: []\n",
			`mapping key "services" already defined`,
		},
		{
			"rule map keys in a providers entry",
			oidcProvider + "      teamRules:\n        - claim: groups\n          map:\n            Staff: [panda]\n            staff: []\n",
			`keys "Staff" and "staff" in providers[0].oidc.teamRules[0].map are the same key`,
		},
		{
			"rule map keys in a legacy block",
			"authMode: any\nanyAuth:\n  teamRules:\n    - claim: username\n      map:\n        Alice: [panda]\n        ALICE: []\n",
			`keys "Alice" and "ALICE" in anyAuth.teamRules[0].map are the same key`,
		},
		{
			"a provider block written twice",
			"providers:\n  - name: anyauth\n    type: any\n    anyAuth:\n      teams: [dev]\n    AnyAuth:\n      teams: [panda]\n",
			`keys "anyAuth" and "AnyAuth" in providers[0] are the same key`,
		},
		{
			"a setting written twice",
			cf + "tokenTTL: 30m\nTokenTTL: 24h\n",
			`keys "tokenTTL" and "TokenTTL" at the top level are the same key`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// The outcome must not depend on map iteration: load it a
			// number of times.
			for range 20 {
				_, err := Load(writeTempConfig(t, teamsConfigHeader+tc.body))
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("load: got %v, want an error containing %q", err, tc.wantErr)
				}
			}
		})
	}
}

// TestLoad_MisspelledGrantsSection: a key that was meant to be the
// grants section but is not is an error — ignored, it would leave every
// service open. Other unknown top-level keys are a warning.
func TestLoad_MisspelledGrantsSection(t *testing.T) {
	cf := `
cloudflareAccess:
  teamDomain: "test.cloudflareaccess.com"
`
	entries := "  - members: [\"cfaccess/team:panda\"]\n    services: [all]\n"

	errors := []struct {
		name string
		body string
		want string
	}{
		{"singular", cf + "grant:\n" + entries, `unknown key "grant": it looks like the service grants section`},
		{"teamService", cf + "teamService:\n  panda: [all]\n", `unknown key "teamService": it looks like the service grants section`},
		{"team_services", cf + "team_services:\n  panda: [all]\n", `unknown key "team_services"`},
		{"team-services", cf + "team-services:\n  panda: [all]\n", `unknown key "team-services"`},
		{"serviceGrants", cf + "serviceGrants:\n" + entries, `unknown key "serviceGrants"`},
		{"service_grants", cf + "service_grants:\n" + entries, `unknown key "service_grants"`},
		{"teamGrants", cf + "teamGrants:\n" + entries, `unknown key "teamGrants"`},
		{"permissions", cf + "permissions:\n" + entries, `unknown key "permissions"`},
		{"grants with a typo", cf + "grnats_grants:\n" + entries, `unknown key "grnats_grants"`},
		{"nested under another key", cf + "cors:\n  grants:\n    - members: [\"cfaccess/team:panda\"]\n      services: [all]\n", `key "grants" in cors: the service grants section is the top-level key "grants"`},
		{"nested under a provider block", "cloudflareAccess:\n  teamDomain: \"test.cloudflareaccess.com\"\n  grants: []\n", `key "grants" in cloudflareAccess: the service grants section is the top-level key`},
		{"nested in a providers entry", "providers:\n  - name: anyauth\n    type: any\n    teamServices:\n      panda: [all]\n", `key "teamServices" in providers[0]`},
		{"nested under an unknown key", cf + "access:\n  grants: []\n", `key "grants" in access`},
	}
	for _, tc := range errors {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(writeTempConfig(t, teamsConfigHeader+tc.body))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("load: got %v, want an error containing %q", err, tc.want)
			}
		})
	}

	t.Run("data named like the section is fine", func(t *testing.T) {
		cfg, err := Load(writeTempConfig(t, teamsConfigHeader+`
authMode: any
anyAuth:
  teamRules:
    - claim: username
      map:
        grants: [grants]
        permissions: [ops]
grants:
  - name: grants
    members: ["anyauth/team:grants", "anyauth/user:grant", "anyauth/username:teamservices"]
    services: [all]
`))
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		if len(cfg.Warnings) != 0 {
			t.Errorf("warnings: %v", cfg.Warnings)
		}
	})

	t.Run("other unknown keys are a warning", func(t *testing.T) {
		cfg, err := Load(writeTempConfig(t, teamsConfigHeader+cf+"tokenTLL: 1h\nfoo: bar\n"))
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		if len(cfg.Warnings) != 1 || !strings.Contains(cfg.Warnings[0], `"tokenTLL"`) || !strings.Contains(cfg.Warnings[0], `"foo"`) {
			t.Errorf("warnings: %v", cfg.Warnings)
		}
	})
}

// TestLoad_KnownKeysDoNotWarn: every documented key — the example
// config, the local dev config, the legacy single-authMode form with
// all its blocks — loads without a warning, and settings that only
// come from the environment do not trip the check.
func TestLoad_KnownKeysDoNotWarn(t *testing.T) {
	for _, file := range []string{"../../config.example.yaml", "../../.hack/local/config.yaml"} {
		cfg, err := Load(file)
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		if len(cfg.Warnings) != 0 {
			t.Errorf("%s: warnings %v", file, cfg.Warnings)
		}
	}

	t.Setenv("AUTHENTICATOOR_LISTEN", ":9999")
	t.Setenv("AUTHENTICATOOR_METRICS_ENABLED", "true")
	t.Setenv("AUTHENTICATOOR_CLOUDFLAREACCESS_TEAMS", "panda")
	cfg, err := Load(writeTempConfig(t, `
listen: ":8080"
issuer: "https://auth.demo.example.com"
externalURL: "https://auth.demo.example.com"
authMode: [cloudflare, basic, any, github, oidc]
devMode: false
audience: [demo.example.com]
scopePattern: "*.demo.example.com"
tokenTTL: 30m
userHeader: "Cf-Access-Authenticated-User-Email"
allowedReturnHosts: ["*.demo.example.com"]
cloudflareAccess:
  teamDomain: "test.cloudflareaccess.com"
  audTag: "aud"
basicAuth:
  htpasswdFile: "/etc/htpasswd"
anyAuth: {}
githubOAuth:
  clientId: "id"
  clientSecret: "secret"
  allowedOrgs: [sigp]
oidc:
  issuerURL: "https://idp.example.com"
  callbackURL: "https://auth.demo.example.com/oidc/callback"
  clientId: "id"
  clientSecret: "secret"
  trustUnverifiedEmail: false
cors:
  allowedOrigins: ["*.demo.example.com"]
signing:
  mode: rs256
  rs256:
    privateKeyFile: "/etc/keys/private.pem"
logging:
  level: info
metrics:
  listen: ":9090"
grants: []
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.Warnings) != 0 {
		t.Errorf("warnings: %v", cfg.Warnings)
	}
	if cfg.Listen != ":9999" || !cfg.Metrics.Enabled {
		t.Errorf("env overrides lost: listen=%q metrics=%t", cfg.Listen, cfg.Metrics.Enabled)
	}
}

// TestLoad_UnknownKeysInProviderConfig: inside a providers entry, a
// provider type block (also in the legacy top-level form) and a team
// rule, an unknown key is a startup error that names the key and the
// allowed ones. The loader would otherwise drop it, and a dropped key
// there fails open.
func TestLoad_UnknownKeysInProviderConfig(t *testing.T) {
	oidcEntry := `
providers:
  - name: oidc
    type: oidc
    oidc:
      issuerURL: "https://idp.example.com"
      callbackURL: "https://auth.demo.example.com/oidc/callback"
      clientId: "id"
      clientSecret: "secret"
`
	rules := func(rule string) string { return oidcEntry + "      teamRules:\n        - " + rule + "\n" }

	tests := []struct {
		name    string
		body    string
		wantErr string
	}{
		// The reviewer's scenarios: a misspelled rule key used to load
		// as the bare-value rule — every group that is a valid team
		// name became that team.
		{"prefx instead of prefix", rules("claim: groups\n          prefx: \"team:\""), `providers[0].oidc.teamRules[0]: unknown key "prefx" (the keys here are: claim, map, prefix, regex, split, value)`},
		{"regexp instead of regex", rules("claim: groups\n          regexp: \"team:(.*)\""), `teamRules[0]: unknown key "regexp"`},
		{"maps instead of map", rules("claim: groups\n          maps: { staff: [panda] }"), `teamRules[0]: unknown key "maps"`},
		{"claims instead of claim", rules("claims: groups\n          prefix: \"team:\""), `teamRules[0]: unknown key "claims"`},
		{"the second rule", oidcEntry + "      teamRules:\n        - claim: groups\n          prefix: \"team:\"\n        - claim: email\n          mapping: { a: [b] }\n", `providers[0].oidc.teamRules[1]: unknown key "mapping"`},

		{"in a provider type block", oidcEntry + "      allowedGroup: [x]\n", `providers[0].oidc: unknown key "allowedGroup"`},
		{"the removed allowedTeams", oidcEntry + "      allowedTeams: [lighthouse]\n", `providers[0].oidc: unknown key "allowedTeams"`},
		{"the removed teamGroupPrefix", oidcEntry + "      teamGroupPrefix: \"team:\"\n", `providers[0].oidc: unknown key "teamGroupPrefix"`},
		{"in a providers entry", oidcEntry + "    teams: [panda]\n", `providers[0]: unknown key "teams" (the keys here are: anyAuth, basicAuth, cloudflareAccess, githubOAuth, name, oidc, type)`},
		{"the block of another type, misspelled", oidcEntry + "    cloudflare_access:\n      teams: [panda]\n", `providers[0]: unknown key "cloudflare_access"`},
		{"in a legacy top-level block", "cloudflareAccess:\n  teamDomain: \"t.example\"\n  audTag: \"aud\"\n  team: [panda]\n", `cloudflareAccess: unknown key "team"`},
		{"in a legacy block's rule", "authMode: any\nanyAuth:\n  teamRules:\n    - claim: username\n      prefx: \"team-\"\n", `anyAuth.teamRules[0]: unknown key "prefx"`},
		{"in a legacy block that is not the active type", "authMode: any\ngithubOAuth:\n  orgTeams:\n    sigp: [lighthouse]\n", `githubOAuth: unknown key "orgTeams"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(writeTempConfig(t, teamsConfigHeader+tc.body))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("load: got %v, want an error containing %q", err, tc.wantErr)
			}
		})
	}

	t.Run("keys in any case are the known keys", func(t *testing.T) {
		_, err := Load(writeTempConfig(t, teamsConfigHeader+`
providers:
  - Name: oidc
    Type: oidc
    OIDC:
      IssuerURL: "https://idp.example.com"
      callbackurl: "https://auth.demo.example.com/oidc/callback"
      ClientID: "id"
      clientSecret: "secret"
      TeamRules:
        - Claim: groups
          Prefix: "team:"
`))
		if err != nil {
			t.Fatalf("load: %v", err)
		}
	})
}

// TestLoad_EmptyRuleKeys: a rule key that is written down but empty is
// an error, never "not set" — and a rule has to say what it does: with
// none of prefix / map / regex / value it is an error, not the rule
// that takes every value as a team.
func TestLoad_EmptyRuleKeys(t *testing.T) {
	rule := func(body string) string {
		return "authMode: any\nanyAuth:\n  teamRules:\n    - " + body + "\n"
	}
	tests := []struct {
		name    string
		body    string
		wantErr string
	}{
		{"prefix: \"\"", rule("claim: username\n      prefix: \"\""), "anyAuth.teamRules[0].prefix: is empty"},
		{"prefix: (null)", rule("claim: username\n      prefix:"), "anyAuth.teamRules[0].prefix: is empty"},
		{"map: {}", rule("claim: username\n      map: {}"), "anyAuth.teamRules[0].map: is empty"},
		{"map: (null)", rule("claim: username\n      map:"), "anyAuth.teamRules[0].map: is empty"},
		{"regex: \"\"", rule("claim: username\n      regex: \"\""), "anyAuth.teamRules[0].regex: is empty"},
		{"split: \"\"", rule("claim: username\n      split: \"\"\n      value: true"), "anyAuth.teamRules[0].split: is empty"},
		{"claim: \"\"", rule("claim: \"\"\n      value: true"), "anyAuth.teamRules[0].claim: is empty"},
		{"claim: (null)", rule("claim:\n      value: true"), "anyAuth.teamRules[0].claim: is empty"},
		{"value: false", rule("claim: username\n      value: false"), "anyAuth.teamRules[0].value: must be true"},
		{"value: (null)", rule("claim: username\n      value:"), "anyAuth.teamRules[0].value: must be true"},
		{"value: yes-as-text", rule("claim: username\n      value: \"true\""), "anyAuth.teamRules[0].value: must be true"},
		{"no form at all", rule("claim: username"), `anyAuth.teamRules[0]: claim "username": one of prefix, map, regex or "value: true" is required`},
		{"only split", rule("claim: username\n      split: \",\""), `one of prefix, map, regex or "value: true" is required`},
		{"value next to a prefix", rule("claim: username\n      prefix: \"team-\"\n      value: true"), "only one of prefix, map, regex and value may be set"},
		{"a rule that is not a map", "authMode: any\nanyAuth:\n  teamRules:\n    - username\n", "teamRules[0]"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(writeTempConfig(t, teamsConfigHeader+tc.body))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("load: got %v, want an error containing %q", err, tc.wantErr)
			}
		})
	}

	// The explicit form works, in both config shapes.
	cfg, err := Load(writeTempConfig(t, teamsConfigHeader+rule("claim: username\n      value: true")))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if r := cfg.Providers[0].AnyAuth.TeamRules[0]; r.Claim != "username" || !r.Value {
		t.Errorf("rule: %+v", r)
	}
}

// TestLoad_MapWhereAListBelongs: the loader turns a single map into a
// list of one (and a list of maps into one map) without a word. The
// checks that walk the document would not see such an entry, so a rule
// with a misspelled or empty key would load. Both are startup errors,
// in the providers form and in the legacy top-level form.
func TestLoad_MapWhereAListBelongs(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			"legacy block: teamRules is one rule instead of a list",
			"authMode: any\nanyAuth:\n  teamRules:\n    claim: username\n    prefx: \"team-\"\n    value: true\n",
			`anyAuth.teamRules: must be a list`,
		},
		{
			"legacy block: the single rule has an empty key",
			"authMode: any\nanyAuth:\n  teamRules:\n    claim: username\n    prefix: \"\"\n    value: true\n",
			`anyAuth.teamRules: must be a list`,
		},
		{
			"providers entry: teamRules is one rule instead of a list",
			"providers:\n  - name: dev\n    type: any\n    anyAuth:\n      teamRules:\n        claim: username\n        prefx: \"team-\"\n        value: true\n",
			`providers[0].anyAuth.teamRules: must be a list`,
		},
		{
			"providers is one entry instead of a list",
			"providers:\n  name: dev\n  type: any\n  anyAuth:\n    bogus: true\n    teams: [panda]\n",
			`providers: must be a list`,
		},
		{
			"teamRules is a single value",
			"authMode: any\nanyAuth:\n  teamRules: username\n",
			`anyAuth`,
		},
		{
			"a type block is a list of maps",
			"authMode: any\nanyAuth:\n  - teams: [panda]\n  - bogus: true\n",
			`'anyAuth' expected a map`,
		},
		{
			"a type block in a providers entry is a list of maps",
			"providers:\n  - name: dev\n    type: any\n    anyAuth:\n      - teams: [panda]\n      - bogus: true\n",
			`'providers[0].anyAuth' expected a map`,
		},
		{
			"a providers entry is a list",
			"providers:\n  - - name: dev\n      type: any\n",
			`providers[0]`,
		},
		{
			"grants is one group instead of a list",
			"authMode: any\ngrants:\n  members: [\"anyauth/team:panda\"]\n  services: [all]\n",
			`grants: must be a list of groups`,
		},
		{
			"members is a single value",
			"authMode: any\ngrants:\n  - members: \"anyauth/team:panda\"\n    services: [all]\n",
			`grants[0].members: must be a list`,
		},
		{
			"members is a map",
			"authMode: any\ngrants:\n  - members: {\"anyauth/team:panda\": true}\n    services: [all]\n",
			`grants[0].members: must be a list`,
		},
		{
			"services is a map",
			"authMode: any\ngrants:\n  - members: [\"anyauth/team:panda\"]\n    services: {all: true}\n",
			`grants[0].services: must be a list`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			wantLoadError(t, writeTempConfig(t, teamsConfigHeader+tc.body), tc.want)
		})
	}

	// A key without a value is an empty list, as it always was: a block
	// whose entries are all commented out must still load.
	cfg, err := Load(writeTempConfig(t, teamsConfigHeader+"authMode: any\nproviders:\nanyAuth:\n  teamRules:\n  teams:\n"))
	if err != nil {
		t.Fatalf("empty lists: %v", err)
	}
	if len(cfg.Providers) != 1 || cfg.Providers[0].ProducesTeams() {
		t.Errorf("empty lists: providers %+v", cfg.Providers)
	}
}

// TestLoad_DeprecatedKeys: a key that a released version documented or
// read, and that means nothing any more, is reported in a deprecation
// warning — it must not stop a config that started before. A key that
// was never valid stays an error, in a used block and in an unused one.
func TestLoad_DeprecatedKeys(t *testing.T) {
	warned := []struct {
		name string
		body string
		want []string
	}{
		{
			"anyAuth.loginPath",
			"authMode: any\nanyAuth:\n  loginPath: \"/auth/anyauth/login\"\n",
			[]string{"anyAuth.loginPath is deprecated and ignored"},
		},
		{
			"githubOAuth.sessionSecret and sessionSecretFile",
			"authMode: github\ngithubOAuth:\n  clientId: id\n  clientSecret: s\n  allowedOrgs: [sigp]\n" +
				"  sessionSecret: \"hunter2\"\n  sessionSecretFile: /etc/gh-session\n",
			[]string{
				"githubOAuth.sessionSecret is deprecated and ignored",
				"githubOAuth.sessionSecretFile is deprecated and ignored",
			},
		},
		{
			"in another case",
			"authMode: any\nanyAuth:\n  LOGINPATH: \"/auth/anyauth/login\"\n",
			[]string{"anyAuth.LOGINPATH is deprecated and ignored"},
		},
		{
			"in an unused legacy block",
			"authMode: any\ngithubOAuth:\n  sessionSecretFile: /etc/gh-session\n",
			[]string{"githubOAuth.sessionSecretFile is deprecated and ignored"},
		},
		{
			"in a providers entry",
			"providers:\n  - name: dev\n    type: any\n    anyAuth:\n      loginPath: /dev/login\n",
			[]string{"providers[0].anyAuth.loginPath is deprecated and ignored"},
		},
	}
	for _, tc := range warned {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Load(writeTempConfig(t, teamsConfigHeader+tc.body))
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			if len(cfg.DeprecationWarnings) != len(tc.want) {
				t.Fatalf("deprecation warnings: %v, want %d", cfg.DeprecationWarnings, len(tc.want))
			}
			for i, want := range tc.want {
				if !strings.Contains(cfg.DeprecationWarnings[i], want) {
					t.Errorf("warning %d: %q, want it to contain %q", i, cfg.DeprecationWarnings[i], want)
				}
				// A warning names the key, never its value.
				if strings.Contains(cfg.DeprecationWarnings[i], "hunter2") {
					t.Errorf("warning %d leaks the value: %q", i, cfg.DeprecationWarnings[i])
				}
			}
		})
	}

	stillErrors := []struct {
		name string
		body string
		want string
	}{
		{
			"a deprecated key is only known where it was valid",
			"authMode: any\nanyAuth:\n  sessionSecret: x\n",
			`anyAuth: unknown key "sessionSecret"`,
		},
		{
			"a key that was never valid",
			"authMode: any\nanyAuth:\n  loginPth: /x\n",
			`anyAuth: unknown key "loginPth"`,
		},
		{
			"a key that was never valid, in an unused legacy block",
			"authMode: any\noidc:\n  sessionSecret: x\n",
			`oidc: unknown key "sessionSecret"`,
		},
	}
	for _, tc := range stillErrors {
		t.Run(tc.name, func(t *testing.T) {
			wantLoadError(t, writeTempConfig(t, teamsConfigHeader+tc.body), tc.want)
		})
	}
}

// TestLoad_MisspelledGrants: an unknown top-level key within two edits
// of "grants" is an error — it was meant to be the section, and
// ignoring it would leave every service open. Other unknown top-level
// keys stay a warning: released versions ignored them.
func TestLoad_MisspelledGrants(t *testing.T) {
	const cf = "cloudflareAccess:\n  verifyJWT: false\n"
	for _, key := range []string{
		"garnts", "grnts", "grantts", "GARNTS", "gra_nts", "grnt",
	} {
		t.Run(key, func(t *testing.T) {
			wantLoadError(t, writeTempConfig(t, teamsConfigHeader+cf+key+": []\n"),
				`unknown key "`+key+`": it looks like the service grants section`)
		})
	}

	for _, key := range []string{"tokenTLL", "x-anchors", "garden", "tenants"} {
		t.Run("only a warning: "+key, func(t *testing.T) {
			cfg, err := Load(writeTempConfig(t, teamsConfigHeader+cf+key+": []\n"))
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			if len(cfg.Warnings) != 1 || !strings.Contains(cfg.Warnings[0], `"`+key+`"`) {
				t.Errorf("warnings: %v", cfg.Warnings)
			}
		})
	}

	// No key the config knows is itself taken for a misspelling.
	var walk func(reflect.Type)
	walk = func(typ reflect.Type) {
		for i := range typ.NumField() {
			field := typ.Field(i)
			if tag := field.Tag.Get("mapstructure"); tag != "" && tag != "-" {
				if misspelledGrants(tag) || looksLikeGrantsSection(tag) {
					t.Errorf("the known key %q would be taken for the grants section", tag)
				}
			}
			ft := field.Type
			if ft.Kind() == reflect.Slice || ft.Kind() == reflect.Pointer {
				ft = ft.Elem()
			}
			if ft.Kind() == reflect.Struct && ft.PkgPath() != "time" {
				walk(ft)
			}
		}
	}
	walk(reflect.TypeOf(Config{}))
	walk(reflect.TypeOf(protection.TeamRule{}))
}
