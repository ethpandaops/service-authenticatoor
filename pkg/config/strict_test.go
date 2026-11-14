package config

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/ethpandaops/service-authenticatoor/pkg/protection"
)

// writeConfigFile writes a config file with the given name (and thereby
// format) and returns its path.
func writeConfigFile(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

// wantLoadError loads a config and requires an error containing want.
func wantLoadError(t *testing.T, path, want string) {
	t.Helper()
	cfg, err := Load(path)
	if err == nil {
		t.Fatalf("load: no error, want one containing %q (providers: %+v)", want, cfg.Providers)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("load: got %v, want an error containing %q", err, want)
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

// TestLoad_MergeKeys: the loader resolves YAML merge keys ("<<"). The
// checks on the document see the merged result too, so nothing pulled
// in through an anchor escapes them — and a config that uses anchors
// for ordinary settings keeps loading.
func TestLoad_MergeKeys(t *testing.T) {
	errorCases := []struct {
		name string
		body string
		want string
	}{
		{
			"an unknown key merged into a provider block",
			"x-base: &base\n  teamz: [panda]\nauthMode: any\nanyAuth:\n  <<: *base\n",
			`anyAuth: unknown key "teamz"`,
		},
		{
			"an unknown key merged into a team rule",
			"x-rule: &rule\n  claim: username\n  prefx: \"team-\"\n  value: true\nauthMode: any\nanyAuth:\n  teamRules:\n    - <<: *rule\n",
			`anyAuth.teamRules[0]: unknown key "prefx"`,
		},
		{
			"an empty rule key merged into a team rule",
			"x-rule: &rule\n  prefix: \"\"\nauthMode: any\nanyAuth:\n  teamRules:\n    - <<: *rule\n      claim: username\n      value: true\n",
			`anyAuth.teamRules[0].prefix: is empty`,
		},
		{
			"an unknown key merged into a providers entry",
			"x-entry: &entry\n  type: any\n  anyAuth:\n    bogus: 1\nproviders:\n  - <<: *entry\n    name: dev\n",
			`providers[0].anyAuth: unknown key "bogus"`,
		},
		{
			"a list of merged maps",
			"x-a: &a\n  cookieName: c\nx-b: &b\n  teamz: [panda]\nauthMode: any\nanyAuth:\n  <<: [*a, *b]\n",
			`anyAuth: unknown key "teamz"`,
		},
		{
			"a misspelled grants section merged into the top level",
			"x-base: &base\n  garnts: []\n<<: *base\nauthMode: any\n",
			`unknown key "garnts"`,
		},
		{
			"an unknown key merged into a grants group",
			"x-group: &group\n  services: [all]\n  member: [\"anyauth/team:panda\"]\nauthMode: any\ngrants:\n  - <<: *group\n    members: [\"anyauth/team:panda\"]\n",
			`grants[0]: unknown key "member"`,
		},
		{
			"case-variant keys, one of them merged",
			"x-base: &base\n  Teams: [panda]\nauthMode: any\nanyAuth:\n  <<: *base\n  teams: [geth]\n",
			`are the same key`,
		},
	}
	for _, tc := range errorCases {
		t.Run(tc.name, func(t *testing.T) {
			wantLoadError(t, writeTempConfig(t, teamsConfigHeader+tc.body), tc.want)
		})
	}

	t.Run("merged content is read like written content", func(t *testing.T) {
		cfg, err := Load(writeTempConfig(t, teamsConfigHeader+`
x-rules: &rules
  teamRules:
    - claim: username
      map:
        Alice.Smith: [panda]
x-group: &group
  members: ["anyauth/team:panda"]
  services: [spamoor]
x-anchored: &level
  level: debug
x-top: &top
  authMode: any
<<: *top
grants:
  - <<: *group
    name: staff
anyAuth:
  <<: *rules
  teams: [geth]
logging:
  <<: *level
  format: json
`))
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		any := cfg.Providers[0].AnyAuth
		// The key of the rule map is data: it keeps its capitals and its
		// dot, also when the rule came in through a merge.
		if len(any.TeamRules) != 1 || !slices.Equal(any.TeamRules[0].Map["Alice.Smith"], []string{"panda"}) {
			t.Errorf("merged rule map: %+v", any.TeamRules)
		}
		if !slices.Equal(any.Teams, []string{"geth"}) {
			t.Errorf("teams: %v", any.Teams)
		}
		if cfg.Grants == nil || len(cfg.Grants.Groups) != 1 || cfg.Grants.Groups[0].Name != "staff" ||
			!slices.Equal(cfg.Grants.Groups[0].Members, []string{"anyauth/team:panda"}) ||
			!slices.Equal(cfg.Grants.Groups[0].Services, []string{"spamoor"}) {
			t.Errorf("merged grants: %+v", cfg.Grants)
		}
		if cfg.Logging.Level != "debug" || cfg.Logging.Format != "json" {
			t.Errorf("logging: %+v", cfg.Logging)
		}
	})

	t.Run("a written key wins over a merged one", func(t *testing.T) {
		cfg, err := Load(writeTempConfig(t, teamsConfigHeader+
			"x-a: &a\n  teams: [panda]\n  cookieName: from-a\nx-b: &b\n  cookieName: from-b\n"+
			"authMode: any\nanyAuth:\n  <<: [*b, *a]\n  teams: [geth]\n"))
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		// The loader and the document reader have to agree, or the
		// checks would look at something else than what is loaded.
		any := cfg.Providers[0].AnyAuth
		if !slices.Equal(any.Teams, []string{"geth"}) || any.CookieName != "from-b" {
			t.Errorf("loader: teams %v cookieName %q", any.Teams, any.CookieName)
		}
		root, unchecked, err := loadRawDocument(writeTempConfig(t, "x-a: &a\n  teams: [panda]\n  cookieName: from-a\n"+
			"x-b: &b\n  cookieName: from-b\nanyAuth:\n  <<: [*b, *a]\n  teams: [geth]\n"))
		if err != nil || unchecked != "" {
			t.Fatalf("raw: %v %q", err, unchecked)
		}
		block := rawChild(root, "anyAuth")
		if got := rawChild(block, "cookieName"); got == nil || got.Value != "from-b" {
			t.Errorf("document: cookieName %+v", got)
		}
		if got := rawItems(rawChild(block, "teams")); len(got) != 1 || got[0].Value != "geth" {
			t.Errorf("document: teams %+v", got)
		}
		if rawChild(block, "<<") != nil {
			t.Error("document: the merge key is still there")
		}
	})
}

// minimalTOML and minimalJSON are the same legacy config in two other
// formats viper reads.
const (
	minimalTOML = `
issuer = "https://auth.demo.example.com"
authMode = "any"

[signing.rs256]
privateKeyFile = "/etc/keys/private.pem"
`
	minimalJSON = `{
	"issuer": "https://auth.demo.example.com",
	"authMode": "any",
	"signing": {"rs256": {"privateKeyFile": "/etc/keys/private.pem"}}`
)

// TestLoad_FileThatCannotBeChecked: the strict checks read the config
// file as YAML. A file in another format is loaded by viper all the
// same; then none of the checks can run. Such a file is accepted — with
// a warning — as long as it configures nothing those checks protect,
// and refused as soon as teams, team rules or grants come into play,
// from the file or from the environment.
func TestLoad_FileThatCannotBeChecked(t *testing.T) {
	t.Run("a plain TOML config loads with a warning", func(t *testing.T) {
		cfg, err := Load(writeConfigFile(t, "config.toml", minimalTOML))
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		if len(cfg.Warnings) != 1 || !strings.Contains(cfg.Warnings[0], "strict checks") ||
			!strings.Contains(cfg.Warnings[0], "not a YAML or JSON file") {
			t.Errorf("warnings: %v", cfg.Warnings)
		}
		if got := cfg.ProviderNames(); !slices.Equal(got, []string{"anyauth"}) {
			t.Errorf("providers: %v", got)
		}
	})

	refused := []struct {
		name string
		body string
		env  [2]string
		want string
	}{
		{"teams in the file", minimalTOML + "\n[anyAuth]\nteams = [\"panda\"]\n", [2]string{}, "anyAuth.teams is configured"},
		{
			"team rules in the file",
			minimalTOML + "\n[[anyAuth.teamRules]]\nclaim = \"username\"\nprefx = \"team-\"\nvalue = true\n",
			[2]string{}, "anyAuth.teamRules is configured",
		},
		{
			"teams in a providers entry",
			"issuer = \"https://auth.demo.example.com\"\n[signing.rs256]\nprivateKeyFile = \"/k.pem\"\n" +
				"[[providers]]\nname = \"dev\"\ntype = \"any\"\n[providers.anyAuth]\nteams = [\"panda\"]\n",
			[2]string{}, "anyAuth.teams is configured",
		},
		{
			"teams of an unused block",
			minimalTOML + "\n[oidc]\nteams = [\"panda\"]\n", [2]string{}, "oidc.teams is configured",
		},
		{"grants in the file", "grants = []\n" + minimalTOML, [2]string{}, "grants is configured"},
		{
			"a misspelled grants section cannot be told from an unknown key, but grants can",
			"teamServices = []\n" + minimalTOML, [2]string{}, "grants is configured",
		},
		{
			"teams from the environment",
			minimalTOML, [2]string{"AUTHENTICATOOR_ANYAUTH_TEAMS", "panda"}, "anyAuth.teams is configured",
		},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			if tc.env[0] != "" {
				t.Setenv(tc.env[0], tc.env[1])
			}
			wantLoadError(t, writeConfigFile(t, "config.toml", tc.body), tc.want)
			wantLoadError(t, writeConfigFile(t, "config.toml", tc.body), "strict checks of the config file cannot run")
		})
	}

	t.Run("JSON is checked like YAML", func(t *testing.T) {
		cfg, err := Load(writeConfigFile(t, "config.json", minimalJSON+`,
	"anyAuth": {
		"teams": ["geth"],
		"teamRules": [{"claim": "username", "map": {"Alice.Smith": ["panda"]}}]
	},
	"grants": [{"name": "staff", "members": ["anyauth/team:panda"], "services": ["all:all"]}]
}`))
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		if len(cfg.Warnings) != 0 {
			t.Errorf("warnings: %v", cfg.Warnings)
		}
		any := cfg.Providers[0].AnyAuth
		if !slices.Equal(any.Teams, []string{"geth"}) || len(any.TeamRules) != 1 ||
			!slices.Equal(any.TeamRules[0].Map["Alice.Smith"], []string{"panda"}) {
			t.Errorf("anyAuth: %+v", any)
		}
		if cfg.Grants == nil || len(cfg.Grants.Groups) != 1 || cfg.Grants.Groups[0].Name != "staff" {
			t.Errorf("grants: %+v", cfg.Grants)
		}

		// And the checks do run on it.
		wantLoadError(t, writeConfigFile(t, "config.json",
			minimalJSON+`, "anyAuth": {"teamz": ["panda"]}}`), `anyAuth: unknown key "teamz"`)
		wantLoadError(t, writeConfigFile(t, "config.json",
			minimalJSON+`, "anyAuth": {"teamRules": {"claim": "username", "value": true}}}`),
			`anyAuth.teamRules: must be a list`)
		wantLoadError(t, writeConfigFile(t, "config.json", minimalJSON+`, "garnts": []}`), `unknown key "garnts"`)
	})

	t.Run("no file and an empty file have nothing to check", func(t *testing.T) {
		t.Setenv("AUTHENTICATOOR_ISSUER", "https://auth.demo.example.com")
		t.Setenv("AUTHENTICATOOR_SIGNING_RS256_PRIVATEKEYFILE", "/etc/keys/private.pem")
		t.Setenv("AUTHENTICATOOR_AUTHMODE", "any")
		t.Setenv("AUTHENTICATOOR_ANYAUTH_TEAMS", "panda")
		for _, path := range []string{"", writeTempConfig(t, ""), writeTempConfig(t, "# nothing\n")} {
			cfg, err := Load(path)
			if err != nil {
				t.Fatalf("load %q: %v", path, err)
			}
			if len(cfg.Warnings) != 0 || !slices.Equal(cfg.Providers[0].AnyAuth.Teams, []string{"panda"}) {
				t.Errorf("load %q: warnings %v, teams %v", path, cfg.Warnings, cfg.Providers[0].AnyAuth.Teams)
			}
		}
	})
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
		"garnts", "grnats", "gratns", "rgants", "grnts", "gants", "grats", "rants", "grabts",
		"grantts", "ggrants", "GARNTS", "Garnts", "gra_nts", "g-rants", "grans", "grnt", "grannts",
	} {
		t.Run(key, func(t *testing.T) {
			wantLoadError(t, writeTempConfig(t, teamsConfigHeader+cf+key+": []\n"),
				`unknown key "`+key+`": it looks like the service grants section`)
		})
	}

	for _, key := range []string{"tokenTLL", "foo", "x-anchors", "garden", "access", "acl", "gr", "tenants"} {
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

func TestEditDistance(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"grants", "grants", 0},
		{"garnts", "grants", 1}, // one swap
		{"grnats", "grants", 1},
		{"grnts", "grants", 1},
		{"grantss", "grants", 1},
		{"grabts", "grants", 1},
		{"rgnats", "grants", 2}, // two swaps
		{"", "grants", 6},
		{"grants", "", 6},
		{"tenants", "grants", 3},
		{"ca", "abc", 3}, // optimal string alignment, not unrestricted Damerau
	}
	for _, tc := range tests {
		if got := editDistance(tc.a, tc.b); got != tc.want {
			t.Errorf("editDistance(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

// TestLoad_CloudflareMembersThatCanNeverMatch: for a cloudflare
// provider the attributes depend on its configuration. A member naming
// something no identity of that provider can have is a startup error —
// a group that silently never applies is not what its author meant.
func TestLoad_CloudflareMembersThatCanNeverMatch(t *testing.T) {
	const (
		verified   = "cloudflareAccess:\n  teamDomain: t.cloudflareaccess.com\n  audTag: aud\n"
		noServices = verified + "  allowServiceTokens: false\n"
		unverified = "cloudflareAccess:\n  verifyJWT: false\n"
	)
	group := func(member string) string {
		return "grants:\n  - members: [\"" + member + "\"]\n    services: [all]\n"
	}
	tests := []struct {
		name    string
		block   string
		member  string
		wantErr string // "": loads
	}{
		{"verified: country", verified, "cfaccess/country:de", ""},
		{"verified: common_name", verified, "cfaccess/common_name:abc.access", ""},
		{"verified: principal service", verified, "cfaccess/principal:service", ""},
		{"verified: principal user", verified, "cfaccess/principal:User", ""},
		{"verified: a custom claim", verified, "cfaccess/custom.department:eng", ""},
		{"verified: a nested custom claim", verified, "cfaccess/custom.org.unit:eng", ""},
		{"verified: email", verified, "cfaccess/email:alice@example.org", ""},
		{"verified: custom without a name", verified, "cfaccess/custom.:x", `"custom." names no claim`},
		{"verified: custom with an empty segment", verified, "cfaccess/custom..a:x", `names no claim`},
		{"verified: custom itself", verified, "cfaccess/custom:x", `has no attribute "custom"`},
		{"verified: a principal that does not exist", verified, "cfaccess/principal:admin", `principal is "user" or "service", never "admin"`},
		{"verified: an unknown claim", verified, "cfaccess/groups:staff", `has no attribute "groups"`},

		{"no service tokens: principal service", noServices, "cfaccess/principal:service", `principal is never "service"`},
		{"no service tokens: common_name", noServices, "cfaccess/common_name:abc.access", `only service tokens have a common_name`},
		{"no service tokens: country", noServices, "cfaccess/country:de", ""},

		{"unverified: email", unverified, "cfaccess/email:alice@example.org", ""},
		{"unverified: principal user", unverified, "cfaccess/principal:user", ""},
		{"unverified: country", unverified, "cfaccess/country:de", `with verifyJWT off a cloudflare provider has no attribute "country"`},
		{"unverified: common_name", unverified, "cfaccess/common_name:x", `with verifyJWT off a cloudflare provider has no attribute "common_name"`},
		{"unverified: principal service", unverified, "cfaccess/principal:service", `principal is never "service"`},
		{"unverified: a custom claim", unverified, "cfaccess/custom.department:eng", `with verifyJWT off`},
		{"unverified: sub", unverified, "cfaccess/sub:abc", `with verifyJWT off`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTempConfig(t, teamsConfigHeader+tc.block+group(tc.member))
			if tc.wantErr != "" {
				wantLoadError(t, path, tc.wantErr)
				wantLoadError(t, path, "this member can never match at the provider \"cfaccess\"")
				return
			}
			if _, err := Load(path); err != nil {
				t.Fatalf("load: %v", err)
			}
		})
	}

	// The same in a providers entry: the check follows the entry's own
	// settings, not the legacy block's.
	wantLoadError(t, writeTempConfig(t, teamsConfigHeader+
		"providers:\n  - name: edge\n    type: cloudflare\n    cloudflareAccess:\n      verifyJWT: false\n"+
		"grants:\n  - members: [\"edge/country:de\"]\n    services: [all]\n"), "with verifyJWT off")
}

// TestLoad_UnverifiedEmailWarning: every oidc provider that does not
// say what to do with an unverified email gets one startup warning that
// explains the rule. Saying it — either way — silences the warning.
func TestLoad_UnverifiedEmailWarning(t *testing.T) {
	entry := func(name, extra string) string {
		return "  - name: " + name + "\n    type: oidc\n    oidc:\n      issuerURL: https://idp.example.com\n" +
			"      callbackURL: https://auth.demo.example.com/" + name + "/callback\n      clientId: id\n" +
			"      clientSecret: s\n" + extra
	}
	cfg, err := Load(writeTempConfig(t, teamsConfigHeader+"providers:\n"+
		entry("unset", "")+
		entry("off", "      trustUnverifiedEmail: false\n")+
		entry("on", "      trustUnverifiedEmail: true\n")+
		entry("unset2", "")+
		"  - name: dev\n    type: any\n"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.Warnings) != 2 {
		t.Fatalf("warnings: %v", cfg.Warnings)
	}
	for i, name := range []string{"unset", "unset2"} {
		w := cfg.Warnings[i]
		for _, part := range []string{
			`provider "` + name + `"`, "oidc.trustUnverifiedEmail is not set", "email_verified: true",
			`the IdP's "sub"`, "alternates", "Upgrading",
		} {
			if !strings.Contains(w, part) {
				t.Errorf("warning %d lacks %q: %s", i, part, w)
			}
		}
	}
	trust := map[string]bool{}
	for _, p := range cfg.Providers {
		trust[p.Name] = p.OIDC.TrustsUnverifiedEmail()
	}
	if trust["unset"] || trust["off"] || !trust["on"] {
		t.Errorf("effective settings: %v", trust)
	}

	// The legacy block is warned about only when it is the provider.
	legacy := "oidc:\n  issuerURL: https://idp.example.com\n  callbackURL: https://auth.demo.example.com/cb\n" +
		"  clientId: id\n  clientSecret: s\n"
	cfg, err = Load(writeTempConfig(t, teamsConfigHeader+"authMode: oidc\n"+legacy))
	if err != nil || len(cfg.Warnings) != 1 || !strings.Contains(cfg.Warnings[0], `provider "oidc"`) {
		t.Errorf("legacy oidc: %v %v", err, cfg.Warnings)
	}
	cfg, err = Load(writeTempConfig(t, teamsConfigHeader+"authMode: any\n"+legacy))
	if err != nil || len(cfg.Warnings) != 0 {
		t.Errorf("unused legacy oidc block: %v %v", err, cfg.Warnings)
	}
}

// docEnvRow matches a row of the env var table in docs/config.md.
var docEnvRow = regexp.MustCompile("(?m)^\\| `([A-Za-z0-9.]+)` +\\| `(AUTHENTICATOOR_[A-Z0-9_]+)` +\\|")

// docFieldRow matches the first cell of a row of the reference table.
var docFieldRow = regexp.MustCompile("(?m)^\\| `([A-Za-z0-9.\\[\\]]+)` +\\| ")

// envSample returns a value to set a config path to through the
// environment, and what the loaded field has to hold then.
func envSample(path string, kind reflect.Type) (env string, want any) {
	special := map[string][2]any{
		"issuer":       {"https://auth.env.example.org", "https://auth.env.example.org"},
		"signing.mode": {"rs256", "rs256"},
		"tokenTTL":     {"17m", 17 * 60 * 1e9},
	}
	if s, ok := special[path]; ok {
		return s[0].(string), s[1]
	}
	switch {
	case kind.Kind() == reflect.Pointer && kind.Elem().Kind() == reflect.Bool:
		// false is the value that differs from every default of a *bool
		// here except trustUnverifiedEmail, which is handled by the
		// caller comparing against "not nil".
		return "false", false
	case kind.Kind() == reflect.Bool:
		return "true", true
	case kind.String() == "time.Duration":
		return "17m", 17 * 60 * 1e9
	case kind.Kind() == reflect.Slice:
		return "env-a,env-b", []string{"env-a", "env-b"}
	default:
		return "env-value", "env-value"
	}
}

// lookupField finds the field of a loaded config that a dotted config
// path names, by the mapstructure tags.
func lookupField(t *testing.T, cfg *Config, path string) reflect.Value {
	t.Helper()
	v := reflect.ValueOf(cfg).Elem()
	for _, part := range strings.Split(path, ".") {
		found := false
		for i := range v.NumField() {
			if strings.EqualFold(v.Type().Field(i).Tag.Get("mapstructure"), part) {
				v, found = v.Field(i), true
				break
			}
		}
		if !found {
			t.Fatalf("config path %q: no field for %q", path, part)
		}
	}
	return v
}

// TestLoad_DocumentedEnvVars walks docs/config.md: every env var of its
// example table, and the env var of every setting of the reference
// table that has a fixed path, is honoured when the config file does
// not mention the key at all.
func TestLoad_DocumentedEnvVars(t *testing.T) {
	doc, err := os.ReadFile("../../docs/config.md")
	if err != nil {
		t.Fatalf("read docs: %v", err)
	}

	paths := make(map[string]string, 64) // config path → env var
	for _, m := range docEnvRow.FindAllStringSubmatch(string(doc), -1) {
		path, env := m[1], m[2]
		if want := "AUTHENTICATOOR_" + strings.ToUpper(strings.ReplaceAll(path, ".", "_")); env != want {
			t.Errorf("docs: %s is listed with %s, the loader reads %s", path, env, want)
		}
		paths[path] = env
	}
	if len(paths) < 5 {
		t.Fatalf("found only %d rows in the env var table of docs/config.md", len(paths))
	}
	_, reference, found := strings.Cut(string(doc), "## Full reference")
	if !found {
		t.Fatal("docs/config.md has no \"Full reference\" section")
	}
	reference, _, _ = strings.Cut(reference, "\n## ")
	fileOnly := 0
	for _, m := range docFieldRow.FindAllStringSubmatch(reference, -1) {
		path := m[1]
		// Lists of structured entries and the grants section are read
		// from the file only, and the docs say so.
		if strings.Contains(path, "[]") || path == "providers" || path == "grants" || strings.HasSuffix(path, ".teamRules") {
			fileOnly++
			continue
		}
		paths[path] = "AUTHENTICATOOR_" + strings.ToUpper(strings.ReplaceAll(path, ".", "_"))
	}
	if len(paths) < 50 || fileOnly < 8 {
		t.Fatalf("the reference table yielded %d settings and %d file-only rows", len(paths), fileOnly)
	}

	// Every setting the loader binds is documented, and the other way
	// round.
	bound := envKeys(reflect.TypeOf(Config{}), "")
	for _, key := range bound {
		if _, ok := paths[key]; !ok {
			t.Errorf("%s can be set through the environment but is not in the reference table", key)
		}
	}
	for path := range paths {
		if !slices.Contains(bound, path) {
			t.Errorf("%s is documented but not bound to its env var", path)
		}
	}

	// A file that mentions none of the keys under test, and is valid
	// whatever one of them is set to.
	const base = "issuer: \"https://auth.demo.example.com\"\n"
	for path, env := range paths {
		t.Run(env, func(t *testing.T) {
			// What makes the config valid, set through the environment
			// too, so the file stays free of every key.
			t.Setenv("AUTHENTICATOOR_SIGNING_RS256_PRIVATEKEYFILE", "/etc/keys/private.pem")
			t.Setenv("AUTHENTICATOOR_CLOUDFLAREACCESS_VERIFYJWT", "false")

			probe := lookupField(t, &Config{}, path)
			value, want := envSample(path, probe.Type())
			if path == "authMode" {
				value, want = "any", []string{"anyauth"}
			}
			t.Setenv(env, value)

			cfg, err := Load(writeTempConfig(t, base))
			if err != nil {
				t.Fatalf("load with %s=%s: %v", env, value, err)
			}
			got := lookupField(t, cfg, path)
			if got.Kind() == reflect.Pointer {
				if got.IsNil() {
					t.Fatalf("%s=%s was ignored: %s is unset", env, value, path)
				}
				got = got.Elem()
			}
			var have any
			switch got.Kind() {
			case reflect.Int64:
				have = float64(got.Int())
			case reflect.Slice:
				have = got.Interface()
			default:
				have = got.Interface()
			}
			if !reflect.DeepEqual(have, want) {
				t.Errorf("%s=%s was ignored: %s is %v, want %v", env, value, path, have, want)
			}
			if path == "userHeader" || strings.HasPrefix(path, "cloudflareAccess.") {
				// The cloudflare block is the provider here: what the
				// environment set has to reach the provider entry.
				entry := lookupField(t, &Config{CloudflareAccess: cfg.Providers[0].CloudflareAccess},
					"cloudflareAccess."+strings.TrimPrefix(strings.TrimPrefix(path, "cloudflareAccess."), "."))
				if path != "userHeader" && !reflect.DeepEqual(entry.Interface(), lookupField(t, cfg, path).Interface()) {
					t.Errorf("%s did not reach the provider entry", path)
				}
			}
		})
	}
}

// TestLoad_EnvForUnusedLegacyBlock: the environment reaches the legacy
// top-level blocks only. With a providers list those blocks are not
// read, and a variable that sets one of their keys changes nothing —
// which is said in a warning rather than passed over.
func TestLoad_EnvForUnusedLegacyBlock(t *testing.T) {
	t.Setenv("AUTHENTICATOOR_OIDC_TRUSTUNVERIFIEDEMAIL", "true")
	t.Setenv("AUTHENTICATOOR_CLOUDFLAREACCESS_AUDTAG", "secret-looking-value")
	t.Setenv("AUTHENTICATOOR_LISTEN", ":9999")

	cfg, err := Load(writeTempConfig(t, teamsConfigHeader+"providers:\n  - name: dev\n    type: any\n"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.Warnings) != 2 ||
		!strings.Contains(cfg.Warnings[0], "AUTHENTICATOOR_CLOUDFLAREACCESS_AUDTAG") ||
		!strings.Contains(cfg.Warnings[1], "AUTHENTICATOOR_OIDC_TRUSTUNVERIFIEDEMAIL") {
		t.Fatalf("warnings: %v", cfg.Warnings)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "secret-looking-value") {
			t.Errorf("a warning shows the value of a variable: %s", w)
		}
	}

	// In the legacy form the same variables are simply honoured.
	cfg, err = Load(writeTempConfig(t, teamsConfigHeader+
		"authMode: [cloudflare, oidc]\ncloudflareAccess:\n  teamDomain: t.cloudflareaccess.com\n"+
		"oidc:\n  issuerURL: https://idp.example.com\n  callbackURL: https://auth.demo.example.com/cb\n"+
		"  clientId: id\n  clientSecret: s\n"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.Warnings) != 0 {
		t.Errorf("warnings: %v", cfg.Warnings)
	}
	if got := cfg.Providers[0].CloudflareAccess.AudTag; got != "secret-looking-value" {
		t.Errorf("audTag from the environment: %q", got)
	}
	if !cfg.Providers[1].OIDC.TrustsUnverifiedEmail() {
		t.Error("trustUnverifiedEmail from the environment was ignored")
	}
}
