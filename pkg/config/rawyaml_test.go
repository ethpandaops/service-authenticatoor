package config

import (
	"slices"
	"strings"
	"testing"
)

// document is now a startup error.
func TestLoad_SecondYAMLDocument(t *testing.T) {
	base := teamsConfigHeader + "cloudflareAccess:\n  teamDomain: \"t.cloudflareaccess.com\"\n"
	grants := "grants:\n  - members: [\"cfaccess/user:alice@example.org\"]\n    services: [all]\n"

	tests := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{"grants in a second document", base + "---\n" + grants, true},
		{"any second document", base + "---\nlisten: \":9999\"\n", true},
		{"a third document", base + "---\n---\n" + grants, true},
		{"a second document that is a list", base + "---\n- a\n- b\n", true},
		{"a leading document marker", "---\n" + base, false},
		{"a trailing document marker with nothing after it", base + "---\n", false},
		{"a document end marker", base + "...\n", false},
		{"a comment after a marker", base + "---\n# nothing here\n", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Load(writeTempConfig(t, tc.body))
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "more than one YAML document") {
					t.Fatalf("load: got %v (grants %+v), want a multi-document error", err, cfg)
				}
				return
			}
			if err != nil {
				t.Fatalf("load: %v", err)
			}
		})
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
// and refused as soon as teams, team rules, grants or an oidc bearer
// block come into play, from the file or from the environment.
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
		{
			"a bearer block in the file",
			minimalTOML + "\n[oidc.bearer]\naudiences = [\"devnet-cli\"]\n", [2]string{}, "oidc.bearer is configured",
		},
		{
			"a bearer block with an issuer only",
			minimalTOML + "\n[oidc.bearer]\nissuerURL = \"https://idp.example.org/cli\"\n", [2]string{}, "oidc.bearer is configured",
		},
		{
			"a bearer block in a providers entry",
			"issuer = \"https://auth.demo.example.com\"\n[signing.rs256]\nprivateKeyFile = \"/k.pem\"\n" +
				"[[providers]]\nname = \"corp\"\ntype = \"oidc\"\n[providers.oidc]\nissuerURL = \"https://idp.example.org\"\n" +
				"[providers.oidc.bearer]\naudiences = [\"devnet-cli\"]\n",
			[2]string{}, "oidc.bearer is configured",
		},
		{
			"bearer audiences from the environment",
			minimalTOML, [2]string{"AUTHENTICATOOR_OIDC_BEARER_AUDIENCES", "devnet-cli"}, "oidc.bearer is configured",
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
