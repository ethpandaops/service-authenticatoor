package config

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ethpandaops/service-authenticatoor/pkg/issuer"
	"github.com/ethpandaops/service-authenticatoor/pkg/protection"
)

func writeTempConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

func TestLoad_MinimalConfig(t *testing.T) {
	p := writeTempConfig(t, `
issuer: "https://auth.demo.example.com"
signing:
  rs256:
    privateKeyFile: "/etc/keys/private.pem"
cloudflareAccess:
  teamDomain: "test.cloudflareaccess.com"
  audTag: "abc123"
`)

	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if cfg.Listen != ":8080" {
		t.Errorf("listen default: %q", cfg.Listen)
	}
	if cfg.TokenTTL.Minutes() != 30 {
		t.Errorf("tokenTTL default: %v", cfg.TokenTTL)
	}
	if cfg.UserHeader != "Cf-Access-Authenticated-User-Email" {
		t.Errorf("userHeader default: %q", cfg.UserHeader)
	}
	if !cfg.CloudflareAccess.VerifyJWTEnabled() {
		t.Error("cf verifyJWT default should be true")
	}

	// Legacy single-provider promotion.
	if len(cfg.Providers) != 1 {
		t.Fatalf("expected one promoted provider, got %d", len(cfg.Providers))
	}
	if cfg.Providers[0].Name != "cfaccess" || cfg.Providers[0].Type != AuthModeCloudflare {
		t.Errorf("promoted provider: got %s:%s", cfg.Providers[0].Name, cfg.Providers[0].Type)
	}
	if cfg.Providers[0].CloudflareAccess.TeamDomain != "test.cloudflareaccess.com" {
		t.Errorf("promoted teamDomain: %q", cfg.Providers[0].CloudflareAccess.TeamDomain)
	}

	// Derived from issuer
	if got, want := cfg.Audience[0], "demo.example.com"; got != want {
		t.Errorf("derived audience: got %q want %q", got, want)
	}
	if got, want := cfg.ScopePattern, "*.demo.example.com"; got != want {
		t.Errorf("derived scope: got %q want %q", got, want)
	}
	if got, want := cfg.AllowedReturnHosts[0], "*.demo.example.com"; got != want {
		t.Errorf("derived returnHosts: got %q want %q", got, want)
	}
	if got, want := cfg.CORS.AllowedOrigins[0], "*.demo.example.com"; got != want {
		t.Errorf("derived corsOrigins: got %q want %q", got, want)
	}
	if cfg.ExternalURL != cfg.Issuer {
		t.Errorf("externalURL default: got %q", cfg.ExternalURL)
	}
}

func TestLoad_RejectsMissingIssuer(t *testing.T) {
	p := writeTempConfig(t, `
signing:
  rs256:
    privateKeyFile: "/etc/keys/private.pem"
cloudflareAccess:
  teamDomain: "test.cloudflareaccess.com"
  audTag: "abc123"
`)
	if _, err := Load(p); err == nil {
		t.Error("expected error for missing issuer")
	}
}

func TestLoad_RejectsMissingPrivateKey(t *testing.T) {
	p := writeTempConfig(t, `
issuer: "https://auth.foo.example"
cloudflareAccess:
  teamDomain: "test.cloudflareaccess.com"
  audTag: "abc123"
`)
	if _, err := Load(p); err == nil {
		t.Error("expected error for missing privateKeyFile")
	}
}

func TestLoad_RejectsMissingTeamDomainWhenVerifyJWTOn(t *testing.T) {
	p := writeTempConfig(t, `
issuer: "https://auth.foo.example"
signing:
  rs256:
    privateKeyFile: "/etc/keys/private.pem"
cloudflareAccess:
  verifyJWT: true
  # teamDomain missing
`)
	if _, err := Load(p); err == nil {
		t.Error("expected error for missing CF teamDomain")
	}
}

func TestLoad_AcceptsMissingAudTagWhenVerifyJWTOn(t *testing.T) {
	// Audience verification is optional; a configured teamDomain alone
	// ties the assertion to the CF Access team via signature + issuer.
	p := writeTempConfig(t, `
issuer: "https://auth.foo.example"
signing:
  rs256:
    privateKeyFile: "/etc/keys/private.pem"
cloudflareAccess:
  verifyJWT: true
  teamDomain: "test.cloudflareaccess.com"
`)
	if _, err := Load(p); err != nil {
		t.Errorf("did not expect error with empty audTag: %v", err)
	}
}

func TestLoad_AcceptsCFConfigWhenVerifyJWTOff(t *testing.T) {
	p := writeTempConfig(t, `
issuer: "https://auth.foo.example"
signing:
  rs256:
    privateKeyFile: "/etc/keys/private.pem"
cloudflareAccess:
  verifyJWT: false
`)
	if _, err := Load(p); err != nil {
		t.Errorf("did not expect error with verifyJWT off: %v", err)
	}
}

func TestLoad_RejectsBadIssuerScheme(t *testing.T) {
	p := writeTempConfig(t, `
issuer: "not-a-url"
signing:
  rs256:
    privateKeyFile: "/etc/keys/private.pem"
cloudflareAccess:
  verifyJWT: false
`)
	if _, err := Load(p); err == nil {
		t.Error("expected error for non-URL issuer")
	}
}

func TestLoad_RejectsIssuerWithoutParent(t *testing.T) {
	p := writeTempConfig(t, `
issuer: "https://localhost"
signing:
  rs256:
    privateKeyFile: "/etc/keys/private.pem"
cloudflareAccess:
  verifyJWT: false
`)
	if _, err := Load(p); err == nil {
		t.Error("expected error for issuer without parent zone")
	}
}

func TestLoad_SingleLabelIssuerWithExplicitFields(t *testing.T) {
	// A parent-zone-less issuer host (local dev on plain localhost) must
	// load as long as every zone-derived field is set explicitly.
	p := writeTempConfig(t, `
issuer: "http://localhost:18080"
audience:
  - "localhost"
scopePattern: "localhost"
allowedReturnHosts:
  - "localhost"
signing:
  rs256:
    privateKeyFile: "/etc/keys/private.pem"
cloudflareAccess:
  verifyJWT: false
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.ExternalURL != "http://localhost:18080" {
		t.Errorf("externalURL: got %q", cfg.ExternalURL)
	}
	if got, want := cfg.CORS.AllowedOrigins[0], "localhost"; got != want {
		t.Errorf("corsOrigins: got %q want %q", got, want)
	}
}

func TestLoad_AuthModeDefaultsToCloudflare(t *testing.T) {
	p := writeTempConfig(t, `
issuer: "https://auth.foo.example"
signing:
  rs256:
    privateKeyFile: "/etc/keys/private.pem"
cloudflareAccess:
  verifyJWT: false
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.AuthMode) != 1 || cfg.AuthMode[0] != "cfaccess" {
		t.Errorf("authMode: got %v want [cfaccess]", cfg.AuthMode)
	}
}

func TestLoad_RejectsUnknownAuthMode(t *testing.T) {
	p := writeTempConfig(t, `
authMode: "bogus"
issuer: "https://auth.foo.example"
signing:
  rs256:
    privateKeyFile: "/etc/keys/private.pem"
cloudflareAccess:
  verifyJWT: false
`)
	if _, err := Load(p); err == nil {
		t.Error("expected error for unknown authMode")
	}
}

func TestLoad_TopLevelUserHeaderFoldsIntoCloudflareAccess(t *testing.T) {
	p := writeTempConfig(t, `
issuer: "https://auth.foo.example"
userHeader: "X-Custom-Email"
signing:
  rs256:
    privateKeyFile: "/etc/keys/private.pem"
cloudflareAccess:
  verifyJWT: false
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.CloudflareAccess.UserHeader != "X-Custom-Email" {
		t.Errorf("cloudflareAccess.userHeader: got %q want %q",
			cfg.CloudflareAccess.UserHeader, "X-Custom-Email")
	}
	// Default top-level value (no explicit override) → no warning.
	if len(cfg.DeprecationWarnings) != 0 {
		t.Errorf("expected no deprecation warnings, got %v", cfg.DeprecationWarnings)
	}
}

func TestLoad_CloudflareAccessUserHeaderOverridesTopLevel(t *testing.T) {
	p := writeTempConfig(t, `
issuer: "https://auth.foo.example"
userHeader: "X-Old-Email"
signing:
  rs256:
    privateKeyFile: "/etc/keys/private.pem"
cloudflareAccess:
  verifyJWT: false
  userHeader: "X-New-Email"
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.CloudflareAccess.UserHeader != "X-New-Email" {
		t.Errorf("cloudflareAccess.userHeader: got %q", cfg.CloudflareAccess.UserHeader)
	}
	if len(cfg.DeprecationWarnings) == 0 {
		t.Error("expected deprecation warning when both forms are set")
	}
}

func TestLoad_BasicMode_RequiresHtpasswdFile(t *testing.T) {
	p := writeTempConfig(t, `
authMode: basic
issuer: "https://auth.foo.example"
signing:
  rs256:
    privateKeyFile: "/etc/keys/private.pem"
`)
	if _, err := Load(p); err == nil {
		t.Error("expected error for missing basicAuth.htpasswdFile")
	}
}

func TestLoad_BasicMode_AcceptsHtpasswdFile(t *testing.T) {
	p := writeTempConfig(t, `
authMode: basic
issuer: "https://auth.foo.example"
signing:
  rs256:
    privateKeyFile: "/etc/keys/private.pem"
basicAuth:
  htpasswdFile: "/etc/htpasswd"
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.AuthMode) != 1 || cfg.AuthMode[0] != "htpasswd" {
		t.Errorf("authMode: got %v want [htpasswd]", cfg.AuthMode)
	}
	if cfg.BasicAuth.HtpasswdFile != "/etc/htpasswd" {
		t.Errorf("htpasswdFile: got %q", cfg.BasicAuth.HtpasswdFile)
	}
}

func TestLoad_AnyMode_NoRequiredFields(t *testing.T) {
	p := writeTempConfig(t, `
authMode: any
issuer: "https://auth.foo.example"
signing:
  rs256:
    privateKeyFile: "/etc/keys/private.pem"
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.AuthMode) != 1 || cfg.AuthMode[0] != "anyauth" {
		t.Errorf("authMode: got %v want [anyauth]", cfg.AuthMode)
	}
}

func TestLoad_ProvidersList(t *testing.T) {
	p := writeTempConfig(t, `
issuer: "https://auth.foo.example"
signing:
  rs256:
    privateKeyFile: "/etc/keys/private.pem"
providers:
  - name: cfaccess
    type: cloudflare
    cloudflareAccess:
      teamDomain: "test.cloudflareaccess.com"
  - name: oidc
    type: oidc
    oidc:
      issuerURL: "https://dex.example"
      callbackURL: "https://relay.example/oidc/callback"
      clientId: "authenticatoor"
      clientSecret: "secret"
  - name: panda
    type: oidc
    oidc:
      issuerURL: "https://authentik.example/application/o/panda/"
      callbackURL: "https://auth.foo.example/panda/callback"
      clientId: "panda"
      clientSecret: "secret"
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.Providers) != 3 {
		t.Fatalf("expected 3 providers, got %d", len(cfg.Providers))
	}
	if cfg.Providers[0].Name != "cfaccess" || cfg.Providers[1].Name != "oidc" || cfg.Providers[2].Name != "panda" {
		t.Errorf("names: got %s, %s, %s", cfg.Providers[0].Name, cfg.Providers[1].Name, cfg.Providers[2].Name)
	}
	// Unset verifyJWT in a providers entry must still mean "on".
	if !cfg.Providers[0].CloudflareAccess.VerifyJWTEnabled() {
		t.Error("providers-entry verifyJWT default should be true")
	}
}

func TestLoad_ProvidersList_RejectsMissingName(t *testing.T) {
	p := writeTempConfig(t, `
issuer: "https://auth.foo.example"
signing:
  rs256:
    privateKeyFile: "/etc/keys/private.pem"
providers:
  - type: any
`)
	if _, err := Load(p); err == nil {
		t.Error("expected error for providers entry without a name")
	}
}

func TestLoad_ProvidersList_RejectsDuplicateNames(t *testing.T) {
	p := writeTempConfig(t, `
issuer: "https://auth.foo.example"
signing:
  rs256:
    privateKeyFile: "/etc/keys/private.pem"
providers:
  - name: dev
    type: any
  - name: dev
    type: any
`)
	if _, err := Load(p); err == nil {
		t.Error("expected error for duplicate provider names")
	}
}

func TestLoad_ProvidersList_RejectsReservedName(t *testing.T) {
	p := writeTempConfig(t, `
issuer: "https://auth.foo.example"
signing:
  rs256:
    privateKeyFile: "/etc/keys/private.pem"
providers:
  - name: auth
    type: any
`)
	if _, err := Load(p); err == nil {
		t.Error("expected error for reserved provider name")
	}
}

func TestLoad_ProvidersList_RejectsMissingRequiredFields(t *testing.T) {
	p := writeTempConfig(t, `
issuer: "https://auth.foo.example"
signing:
  rs256:
    privateKeyFile: "/etc/keys/private.pem"
providers:
  - name: github
    type: github
    githubOAuth:
      clientId: "id-only"
`)
	if _, err := Load(p); err == nil {
		t.Error("expected error for incomplete github provider")
	}
}

func TestLoad_ProvidersList_CFVerifyJWTExplicitFalse(t *testing.T) {
	p := writeTempConfig(t, `
issuer: "https://auth.foo.example"
signing:
  rs256:
    privateKeyFile: "/etc/keys/private.pem"
providers:
  - name: cfaccess
    type: cloudflare
    cloudflareAccess:
      verifyJWT: false
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Providers[0].CloudflareAccess.VerifyJWTEnabled() {
		t.Error("explicit verifyJWT: false must be honored")
	}
}

func TestLoad_AuthModeArray_ConvertsLegacyBlocks(t *testing.T) {
	p := writeTempConfig(t, `
authMode: [basic, any]
issuer: "https://auth.foo.example"
signing:
  rs256:
    privateKeyFile: "/etc/keys/private.pem"
basicAuth:
  htpasswdFile: "/etc/htpasswd"
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.Providers) != 2 {
		t.Fatalf("expected 2 converted providers, got %d", len(cfg.Providers))
	}
	if cfg.Providers[0].Name != "htpasswd" || cfg.Providers[0].Type != AuthModeBasic {
		t.Errorf("providers[0]: got %s:%s", cfg.Providers[0].Name, cfg.Providers[0].Type)
	}
	if cfg.Providers[1].Name != "anyauth" || cfg.Providers[1].Type != AuthModeAny {
		t.Errorf("providers[1]: got %s:%s", cfg.Providers[1].Name, cfg.Providers[1].Type)
	}
	if len(cfg.AuthMode) != 2 || cfg.AuthMode[0] != "htpasswd" || cfg.AuthMode[1] != "anyauth" {
		t.Errorf("authMode: got %v", cfg.AuthMode)
	}
}

func TestLoad_AuthModeAdvertisesProvidersByName(t *testing.T) {
	p := writeTempConfig(t, `
authMode: [alt, anyauth]
issuer: "https://auth.foo.example"
signing:
  rs256:
    privateKeyFile: "/etc/keys/private.pem"
providers:
  - name: anyauth
    type: any
  - name: alt
    type: any
  - name: dormant
    type: any
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	// ALL defined providers stay enabled; authMode only orders the
	// advertised subset.
	if len(cfg.Providers) != 3 {
		t.Fatalf("expected all 3 providers enabled, got %d", len(cfg.Providers))
	}
	if len(cfg.AuthMode) != 2 || cfg.AuthMode[0] != "alt" || cfg.AuthMode[1] != "anyauth" {
		t.Errorf("advertised: got %v", cfg.AuthMode)
	}
}

func TestLoad_AuthModeRejectsDuplicateEntries(t *testing.T) {
	p := writeTempConfig(t, `
authMode: [anyauth, anyauth]
issuer: "https://auth.foo.example"
signing:
  rs256:
    privateKeyFile: "/etc/keys/private.pem"
providers:
  - name: anyauth
    type: any
`)
	if _, err := Load(p); err == nil {
		t.Error("expected error for duplicate authMode entries")
	}
}

func TestLoad_AuthModeRejectsUnknownProviderName(t *testing.T) {
	p := writeTempConfig(t, `
authMode: nope
issuer: "https://auth.foo.example"
signing:
  rs256:
    privateKeyFile: "/etc/keys/private.pem"
providers:
  - name: anyauth
    type: any
`)
	if _, err := Load(p); err == nil {
		t.Error("expected error for authMode referencing unknown provider")
	}
}

func TestLoad_ProvidersDefaultAllActive(t *testing.T) {
	p := writeTempConfig(t, `
issuer: "https://auth.foo.example"
signing:
  rs256:
    privateKeyFile: "/etc/keys/private.pem"
providers:
  - name: anyauth
    type: any
  - name: alt
    type: any
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.Providers) != 2 {
		t.Fatalf("expected both providers active, got %d", len(cfg.Providers))
	}
	if len(cfg.AuthMode) != 2 || cfg.AuthMode[0] != "anyauth" || cfg.AuthMode[1] != "alt" {
		t.Errorf("authMode: got %v", cfg.AuthMode)
	}
}

func TestLoad_EnvOverride(t *testing.T) {
	p := writeTempConfig(t, `
issuer: "https://auth.foo.example"
signing:
  rs256:
    privateKeyFile: "/etc/keys/private.pem"
cloudflareAccess:
  verifyJWT: false
`)

	t.Setenv("AUTHENTICATOOR_LISTEN", ":9999")
	t.Setenv("AUTHENTICATOOR_SIGNING_RS256_PRIVATEKEYFILE", "/etc/keys/override.pem")

	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Listen != ":9999" {
		t.Errorf("env override of listen failed: got %q", cfg.Listen)
	}
	if cfg.Signing.RS256.PrivateKeyFile != "/etc/keys/override.pem" {
		t.Errorf("env override of privateKeyFile failed: got %q", cfg.Signing.RS256.PrivateKeyFile)
	}
}

// TestLoad_EnvOverrideKeysWithoutDefaults covers keys that have no viper
// default: their env overrides must apply even when the config file
// doesn't mention them.
func TestLoad_EnvOverrideKeysWithoutDefaults(t *testing.T) {
	p := writeTempConfig(t, `
issuer: "https://auth.foo.example"
signing:
  rs256:
    privateKeyFile: "/etc/keys/private.pem"
basicAuth:
  htpasswdFile: "/etc/htpasswd"
`)

	t.Setenv("AUTHENTICATOOR_AUTHMODE", "cloudflare,basic")
	t.Setenv("AUTHENTICATOOR_CLOUDFLAREACCESS_VERIFYJWT", "false")
	t.Setenv("AUTHENTICATOOR_CLOUDFLAREACCESS_ALLOWSERVICETOKENS", "false")

	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.AuthMode) != 2 || cfg.AuthMode[0] != "cfaccess" || cfg.AuthMode[1] != "htpasswd" {
		t.Errorf("authMode env override: got %v", cfg.AuthMode)
	}
	cf := cfg.Providers[0].CloudflareAccess
	if cf.VerifyJWTEnabled() {
		t.Error("verifyJWT env override: still enabled")
	}
	if cf.ServiceTokensAllowed() {
		t.Error("allowServiceTokens env override: still enabled")
	}
}

// TestLoad_LegacyBlocksKeepPreviousDefaults checks that entries converted
// from legacy top-level blocks keep the old callback paths and cookie
// names, while providers-list entries leave them empty (→ /<name>/...).
func TestLoad_LegacyBlocksKeepPreviousDefaults(t *testing.T) {
	p := writeTempConfig(t, `
authMode: [github, oidc]
issuer: "https://auth.foo.example"
signing:
  rs256:
    privateKeyFile: "/etc/keys/private.pem"
githubOAuth:
  clientId: "id"
  clientSecret: "secret"
  allowedOrgs: ["org"]
oidc:
  issuerURL: "https://idp.example"
  callbackURL: "https://relay.example/oidc/callback"
  clientId: "id"
  clientSecret: "secret"
  sessionCookieName: "custom_oidc_session"
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	gh := cfg.Providers[0].GitHubOAuth
	if gh.CallbackPath != "/auth/oauth/callback" {
		t.Errorf("github callbackPath: got %q", gh.CallbackPath)
	}
	if gh.SessionCookieName != "authenticatoor_session" || gh.StateCookieName != "authenticatoor_oauth_state" {
		t.Errorf("github cookie names: got %q / %q", gh.SessionCookieName, gh.StateCookieName)
	}
	oc := cfg.Providers[1].OIDC
	if oc.CallbackPath != "/auth/oidc/callback" {
		t.Errorf("oidc callbackPath: got %q", oc.CallbackPath)
	}
	if oc.SessionCookieName != "custom_oidc_session" {
		t.Errorf("explicit oidc sessionCookieName overridden: got %q", oc.SessionCookieName)
	}

	p = writeTempConfig(t, `
issuer: "https://auth.foo.example"
signing:
  rs256:
    privateKeyFile: "/etc/keys/private.pem"
providers:
  - name: gh
    type: github
    githubOAuth:
      clientId: "id"
      clientSecret: "secret"
      allowedOrgs: ["org"]
`)
	cfg, err = Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := cfg.Providers[0].GitHubOAuth.CallbackPath; got != "" {
		t.Errorf("providers-list callbackPath should stay unset, got %q", got)
	}
}

const teamsConfigHeader = `
issuer: "https://auth.demo.example.com"
signing:
  rs256:
    privateKeyFile: "/etc/keys/private.pem"
`

// TestLoad_Teams_ProvidersList loads the canonical form with every team
// field set.
func TestLoad_Teams_ProvidersList(t *testing.T) {
	p := writeTempConfig(t, teamsConfigHeader+`
providers:
  - name: cfaccess
    type: cloudflare
    cloudflareAccess:
      teamDomain: "test.cloudflareaccess.com"
      audTag: "aud"
      teams: [door]
      teamRules:
        - claim: principal
          map: { user: [panda] }
  - name: htpasswd
    type: basic
    basicAuth:
      htpasswdFile: "/etc/htpasswd"
      teams: [ops, panda]
      teamRules:
        - claim: username
          map: { Alice: [lighthouse] }
  - name: anyauth
    type: any
    anyAuth:
      teams: [dev]
      teamRules:
        - claim: username
          prefix: "team-"
  - name: github
    type: github
    githubOAuth:
      clientId: "id"
      clientSecret: "secret"
      allowedOrgs: [ethpandaops, sigp]
      teams: [devnet]
      teamRules:
        - claim: orgs
          map:
            ethpandaops: [panda]
            SigP: [lighthouse, anchor]
  - name: oidc
    type: oidc
    oidc:
      issuerURL: "https://idp.example.com"
      callbackURL: "https://auth.demo.example.com/oidc/callback"
      clientId: "id"
      clientSecret: "secret"
      teams: [devnet]
      teamRules:
        - claim: groups
          prefix: "team:"
        - claim: groups
          map:
            ethpandaops: [panda]
            "ethpandaops:*": [panda]
            "EthDevOpsAccess:validatorops": [ops]
            "some.dotted.group": [dotted]
        - claim: department
          regex: "^eng-([a-z0-9-]+)$"
        - claim: scope
          split: " "
          value: true
        - claim: email
          map: { "Alice@Example.org": [lighthouse] }
        - claim: level
          map: { 3: [senior], true: [yes] }
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	byName := make(map[string]ProviderConfig, len(cfg.Providers))
	for _, pc := range cfg.Providers {
		byName[pc.Name] = pc
	}

	cf := byName["cfaccess"].CloudflareAccess
	if !slices.Equal(cf.Teams, []string{"door"}) || len(cf.TeamRules) != 1 ||
		cf.TeamRules[0].Claim != "principal" || !slices.Equal(cf.TeamRules[0].Map["user"], []string{"panda"}) {
		t.Errorf("cloudflareAccess: teams=%v rules=%+v", cf.Teams, cf.TeamRules)
	}

	basicCfg := byName["htpasswd"].BasicAuth
	if !slices.Equal(basicCfg.Teams, []string{"ops", "panda"}) || len(basicCfg.TeamRules) != 1 ||
		!slices.Equal(basicCfg.TeamRules[0].Map["Alice"], []string{"lighthouse"}) {
		t.Errorf("basicAuth: teams=%v rules=%+v", basicCfg.Teams, basicCfg.TeamRules)
	}

	aa := byName["anyauth"].AnyAuth
	if !slices.Equal(aa.Teams, []string{"dev"}) || len(aa.TeamRules) != 1 || aa.TeamRules[0].Prefix != "team-" {
		t.Errorf("anyAuth: teams=%v rules=%+v", aa.Teams, aa.TeamRules)
	}

	gh := byName["github"].GitHubOAuth
	if !slices.Equal(gh.Teams, []string{"devnet"}) || len(gh.TeamRules) != 1 {
		t.Fatalf("githubOAuth: teams=%v rules=%+v", gh.Teams, gh.TeamRules)
	}
	// Map keys arrive exactly as written: case kept.
	if got := gh.TeamRules[0].Map; !maps.EqualFunc(got, map[string][]string{
		"ethpandaops": {"panda"}, "SigP": {"lighthouse", "anchor"},
	}, slices.Equal[[]string]) {
		t.Errorf("githubOAuth rule map: %v", got)
	}

	oc := byName["oidc"].OIDC
	if !slices.Equal(oc.Teams, []string{"devnet"}) {
		t.Errorf("oidc teams=%v", oc.Teams)
	}
	if len(oc.TeamRules) != 6 {
		t.Fatalf("oidc rules: %+v", oc.TeamRules)
	}
	if r := oc.TeamRules[0]; r.Claim != "groups" || r.Prefix != "team:" {
		t.Errorf("rule 0: %+v", r)
	}
	// Keys with colons, globs, dots and capitals survive untouched.
	if got := oc.TeamRules[1].Map; !maps.EqualFunc(got, map[string][]string{
		"ethpandaops":                  {"panda"},
		"ethpandaops:*":                {"panda"},
		"EthDevOpsAccess:validatorops": {"ops"},
		"some.dotted.group":            {"dotted"},
	}, slices.Equal[[]string]) {
		t.Errorf("rule 1 map: %v", got)
	}
	if r := oc.TeamRules[2]; r.Claim != "department" || r.Regex != "^eng-([a-z0-9-]+)$" {
		t.Errorf("rule 2: %+v", r)
	}
	if r := oc.TeamRules[3]; r.Claim != "scope" || r.Split != " " || !r.Value {
		t.Errorf("rule 3: %+v", r)
	}
	if got := oc.TeamRules[4].Map; !slices.Equal(got["Alice@Example.org"], []string{"lighthouse"}) {
		t.Errorf("rule 4 map (an email key): %v", got)
	}
	// Unquoted numbers and booleans are keys too, by their text.
	if got := oc.TeamRules[5].Map; !slices.Equal(got["3"], []string{"senior"}) || !slices.Equal(got["true"], []string{"yes"}) {
		t.Errorf("rule 5 map: %v", got)
	}
}

// TestLoad_Teams_LegacyBlocks: the legacy single-authMode form carries
// the team fields of its top-level block into the converted entry —
// including rule maps whose keys contain dots, which viper alone would
// break apart.
func TestLoad_Teams_LegacyBlocks(t *testing.T) {
	tests := []struct {
		name  string
		body  string
		check func(t *testing.T, pc ProviderConfig)
	}{
		{
			"cloudflare (default authMode)",
			`
cloudflareAccess:
  teamDomain: "test.cloudflareaccess.com"
  audTag: "aud"
  teams: [door]
  teamRules:
    - claim: principal
      map: { user: [panda] }
    - claim: email
      map: { "Alice@Example.org": [lighthouse] }
`,
			func(t *testing.T, pc ProviderConfig) {
				c := pc.CloudflareAccess
				if pc.Name != "cfaccess" || !slices.Equal(c.Teams, []string{"door"}) || len(c.TeamRules) != 2 ||
					!slices.Equal(c.TeamRules[0].Map["user"], []string{"panda"}) ||
					!slices.Equal(c.TeamRules[1].Map["Alice@Example.org"], []string{"lighthouse"}) {
					t.Errorf("%s: teams=%v rules=%+v", pc.Name, c.Teams, c.TeamRules)
				}
			},
		},
		{
			"basic",
			`
authMode: basic
basicAuth:
  htpasswdFile: "/etc/htpasswd"
  teams: [ops]
  teamRules:
    - claim: username
      value: true
`,
			func(t *testing.T, pc ProviderConfig) {
				if !slices.Equal(pc.BasicAuth.Teams, []string{"ops"}) || len(pc.BasicAuth.TeamRules) != 1 {
					t.Errorf("teams=%v rules=%+v", pc.BasicAuth.Teams, pc.BasicAuth.TeamRules)
				}
			},
		},
		{
			"any",
			`
authMode: any
anyAuth:
  teams: [dev]
  teamRules:
    - claim: username
      prefix: "team-"
`,
			func(t *testing.T, pc ProviderConfig) {
				if !slices.Equal(pc.AnyAuth.Teams, []string{"dev"}) ||
					len(pc.AnyAuth.TeamRules) != 1 || pc.AnyAuth.TeamRules[0].Prefix != "team-" {
					t.Errorf("teams=%v rules=%+v", pc.AnyAuth.Teams, pc.AnyAuth.TeamRules)
				}
			},
		},
		{
			"github",
			`
authMode: github
githubOAuth:
  clientId: "id"
  clientSecret: "secret"
  allowedOrgs: [sigp]
  teams: [devnet]
  teamRules:
    - claim: orgs
      map:
        sigp: [lighthouse]
`,
			func(t *testing.T, pc ProviderConfig) {
				if !slices.Equal(pc.GitHubOAuth.Teams, []string{"devnet"}) || len(pc.GitHubOAuth.TeamRules) != 1 ||
					!slices.Equal(pc.GitHubOAuth.TeamRules[0].Map["sigp"], []string{"lighthouse"}) {
					t.Errorf("teams=%v rules=%+v", pc.GitHubOAuth.Teams, pc.GitHubOAuth.TeamRules)
				}
			},
		},
		{
			"oidc",
			`
authMode: oidc
oidc:
  issuerURL: "https://idp.example.com"
  callbackURL: "https://auth.demo.example.com/oidc/callback"
  clientId: "id"
  clientSecret: "secret"
  teams: [devnet]
  teamRules:
    - claim: groups
      prefix: "team:"
    - claim: groups
      map:
        ethpandaops: [panda]
        "some.dotted.group": [dotted]
`,
			func(t *testing.T, pc ProviderConfig) {
				c := pc.OIDC
				if !slices.Equal(c.Teams, []string{"devnet"}) || len(c.TeamRules) != 2 || c.TeamRules[0].Prefix != "team:" ||
					!slices.Equal(c.TeamRules[1].Map["ethpandaops"], []string{"panda"}) ||
					!slices.Equal(c.TeamRules[1].Map["some.dotted.group"], []string{"dotted"}) || len(c.TeamRules[1].Map) != 2 {
					t.Errorf("teams=%v rules=%+v", c.Teams, c.TeamRules)
				}
			},
		},
		{
			"no team config at all",
			`
authMode: oidc
oidc:
  issuerURL: "https://idp.example.com"
  callbackURL: "https://auth.demo.example.com/oidc/callback"
  clientId: "id"
  clientSecret: "secret"
`,
			func(t *testing.T, pc ProviderConfig) {
				if pc.OIDC.Teams != nil || len(pc.OIDC.TeamRules) != 0 {
					t.Errorf("defaults: teams=%v rules=%+v", pc.OIDC.Teams, pc.OIDC.TeamRules)
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Load(writeTempConfig(t, teamsConfigHeader+tc.body))
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			if len(cfg.Providers) != 1 {
				t.Fatalf("providers: %d", len(cfg.Providers))
			}
			tc.check(t, cfg.Providers[0])
		})
	}
}

// TestLoad_Teams_RejectsInvalid: a malformed team configuration is a
// startup error naming the field, in both config forms.
func TestLoad_Teams_RejectsInvalid(t *testing.T) {
	many := make([]string, 0, 33)
	for i := range 33 {
		many = append(many, fmt.Sprintf("t%02d", i))
	}
	oidcBlock := `
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
			"legacy cloudflare: whitespace in a name",
			`
cloudflareAccess:
  teamDomain: "test.cloudflareaccess.com"
  teams: ["core devs"]
`,
			`cloudflareAccess.teams: invalid team name(s) ["core devs"]`,
		},
		{
			"legacy cloudflare: too many",
			`
cloudflareAccess:
  teamDomain: "test.cloudflareaccess.com"
  teams: [` + strings.Join(many, ", ") + `]
`,
			"cloudflareAccess.teams: too many teams: 33 (at most 32)",
		},
		{
			"legacy cloudflare: a rule",
			`
cloudflareAccess:
  teamDomain: "test.cloudflareaccess.com"
  teamRules:
    - claim: principal
      map: { user: ["Staff Team"] }
`,
			`cloudflareAccess.teamRules[0]: claim "principal": map key "user": invalid team name(s) ["Staff Team"]`,
		},
		{
			"providers list: basic",
			`
providers:
  - name: htpasswd
    type: basic
    basicAuth:
      htpasswdFile: "/etc/htpasswd"
      teams: ["team:panda"]
`,
			`providers[0] (htpasswd): basicAuth.teams: invalid team name(s) ["team:panda"]`,
		},
		{
			"providers list: any",
			`
providers:
  - name: anyauth
    type: any
    anyAuth:
      teams: [""]
`,
			`anyAuth.teams: invalid team name(s) [""]`,
		},
		{
			"providers list: github static",
			`
providers:
  - name: github
    type: github
    githubOAuth:
      clientId: "id"
      clientSecret: "secret"
      allowedOrgs: [sigp]
      teams: ["-x"]
`,
			`githubOAuth.teams: invalid team name(s) ["-x"]`,
		},
		{
			"providers list: github rule map value",
			`
providers:
  - name: github
    type: github
    githubOAuth:
      clientId: "id"
      clientSecret: "secret"
      allowedOrgs: [sigp]
      teamRules:
        - claim: orgs
          map:
            sigp: ["light house"]
`,
			`githubOAuth.teamRules[0]: claim "orgs": map key "sigp": invalid team name(s) ["light house"]`,
		},
		{"oidc static", oidcBlock + `      teams: ["pan/da"]` + "\n", `oidc.teams: invalid team name(s) ["pan/da"]`},
		{"oidc rule without a claim", oidcBlock + "      teamRules:\n        - prefix: \"team:\"\n", `oidc.teamRules[0]: claim is required`},
		{
			"oidc rule with two forms",
			oidcBlock + "      teamRules:\n        - claim: groups\n          prefix: \"team:\"\n          regex: \"(a)\"\n",
			`oidc.teamRules[0]: claim "groups": only one of prefix, map, regex and value may be set`,
		},
		{
			"oidc second rule: regex without a capture group",
			oidcBlock + "      teamRules:\n        - claim: groups\n          value: true\n        - claim: department\n          regex: \"^eng-.+$\"\n",
			`oidc.teamRules[1]: claim "department": regex: must have exactly one capture group`,
		},
		{
			"oidc rule: regex that does not compile",
			oidcBlock + "      teamRules:\n        - claim: department\n          regex: \"(eng\"\n",
			`oidc.teamRules[0]: claim "department": regex:`,
		},
		{
			"oidc rule: map is not a map",
			oidcBlock + "      teamRules:\n        - claim: groups\n          map: [a, b]\n",
			`oidc.teamRules[0]`,
		},
		{
			"oidc rule: a nested map value",
			oidcBlock + "      teamRules:\n        - claim: groups\n          map:\n            staff:\n              teams: [panda]\n",
			`providers[0].oidc.teamRules[0].map`,
		},
		{
			"the removed oidc fields are gone, not aliased",
			oidcBlock + "      teamRules:\n        - claim: groups\n          map: { ethpandaops: [\"Not Valid\"] }\n",
			`invalid team name(s) ["Not Valid"]`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(writeTempConfig(t, teamsConfigHeader+tc.body))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("load: got %v, want an error containing %q", err, tc.wantErr)
			}
		})
	}
}

// TestLoad_Teams_OnlyTheTypesOwnBlockIsValidated: a legacy config may
// carry blocks for provider types it does not use; team names in those
// are never applied, so they must not fail startup.
func TestLoad_Teams_OnlyTheTypesOwnBlockIsValidated(t *testing.T) {
	_, err := Load(writeTempConfig(t, teamsConfigHeader+`
authMode: any
basicAuth:
  teams: ["not valid"]
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
}

// TestLoad_Teams_EnvOverride: the legacy blocks' static team lists have
// no default, so they are bound explicitly; a comma-separated env value
// becomes a list.
func TestLoad_Teams_EnvOverride(t *testing.T) {
	t.Setenv("AUTHENTICATOOR_CLOUDFLAREACCESS_TEAMS", "panda,ops")
	cfg, err := Load(writeTempConfig(t, teamsConfigHeader+`
cloudflareAccess:
  teamDomain: "test.cloudflareaccess.com"
  audTag: "aud"
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := cfg.Providers[0].CloudflareAccess.Teams; !slices.Equal(got, []string{"panda", "ops"}) {
		t.Errorf("teams from env: %v", got)
	}

	t.Setenv("AUTHENTICATOOR_OIDC_TEAMS", "devnet")
	cfg, err = Load(writeTempConfig(t, teamsConfigHeader+`
authMode: oidc
oidc:
  issuerURL: "https://idp.example.com"
  callbackURL: "https://auth.demo.example.com/oidc/callback"
  clientId: "id"
  clientSecret: "secret"
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if oc := cfg.Providers[0].OIDC; !slices.Equal(oc.Teams, []string{"devnet"}) {
		t.Errorf("oidc from env: teams=%v", oc.Teams)
	}
}

// TestLoad_Grants loads the grants section from real files.
func TestLoad_Grants(t *testing.T) {
	providers := `
providers:
  - name: cfaccess
    type: cloudflare
    cloudflareAccess:
      teamDomain: "test.cloudflareaccess.com"
      audTag: "aud"
  - name: oidc
    type: oidc
    oidc:
      issuerURL: "https://idp.example.com"
      callbackURL: "https://auth.demo.example.com/oidc/callback"
      clientId: "id"
      clientSecret: "secret"
  - name: github
    type: github
    githubOAuth:
      clientId: "id"
      clientSecret: "secret"
      allowedOrgs: [sigp]
  - name: htpasswd
    type: basic
    basicAuth:
      htpasswdFile: "/etc/htpasswd"
  - name: anyauth
    type: any
`
	group := func(members string) string {
		return "\ngrants:\n  - members: [" + members + "]\n    services: [dora]\n"
	}

	tests := []struct {
		name    string
		body    string
		want    *issuer.GrantsConfig // nil: section absent
		wantErr string
	}{
		{"absent", "", nil, ""},
		{
			"the documented shape",
			`
grants:
  - name: staff
    members:
      - "cfaccess/team:panda"
      - "oidc/team:ethpandaops"
    services: ["all:all"]
  - name: client-devs
    members: ["oidc/team:lighthouse", "oidc/team:geth"]
    services: [dora, "spamoor:user*"]
  - members: ["oidc/user:alice@example.org"]
    services: ["dora:reindex"]
  - name: internal
    members: ["oidc/groups:panda-access", "github/orgs:EthPandaOps"]
    services: []
`,
			&issuer.GrantsConfig{Groups: []issuer.GrantGroup{
				{Name: "staff", Members: []string{"cfaccess/team:panda", "oidc/team:ethpandaops"}, Services: []string{"all:all"}},
				{Name: "client-devs", Members: []string{"oidc/team:lighthouse", "oidc/team:geth"}, Services: []string{"dora", "spamoor:user*"}},
				{Members: []string{"oidc/user:alice@example.org"}, Services: []string{"dora:reindex"}},
				{Name: "internal", Members: []string{"oidc/groups:panda-access", "github/orgs:EthPandaOps"}, Services: []string{}},
			}},
			"",
		},
		{"present but empty", "\ngrants: []\n", &issuer.GrantsConfig{Groups: []issuer.GrantGroup{}}, ""},
		{
			"members arrive as written: colons, slashes, case, dots",
			group(`"oidc/groups:sigp:core/devs", "oidc/user:Alice@Example.org", "oidc/realm_access.roles:Ops", "oidc/user:https://idp.example/u/1"`),
			&issuer.GrantsConfig{Groups: []issuer.GrantGroup{{
				Members:  []string{"oidc/groups:sigp:core/devs", "oidc/user:Alice@Example.org", "oidc/realm_access.roles:Ops", "oidc/user:https://idp.example/u/1"},
				Services: []string{"dora"},
			}}},
			"",
		},
		{
			"the section key in another case is still the section",
			"\nGrants:\n  - members: [\"oidc/team:panda\"]\n    services: [all]\n",
			&issuer.GrantsConfig{Groups: []issuer.GrantGroup{{Members: []string{"oidc/team:panda"}, Services: []string{"all"}}}},
			"",
		},
		{
			"each provider type with an attribute member",
			group(`"oidc/groups:x", "cfaccess/principal:user", "cfaccess/custom.dept:eng", "github/orgs:sigp", "github/login:octocat", "htpasswd/username:alice", "anyauth/username:bob"`),
			&issuer.GrantsConfig{Groups: []issuer.GrantGroup{{
				Members:  []string{"oidc/groups:x", "cfaccess/principal:user", "cfaccess/custom.dept:eng", "github/orgs:sigp", "github/login:octocat", "htpasswd/username:alice", "anyauth/username:bob"},
				Services: []string{"dora"},
			}}},
			"",
		},

		// ─── shape ──────────────────────────────────────────────────────
		{"null section", "\ngrants:\n", nil, "grants: must be a list of groups"},
		{"an empty map", "\ngrants: {}\n", nil, "grants: must be a list of groups"},
		{"a string", "\ngrants: all\n", nil, "grants: must be a list of groups"},
		{"the old shape: teams", "\ngrants:\n  teams:\n    panda: [all]\n", nil, "grants: the keys everyone / teams / users are gone"},
		{"the old shape: everyone", "\ngrants:\n  everyone: []\n", nil, "the keys everyone / teams / users are gone"},
		{"the old shape: users", "\ngrants:\n  users:\n    alice: [all]\n", nil, `a member names its provider: "<provider>/team:<team>", "<provider>/user:<id>" or "<provider>/<attribute>:<value>"`},
		{"a group that is a string", "\ngrants:\n  - panda\n", nil, "grants[0]: must be a group"},
		{"a group that is a list", "\ngrants:\n  - [a, b]\n", nil, "grants[0]: must be a group"},
		{"an unknown key in a group", "\ngrants:\n  - members: [\"oidc/team:panda\"]\n    services: [all]\n    teams: [x]\n", nil, `grants[0]: unknown key "teams" (the keys of a group are name, members and services)`},
		{"a misspelled key in the second group", "\ngrants:\n  - members: [\"oidc/team:panda\"]\n    services: []\n  - member: [\"oidc/team:geth\"]\n    services: []\n", nil, `grants[1]: unknown key "member"`},
		{"service instead of services", "\ngrants:\n  - members: [\"oidc/team:panda\"]\n    service: [all]\n", nil, `grants[0]: unknown key "service"`},
		{"members missing", "\ngrants:\n  - services: [all]\n", nil, "grants[0]: members is required"},
		{"services missing", "\ngrants:\n  - members: [\"oidc/team:panda\"]\n", nil, "grants[0]: services is required (use [] for a group that grants nothing)"},
		{"members is a string", "\ngrants:\n  - members: \"oidc/team:panda\"\n    services: [all]\n", nil, "grants[0].members: must be a list"},
		{"members is a map", "\ngrants:\n  - members:\n      oidc: panda\n    services: [all]\n", nil, "grants[0].members: must be a list"},
		{"members is null", "\ngrants:\n  - members:\n    services: [all]\n", nil, "grants[0].members: must be a list"},
		{"members is empty", "\ngrants:\n  - members: []\n    services: [all]\n", nil, "grants[0]: members must list at least one member"},
		{"a nested member", "\ngrants:\n  - members: [[\"oidc/team:panda\"]]\n    services: [all]\n", nil, "grants[0].members: list entries must be plain values"},
		{"services is a string", "\ngrants:\n  - members: [\"oidc/team:panda\"]\n    services: all\n", nil, "grants[0].services: must be a list"},
		{"services is null", "\ngrants:\n  - members: [\"oidc/team:panda\"]\n    services:\n", nil, "grants[0].services: must be a list"},
		{"name is a list", "\ngrants:\n  - name: [staff]\n    members: [\"oidc/team:panda\"]\n    services: []\n", nil, "grants[0].name: must be a non-empty text"},
		{"name is empty", "\ngrants:\n  - name: \"\"\n    members: [\"oidc/team:panda\"]\n    services: []\n", nil, "grants[0].name: must be a non-empty text"},
		{"a name used twice", "\ngrants:\n  - name: staff\n    members: [\"oidc/team:panda\"]\n    services: []\n  - name: staff\n    members: [\"oidc/team:geth\"]\n    services: []\n", nil, `grants[1]: the name "staff" is already used by grants[0]`},
		{"a key twice in two spellings", "\ngrants:\n  - members: [\"oidc/team:panda\"]\n    Members: [\"oidc/team:geth\"]\n    services: []\n", nil, `keys "members" and "Members" in grants[0] are the same key`},

		// ─── members ────────────────────────────────────────────────────
		{"a bare team", group(`panda`), nil, `grants[0]: members: "panda": no provider`},
		{"an unknown provider", group(`"gitlab/team:panda"`), nil, `no provider named "gitlab" (configured: [cfaccess, oidc, github, htpasswd, anyauth])`},
		{"a capitalised provider", group(`"OIDC/team:x"`), nil, `no provider named "OIDC" — did you mean "oidc"?`},
		{"an uppercase team", group(`"oidc/team:Panda"`), nil, `"Panda" is not a team name`},
		{"an attribute the provider type cannot have: github", group(`"github/groups:sigp"`), nil, `the provider type github has no attribute "groups"`},
		{"an attribute the provider type cannot have: basic", group(`"htpasswd/email:a@b"`), nil, `the provider type basic has no attribute "email"`},
		{"an attribute the provider type cannot have: any", group(`"anyauth/groups:x"`), nil, `the provider type any has no attribute "groups"`},
		{"an attribute the provider type cannot have: cloudflare", group(`"cfaccess/groups:staff"`), nil, `the provider type cloudflare has no attribute "groups"`},
		{"an empty value", group(`"oidc/groups:"`), nil, `the value after "groups:" is empty`},
		{"an empty attribute", group(`"oidc/:x"`), nil, `the attribute before the ":" is empty`},
		{"a wildcard", group(`"oidc/groups:team:*"`), nil, "there are no wildcards"},
		{"the same member twice", group(`"oidc/team:panda", "oidc/team:panda"`), nil, "are the same member; list it once"},
		{"the same member twice by case", group(`"oidc/groups:Staff", "oidc/groups:staff"`), nil, `"oidc/groups:Staff" and "oidc/groups:staff" are the same member`},

		// ─── grants ─────────────────────────────────────────────────────
		{"an invalid service name", "\ngrants:\n  - members: [\"oidc/team:panda\"]\n    services: [\"do ra\"]\n", nil, `grants[0]: services: invalid service name "do ra"`},
		{"a denied service", "\ngrants:\n  - name: lh\n    members: [\"oidc/team:lighthouse\"]\n    services: [\"-spamoor\"]\n", nil, `grants[0] (lh): services: invalid grant "-spamoor": a grant cannot deny`},
		{"the denial error says why", "\ngrants:\n  - members: [\"oidc/team:panda\"]\n    services: [\"dora:-roll\"]\n", nil, "would depend on the order"},
		{"a misplaced wildcard", "\ngrants:\n  - members: [\"oidc/team:panda\"]\n    services: [\"spamoor:us*er\"]\n", nil, `invalid feature "us*er" in grant "spamoor:us*er": "*" is a prefix wildcard`},

		// ─── the removed section ────────────────────────────────────────
		{"teamServices is gone", "\nteamServices:\n  panda: [all]\n", nil, `teamServices: this section was replaced by "grants"`},
		{"teamServices in another case", "\nTEAMSERVICES:\n  panda: [all]\n", nil, `this section was replaced by "grants"`},
		{"a null teamServices", "\nteamServices:\n", nil, `this section was replaced by "grants"`},
		{"teamServices next to grants", "\ngrants: []\nteamServices:\n  panda: [all]\n", nil, `this section was replaced by "grants"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Load(writeTempConfig(t, teamsConfigHeader+providers+tc.body))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("load: got %v, want an error containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			if (cfg.Grants == nil) != (tc.want == nil) {
				t.Fatalf("presence: got %+v, want %+v", cfg.Grants, tc.want)
			}
			if tc.want == nil {
				return
			}
			if len(cfg.Grants.Groups) != len(tc.want.Groups) {
				t.Fatalf("groups: got %+v, want %+v", cfg.Grants.Groups, tc.want.Groups)
			}
			for i, want := range tc.want.Groups {
				got := cfg.Grants.Groups[i]
				if got.Name != want.Name || !slices.Equal(got.Members, want.Members) || !slices.Equal(got.Services, want.Services) {
					t.Errorf("group %d: got %+v, want %+v", i, got, want)
				}
			}
		})
	}
}

// TestConfig_ServicesUngated covers the condition behind the startup
// warning about tokens valid for every service.
func TestConfig_ServicesUngated(t *testing.T) {
	cf := ProviderConfig{Name: "cfaccess", Type: AuthModeCloudflare}
	cfTeams := cf
	cfTeams.CloudflareAccess.Teams = []string{"panda"}
	oidcPlain := ProviderConfig{Name: "oidc", Type: AuthModeOIDC}
	oidcPrefix := oidcPlain
	oidcPrefix.OIDC.TeamRules = []protection.TeamRule{{Claim: "groups", Prefix: "team:"}}
	oidcMap := oidcPlain
	oidcMap.OIDC.TeamRules = []protection.TeamRule{{Claim: "groups", Map: map[string][]string{"ethpandaops": {"panda"}}}}
	ghMap := ProviderConfig{Name: "github", Type: AuthModeGitHub}
	ghMap.GitHubOAuth.TeamRules = []protection.TeamRule{{Claim: "orgs", Map: map[string][]string{"sigp": {"lighthouse"}}}}
	// A block of another type does not count.
	cfOtherBlock := cf
	cfOtherBlock.OIDC.TeamRules = []protection.TeamRule{{Claim: "groups", Value: true}}
	basicTeams := ProviderConfig{Name: "htpasswd", Type: AuthModeBasic}
	basicTeams.BasicAuth.Teams = []string{"ops"}
	anyTeams := ProviderConfig{Name: "anyauth", Type: AuthModeAny}
	anyTeams.AnyAuth.Teams = []string{"dev"}

	tests := []struct {
		name      string
		providers []ProviderConfig
		grants    *issuer.GrantsConfig
		want      bool
	}{
		{"one provider, no teams", []ProviderConfig{cf}, nil, false},
		{"one provider, team rules in an unused block", []ProviderConfig{cfOtherBlock}, nil, false},
		{"one oidc provider, no teams", []ProviderConfig{oidcPlain}, nil, false},
		{"one provider with static teams", []ProviderConfig{cfTeams}, nil, true},
		{"oidc prefix rule", []ProviderConfig{oidcPrefix}, nil, true},
		{"oidc map rule", []ProviderConfig{oidcMap}, nil, true},
		{"github map rule", []ProviderConfig{ghMap}, nil, true},
		{"basic teams", []ProviderConfig{basicTeams}, nil, true},
		{"any teams", []ProviderConfig{anyTeams}, nil, true},
		{"two providers, no teams", []ProviderConfig{cf, oidcPlain}, nil, true},
		{"two providers, grants configured", []ProviderConfig{cfTeams, oidcPrefix}, &issuer.GrantsConfig{Groups: []issuer.GrantGroup{{Members: []string{"cfaccess/team:panda"}, Services: []string{"all"}}}}, false},
		{"grants configured but empty", []ProviderConfig{cfTeams, oidcPrefix}, &issuer.GrantsConfig{}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{Providers: tc.providers, Grants: tc.grants}
			if got := cfg.ServicesUngated(); got != tc.want {
				t.Errorf("ServicesUngated() = %t, want %t", got, tc.want)
			}
		})
	}
}

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

// TestLoad_ConfigTeamNamesAreNotFolded: a team name written in the
// config has to be in normal form. An uppercase or padded name is an
// error, not another spelling of the lowercase one.
func TestLoad_ConfigTeamNamesAreNotFolded(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr string
	}{
		{"static teams", "cloudflareAccess:\n  teamDomain: \"t.example\"\n  teams: [Panda]\n", `cloudflareAccess.teams: invalid team name(s) ["Panda"]`},
		{"static teams, padded", "cloudflareAccess:\n  teamDomain: \"t.example\"\n  teams: [\"panda \"]\n", `invalid team name(s) ["panda "]`},
		{"a rule map value", "authMode: any\nanyAuth:\n  teamRules:\n    - claim: username\n      map: { alice: [Lighthouse] }\n", `map key "alice": invalid team name(s) ["Lighthouse"]`},
		{"a team member of a grants group", "authMode: any\ngrants:\n  - members: [\"anyauth/team:Panda\"]\n    services: [all]\n", `"Panda" is not a team name`},
		{"the hint", "authMode: any\nanyAuth:\n  teams: [PANDA]\n", "write them lowercase"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(writeTempConfig(t, teamsConfigHeader+tc.body))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("load: got %v, want an error containing %q", err, tc.wantErr)
			}
		})
	}
}

// TestLoad_DocsDevnetExample loads the complete example of
// docs/config.md as it is printed there (placeholders filled in), so
// the documented config cannot drift from what the loader accepts.
func TestLoad_DocsDevnetExample(t *testing.T) {
	doc, err := os.ReadFile("../../docs/config.md")
	if err != nil {
		t.Fatalf("read docs: %v", err)
	}
	_, rest, found := strings.Cut(string(doc), "### A complete devnet")
	if !found {
		t.Fatal("docs/config.md has no \"A complete devnet\" section")
	}
	_, rest, found = strings.Cut(rest, "```yaml\n")
	if !found {
		t.Fatal("the section has no yaml block")
	}
	example, _, _ := strings.Cut(rest, "```")
	example = strings.NewReplacer(
		"<devnet>", "devnet-1", "<team>", "ethpandaops",
		"<central-idp>", "idp.example.org", "<oidc-relay>", "relay.example.org",
	).Replace(example)

	cfg, err := Load(writeTempConfig(t, example))
	if err != nil {
		t.Fatalf("load: %v\n%s", err, example)
	}
	if len(cfg.Warnings) != 0 {
		t.Errorf("warnings: %v", cfg.Warnings)
	}
	if got := cfg.ProviderNames(); !slices.Equal(got, []string{"cfaccess", "oidc"}) {
		t.Errorf("providers: %v", got)
	}
	cf, oc := cfg.Providers[0].CloudflareAccess, cfg.Providers[1].OIDC
	if len(cf.TeamRules) != 1 || cf.TeamRules[0].Claim != "principal" || !slices.Equal(cf.TeamRules[0].Map["user"], []string{"panda"}) {
		t.Errorf("cloudflare rules: %+v", cf.TeamRules)
	}
	if cf.AudTag == "" {
		t.Error("the example's Cloudflare door has no audTag")
	}
	if len(oc.TeamRules) != 2 || oc.TeamRules[0].Prefix != "team:" ||
		!slices.Equal(oc.TeamRules[1].Map["carol@example.org"], []string{"geth"}) {
		t.Errorf("oidc rules: %+v", oc.TeamRules)
	}
	if cfg.Grants == nil || len(cfg.Grants.Groups) != 4 {
		t.Fatalf("grants: %+v", cfg.Grants)
	}
	staff := cfg.Grants.Groups[0]
	if staff.Name != "staff" || !slices.Equal(staff.Members, []string{"cfaccess/team:panda", "oidc/team:ethpandaops"}) ||
		!slices.Equal(staff.Services, []string{"all:all"}) {
		t.Errorf("staff group: %+v", staff)
	}
	if internal := cfg.Grants.Groups[1]; !slices.Equal(internal.Members, []string{"oidc/groups:panda-access"}) {
		t.Errorf("internal-tooling group: %+v", internal)
	}
	if cfg.ServicesUngated() {
		t.Error("the example must not be an ungated instance")
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

// TestLoad_CloudflareWithoutAudTag: a Cloudflare door without audTag
// accepts, on /auth/*, an assertion issued for any Access application
// of the team. Released versions did, and deployments rely on it, so
// such a door may give teams and be named in grants — but the operator
// is told, once per provider, that the door is shared by all those
// applications.
func TestLoad_CloudflareWithoutAudTag(t *testing.T) {
	door := func(extra string) string {
		return "providers:\n  - name: cfaccess\n    type: cloudflare\n    cloudflareAccess:\n      teamDomain: \"t.cloudflareaccess.com\"\n" + extra +
			"  - name: oidc\n    type: oidc\n    oidc:\n      issuerURL: \"https://idp.example.com\"\n      callbackURL: \"https://auth.demo.example.com/oidc/callback\"\n      clientId: \"id\"\n      clientSecret: \"secret\"\n      trustUnverifiedEmail: false\n"
	}
	grants := func(member string) string {
		return "grants:\n  - members: [\"" + member + "\"]\n    services: [all]\n"
	}
	const (
		audTag = "      audTag: \"0123456789abcdef\"\n"
		rules  = "      teamRules:\n        - claim: principal\n          map: { user: [panda] }\n"
	)

	tests := []struct {
		name string
		body string
		env  string   // AUTHENTICATOOR_CLOUDFLAREACCESS_AUDTAG
		want []string // parts of the one warning; nil: no warning
	}{
		{"no teams, no grants", door(""), "", nil},
		{"static teams", door("      teams: [panda]\n"), "", []string{`provider "cfaccess" gives teams to the identities it authenticates`}},
		{"team rules", door(rules), "", []string{"gives teams to the identities it authenticates"}},
		{"a team member in grants", door("") + grants("cfaccess/team:panda"), "", []string{`provider "cfaccess" is named in grants members`}},
		{"a user member in grants", door("") + grants("cfaccess/user:alice@example.org"), "", []string{"is named in grants members"}},
		{"an attribute member in grants", door("") + grants("cfaccess/principal:user"), "", []string{"is named in grants members"}},
		{
			"teams and grants: still one warning, and it says what follows",
			door(rules) + grants("cfaccess/team:panda"), "",
			[]string{
				"gives teams to the identities it authenticates and is named in grants members",
				"cloudflareAccess.audTag is not set",
				"any Access application of the Cloudflare team t.cloudflareaccess.com",
				"the teams and grants of this door apply to everyone admitted to any of them",
			},
		},
		{"grants naming only the other provider", door("") + grants("oidc/team:panda"), "", nil},
		{"static teams with audTag", door(audTag + "      teams: [panda]\n"), "", nil},
		{"rules and grants with audTag", door(audTag+rules) + grants("cfaccess/team:panda"), "", nil},
		{"verifyJWT off: no assertion is checked at all", door("      verifyJWT: false\n      teams: [panda]\n") + grants("cfaccess/team:panda"), "", nil},
		{
			"the legacy top-level block",
			"cloudflareAccess:\n  teamDomain: \"t.cloudflareaccess.com\"\n  teams: [panda]\n", "",
			[]string{`provider "cfaccess" gives teams`},
		},
		{
			"the legacy block with audTag",
			"cloudflareAccess:\n  teamDomain: \"t.cloudflareaccess.com\"\n  audTag: \"aud\"\n  teams: [panda]\n", "", nil,
		},
		{
			"the legacy block with audTag from the environment",
			"cloudflareAccess:\n  teamDomain: \"t.cloudflareaccess.com\"\n  teams: [panda]\n", "aud-from-env", nil,
		},
		{
			"the legacy block with teams from the environment",
			"cloudflareAccess:\n  teamDomain: \"t.cloudflareaccess.com\"\n", "",
			[]string{`provider "cfaccess" gives teams`},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.env != "" {
				t.Setenv("AUTHENTICATOOR_CLOUDFLAREACCESS_AUDTAG", tc.env)
			}
			if strings.Contains(tc.name, "teams from the environment") {
				t.Setenv("AUTHENTICATOOR_CLOUDFLAREACCESS_TEAMS", "panda")
			}
			cfg, err := Load(writeTempConfig(t, teamsConfigHeader+tc.body))
			if err != nil {
				t.Fatalf("a Cloudflare door without audTag must load: %v", err)
			}
			if tc.want == nil {
				if len(cfg.Warnings) != 0 {
					t.Fatalf("warnings: %v", cfg.Warnings)
				}
				return
			}
			if len(cfg.Warnings) != 1 {
				t.Fatalf("want one warning, got %v", cfg.Warnings)
			}
			for _, part := range tc.want {
				if !strings.Contains(cfg.Warnings[0], part) {
					t.Errorf("the warning lacks %q: %s", part, cfg.Warnings[0])
				}
			}
		})
	}
}

// TestLoad_SharedCloudflareDoorWithGrants is the deployed shape: an
// OIDC provider whose groups become teams next to a Cloudflare Access
// door without audTag, with staff granted everything through either.
// It loads, and a person and a service token coming through Cloudflare
// both get everything.
func TestLoad_SharedCloudflareDoorWithGrants(t *testing.T) {
	cfg, err := Load(writeTempConfig(t, teamsConfigHeader+`
providers:
  - name: authentik
    type: oidc
    oidc:
      issuerURL: "https://authentik.example.com/application/o/authenticatoor/"
      callbackURL: "https://auth.demo.example.com/authentik/callback"
      clientId: "id"
      clientSecret: "secret"
      teamRules:
        - claim: groups
          prefix: "team:"
  - name: cfaccess
    type: cloudflare
    cloudflareAccess:
      verifyJWT: true
      teamDomain: "ethpandaops.cloudflareaccess.com"
      audTag: ""
grants:
  - name: staff
    members:
      - "authentik/team:ethpandaops"
      - "cfaccess/principal:user"
      - "cfaccess/principal:service"
    services: ["all:all"]
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := cfg.ProviderNames(); !slices.Equal(got, []string{"authentik", "cfaccess"}) {
		t.Fatalf("providers: %v", got)
	}
	shared := 0
	for _, w := range cfg.Warnings {
		if strings.Contains(w, `provider "cfaccess" is named in grants members, but cloudflareAccess.audTag is not set`) {
			shared++
		}
	}
	if shared != 1 {
		t.Errorf("want one warning about the shared Cloudflare door, got %v", cfg.Warnings)
	}

	grants, err := issuer.NewServiceGrants(*cfg.Grants, cfg.GrantProviders())
	if err != nil {
		t.Fatalf("grants: %v", err)
	}
	want := []protection.AttributeMember{
		{Attribute: "principal", Value: "user"}, {Attribute: "principal", Value: "service"},
	}
	if got := grants.AttributeMembers("cfaccess"); !slices.Equal(got, want) {
		t.Fatalf("what the Cloudflare provider is told to look for: %v", got)
	}

	// The identities as the Cloudflare provider builds them from these
	// members (see the provider's own test for that half).
	members := protection.NewMembers(grants.AttributeMembers("cfaccess"))
	const all = "+all,+all:all"
	user := issuer.Identity{
		Subject: "alice@example.org", Email: "alice@example.org", SubjectIsEmail: true, Provider: "cfaccess",
		Matches: members.ForRequest(protection.Attributes{"principal": "user", "email": "alice@example.org"}),
	}
	if got := grants.Directive(user, ""); got != all {
		t.Errorf("a Cloudflare user: %q, want %q", got, all)
	}
	service := issuer.Identity{
		Subject: "0123456789abcdef.access", Provider: "cfaccess",
		Matches: members.ForRequest(protection.Attributes{"principal": "service", "common_name": "0123456789abcdef.access"}),
	}
	if got := grants.Directive(service, ""); got != all {
		t.Errorf("a Cloudflare service token: %q, want %q", got, all)
	}
	staff := issuer.Identity{Subject: "sub-1", Teams: []string{"ethpandaops"}, Provider: "authentik"}
	if got := grants.Directive(staff, ""); got != all {
		t.Errorf("staff through the IdP: %q, want %q", got, all)
	}
	// And nobody else: the same team through the wrong door, an IdP
	// user without the team.
	for _, id := range []issuer.Identity{
		{Subject: "sub-2", Teams: []string{"lighthouse"}, Provider: "authentik"},
		{Subject: "x@example.org", Email: "x@example.org", Teams: []string{"ethpandaops"}, Provider: "cfaccess"},
	} {
		if got := grants.Directive(id, ""); got != "-all" {
			t.Errorf("%+v: %q, want -all", id, got)
		}
	}
}

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

// TestLoad_GrantsEnvVars: grants are read from the config file only. An
// environment variable that looks like it configures them would be
// ignored — with no grants in the file the instance would run ungated —
// so it is a startup error, in every spelling viper would map.
func TestLoad_GrantsEnvVars(t *testing.T) {
	body := teamsConfigHeader + "cloudflareAccess:\n  teamDomain: \"t.cloudflareaccess.com\"\n"

	refused := []string{
		"AUTHENTICATOOR_GRANTS",
		"AUTHENTICATOOR_GRANTS_0_MEMBERS",
		"AUTHENTICATOOR_GRANTS_0_SERVICES",
		"AUTHENTICATOOR_GRANTS_STAFF",
		"AUTHENTICATOOR_TEAMSERVICES",
		"AUTHENTICATOOR_TEAMSERVICES_PANDA",
	}
	for _, name := range refused {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "cfaccess/team:panda")
			_, err := Load(writeTempConfig(t, body))
			if err == nil || !strings.Contains(err.Error(), "environment variable "+name) ||
				!strings.Contains(err.Error(), "read from the YAML config file only") {
				t.Fatalf("load: got %v", err)
			}
		})
	}

	// Case does not matter: the check sees what viper would map.
	if err := checkGrantsEnv("AUTHENTICATOOR", []string{"Authenticatoor_Grants_0_members=x"}); err == nil {
		t.Error("a mixed-case variable was not refused")
	}

	// Variables that merely start alike, and every real override, pass.
	for _, name := range []string{"AUTHENTICATOOR_GRANTSFOO", "AUTHENTICATOOR_LISTEN", "GRANTS", "OTHER_GRANTS", "AUTHENTICATOOR_OIDC_CLIENTSECRET"} {
		t.Setenv(name, "x")
	}
	t.Setenv("AUTHENTICATOOR_LISTEN", ":9999")
	cfg, err := Load(writeTempConfig(t, body))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Listen != ":9999" || cfg.Grants != nil {
		t.Errorf("listen=%q grants=%+v", cfg.Listen, cfg.Grants)
	}
}
