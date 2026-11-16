package config

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
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
	if got, err := grants.Directive(user, ""); err != nil || got != all {
		t.Errorf("a Cloudflare user: %q, want %q", got, all)
	}
	service := issuer.Identity{
		Subject: "0123456789abcdef.access", Provider: "cfaccess",
		Matches: members.ForRequest(protection.Attributes{"principal": "service", "common_name": "0123456789abcdef.access"}),
	}
	if got, err := grants.Directive(service, ""); err != nil || got != all {
		t.Errorf("a Cloudflare service token: %q, want %q", got, all)
	}
	staff := issuer.Identity{Subject: "sub-1", Teams: []string{"ethpandaops"}, Provider: "authentik"}
	if got, err := grants.Directive(staff, ""); err != nil || got != all {
		t.Errorf("staff through the IdP: %q, want %q", got, all)
	}
	// And nobody else: the same team through the wrong door, an IdP
	// user without the team.
	for _, id := range []issuer.Identity{
		{Subject: "sub-2", Teams: []string{"lighthouse"}, Provider: "authentik"},
		{Subject: "x@example.org", Email: "x@example.org", Teams: []string{"ethpandaops"}, Provider: "cfaccess"},
	} {
		if got, err := grants.Directive(id, ""); !errors.Is(err, issuer.ErrNotGranted) {
			t.Errorf("%+v: %q, %v, want ErrNotGranted (no token)", id, got, err)
		}
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

// oidcEntry is a providers list with one oidc entry; the test appends
// the keys of its oidc block.
const oidcEntry = teamsConfigHeader + `
providers:
  - name: corp
    type: oidc
    oidc:
      issuerURL: "https://idp.example.org"
      callbackURL: "https://auth.demo.example.com/corp/callback"
      clientId: "authenticatoor"
      clientSecret: "secret"
`

// legacyOIDC is the same provider as a legacy top-level block.
const legacyOIDC = teamsConfigHeader + `
authMode: oidc
oidc:
  issuerURL: "https://idp.example.org"
  callbackURL: "https://auth.demo.example.com/oidc/callback"
  clientId: "authenticatoor"
  clientSecret: "secret"
`

// TestLoad_OIDCBearer: the oidc.bearer block is off when absent, and on
// with its audiences (and optional issuer) when present.
func TestLoad_OIDCBearer(t *testing.T) {
	cfg, err := Load(writeTempConfig(t, oidcEntry))
	if err != nil {
		t.Fatalf("load without the block: %v", err)
	}
	if b := cfg.Providers[0].OIDC.Bearer; b.Enabled() || b.IssuerURL != "" {
		t.Errorf("without the block: %+v", b)
	}

	cfg, err = Load(writeTempConfig(t, oidcEntry+
		"      bearer:\n        audiences: [\"devnet-cli\", \"authenticatoor\"]\n"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	b := cfg.Providers[0].OIDC.Bearer
	if !b.Enabled() || !slices.Equal(b.Audiences, []string{"devnet-cli", "authenticatoor"}) || b.IssuerURL != "" {
		t.Errorf("bearer: %+v", b)
	}

	// A client id that looks like a number, written as a string; an
	// issuer over plain http (the scheme is the operator's choice, as
	// for oidc.issuerURL).
	cfg, err = Load(writeTempConfig(t, oidcEntry+
		"      bearer:\n        audiences: [\"123\", 'true', devnet-cli]\n        issuerURL: \"http://idp.internal:9000/cli\"\n"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	b = cfg.Providers[0].OIDC.Bearer
	if !slices.Equal(b.Audiences, []string{"123", "true", "devnet-cli"}) || b.IssuerURL != "http://idp.internal:9000/cli" {
		t.Errorf("bearer: %+v", b)
	}

	// The environment form switches the feature on for the legacy
	// top-level block.
	t.Run("environment", func(t *testing.T) {
		t.Setenv("AUTHENTICATOOR_OIDC_BEARER_AUDIENCES", "devnet-cli,other-cli")
		cfg, err := Load(writeTempConfig(t, legacyOIDC))
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		if b := cfg.Providers[0].OIDC.Bearer; !slices.Equal(b.Audiences, []string{"devnet-cli", "other-cli"}) {
			t.Errorf("bearer from the environment: %+v", b)
		}
	})

	cfg, err = Load(writeTempConfig(t, legacyOIDC+
		"  bearer:\n    audiences:\n      - devnet-cli\n    issuerURL: \"https://idp.example.org/application/o/cli/\"\n"))
	if err != nil {
		t.Fatalf("load legacy: %v", err)
	}
	b = cfg.Providers[0].OIDC.Bearer
	if !slices.Equal(b.Audiences, []string{"devnet-cli"}) || b.IssuerURL != "https://idp.example.org/application/o/cli/" {
		t.Errorf("legacy bearer: %+v", b)
	}
}

// TestLoad_OIDCBearer_Errors: a block that is written down and does not
// say exactly whose tokens are accepted is a startup error — never
// "off", and never a guess.
func TestLoad_OIDCBearer_Errors(t *testing.T) {
	tests := []struct {
		name string
		body string // appended to the oidc block of the providers entry
		want string
	}{
		{"empty block", "      bearer:\n", "providers[0].oidc.bearer: is empty"},
		{"empty audiences", "      bearer:\n        audiences: []\n", "providers[0].oidc.bearer.audiences: must be a non-empty list"},
		{"audiences is a single value", "      bearer:\n        audiences: devnet-cli\n", "providers[0].oidc.bearer.audiences: must be a non-empty list"},
		{"empty audience", "      bearer:\n        audiences: [\"devnet-cli\", \"\"]\n", "providers[0].oidc.bearer.audiences[1]: must be a non-empty string"},
		{"audiences are a number and a boolean", "      bearer:\n        audiences: [123, true]\n", "providers[0].oidc.bearer.audiences[0]: must be a non-empty string, not int (123)"},
		{"blank audience", "      bearer:\n        audiences: [\" \"]\n", "oidc.bearer.audiences[0]"},
		{"issuer is not a URL", "      bearer:\n        audiences: [devnet-cli]\n        issuerURL: \"http://[::1\"\n", "oidc.bearer.issuerURL"},
		{"issuer without a scheme", "      bearer:\n        audiences: [devnet-cli]\n        issuerURL: \"idp.example.org/cli\"\n", "oidc.bearer.issuerURL: \"idp.example.org/cli\" must be an http or https URL"},
		{"issuer without a host", "      bearer:\n        audiences: [devnet-cli]\n        issuerURL: \"https:///cli\"\n", "oidc.bearer.issuerURL: \"https:///cli\" has no host"},
		{"duplicate audience", "      bearer:\n        audiences: [\"devnet-cli\", \"devnet-cli\"]\n", `"devnet-cli" is listed twice`},
		{"unknown key", "      bearer:\n        audiences: [\"devnet-cli\"]\n        issuer: \"https://idp.example.org\"\n", `providers[0].oidc.bearer: unknown key "issuer"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			wantLoadError(t, writeTempConfig(t, oidcEntry+tc.body), tc.want)
		})
	}

	t.Run("legacy block", func(t *testing.T) {
		wantLoadError(t, writeTempConfig(t, legacyOIDC+"  bearer:\n    issuerURL: \"https://idp.example.org/cli\"\n"),
			"oidc.bearer.audiences: must be a non-empty list")
	})
	// Through the environment there is no block to look at: an issuer
	// without audiences is caught by the validation.
	t.Run("environment", func(t *testing.T) {
		t.Setenv("AUTHENTICATOOR_OIDC_BEARER_ISSUERURL", "https://idp.example.org/cli")
		wantLoadError(t, writeTempConfig(t, legacyOIDC), "oidc.bearer.audiences is required")
	})
}

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

// TestLoad_ConfigsOfReleasedVersions: every config under testdata/compat
// loads and resolves as it did before (see the comment on the fixtures
// above).
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
