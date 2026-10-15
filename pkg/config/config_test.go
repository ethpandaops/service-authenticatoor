package config

import (
	"os"
	"path/filepath"
	"testing"
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
