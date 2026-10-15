// Package config loads, validates, and applies derivation rules to the
// authenticatoor service configuration.
//
// Configuration is sourced from a YAML file (path supplied via --config) and
// optionally overridden by environment variables prefixed with
// AUTHENTICATOOR_*. Values omitted from the file are derived from the
// canonical issuer URL where reasonable, so a minimal config is just six
// lines (see config.example.yaml).
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// AuthMode names a protection provider type. Providers are configured
// via the providers list; the legacy top-level authMode field promotes
// to a single-entry list.
const (
	AuthModeCloudflare = "cloudflare"
	AuthModeBasic      = "basic"
	AuthModeAny        = "any"
	AuthModeGitHub     = "github"
	AuthModeOIDC       = "oidc"
)

// legacyProviderNames maps a provider type to the instance name used
// when converting the legacy top-level blocks (authMode naming types)
// into providers entries. Explicit providers entries must set their own
// name. The name doubles as the provider's path prefix: /<name>/login,
// /<name>/callback, /<name>/token.
var legacyProviderNames = map[string]string{
	AuthModeCloudflare: "cfaccess",
	AuthModeBasic:      "htpasswd",
	AuthModeAny:        "anyauth",
	AuthModeGitHub:     "github",
	AuthModeOIDC:       "oidc",
}

// reservedProviderNames are path segments already claimed by the server's
// own routes; a provider name colliding with one would shadow them.
var reservedProviderNames = map[string]struct{}{
	"auth":        {},
	"login":       {},
	"healthz":     {},
	"clientFrame": {},
	"metrics":     {},
	"cdn-cgi":     {},
}

// Config is the resolved, validated, derivation-applied configuration of the
// authenticatoor service.
type Config struct {
	Listen      string `yaml:"listen" mapstructure:"listen"`
	Issuer      string `yaml:"issuer" mapstructure:"issuer"`
	ExternalURL string `yaml:"externalURL" mapstructure:"externalURL"`

	// AuthMode names the provider(s) actively advertised to
	// unauthenticated users — a single string or a list (viper also
	// accepts a comma-separated env value). With one entry,
	// unauthenticated /auth/* requests go straight into that provider's
	// login flow; with several, they land on the /login provider
	// selection page listing exactly these entries. ALL defined
	// providers stay enabled regardless — they authenticate in the
	// passive chain and their login routes remain reachable directly;
	// authMode only controls what is advertised. Entries reference
	// providers-list entries by name. When the providers list is empty,
	// each entry instead names a provider type whose legacy top-level
	// block is converted into a providers entry. Defaults to all
	// configured providers (or "cloudflare" when nothing is configured
	// at all).
	AuthMode []string `yaml:"authMode" mapstructure:"authMode"`

	// Providers configures the protection provider instances gating
	// /auth/*. Each entry mounts its interactive routes under its own
	// path prefix ("/<name>/login", ...). This is the canonical form;
	// when empty, entries are converted from the authMode field and the
	// legacy top-level provider blocks below.
	Providers []ProviderConfig `yaml:"providers" mapstructure:"providers"`

	// DevMode disables production optimizations for local development:
	// the client scripts are served unminified (readable as-is, so no
	// source maps are generated or served).
	DevMode bool `yaml:"devMode" mapstructure:"devMode"`

	Audience     []string      `yaml:"audience" mapstructure:"audience"`
	ScopePattern string        `yaml:"scopePattern" mapstructure:"scopePattern"`
	TokenTTL     time.Duration `yaml:"tokenTTL" mapstructure:"tokenTTL"`

	// UserHeader is a deprecated alias for cloudflareAccess.userHeader.
	// When the latter is unset, this value is folded in by applyDerived.
	UserHeader         string   `yaml:"userHeader" mapstructure:"userHeader"`
	AllowedReturnHosts []string `yaml:"allowedReturnHosts" mapstructure:"allowedReturnHosts"`

	CloudflareAccess CloudflareAccessConfig `yaml:"cloudflareAccess" mapstructure:"cloudflareAccess"`
	BasicAuth        BasicAuthConfig        `yaml:"basicAuth" mapstructure:"basicAuth"`
	AnyAuth          AnyAuthConfig          `yaml:"anyAuth" mapstructure:"anyAuth"`
	GitHubOAuth      GitHubOAuthConfig      `yaml:"githubOAuth" mapstructure:"githubOAuth"`
	OIDC             OIDCConfig             `yaml:"oidc" mapstructure:"oidc"`
	CORS             CORSConfig             `yaml:"cors" mapstructure:"cors"`
	Signing          SigningConfig          `yaml:"signing" mapstructure:"signing"`
	Logging          LoggingConfig          `yaml:"logging" mapstructure:"logging"`
	Metrics          MetricsConfig          `yaml:"metrics" mapstructure:"metrics"`

	// DeprecationWarnings collects messages about deprecated config
	// fields encountered during Load. The entrypoint logs each at
	// startup; tests can inspect this slice directly.
	DeprecationWarnings []string `yaml:"-" mapstructure:"-"`
}

// ProviderConfig configures one protection provider instance. Exactly
// the block matching Type is read; the others are ignored.
type ProviderConfig struct {
	// Name is the instance name, used as the path prefix for the
	// provider's routes (/<name>/login, /<name>/callback, /<name>/token),
	// as the label on the provider selector page, and as the reference
	// key in authMode. Required; unique; lowercase [a-z0-9-].
	Name string `yaml:"name" mapstructure:"name"`
	// Type selects the provider implementation: cloudflare | basic |
	// any | github | oidc. Required.
	Type string `yaml:"type" mapstructure:"type"`

	CloudflareAccess CloudflareAccessConfig `yaml:"cloudflareAccess" mapstructure:"cloudflareAccess"`
	BasicAuth        BasicAuthConfig        `yaml:"basicAuth" mapstructure:"basicAuth"`
	AnyAuth          AnyAuthConfig          `yaml:"anyAuth" mapstructure:"anyAuth"`
	GitHubOAuth      GitHubOAuthConfig      `yaml:"githubOAuth" mapstructure:"githubOAuth"`
	OIDC             OIDCConfig             `yaml:"oidc" mapstructure:"oidc"`
}

// CloudflareAccessConfig configures the cloudflare protection provider.
// The two booleans are pointers so an entry in the providers list can
// distinguish "unset" (secure default: true) from an explicit false —
// viper defaults only reach the legacy top-level block, not list entries.
type CloudflareAccessConfig struct {
	VerifyJWT  *bool  `yaml:"verifyJWT" mapstructure:"verifyJWT"`
	TeamDomain string `yaml:"teamDomain" mapstructure:"teamDomain"`
	AudTag     string `yaml:"audTag" mapstructure:"audTag"`
	JwtHeader  string `yaml:"jwtHeader" mapstructure:"jwtHeader"`
	// UserHeader is the request header carrying the authenticated email.
	// Defaults to "Cf-Access-Authenticated-User-Email". This is the
	// canonical location; the top-level userHeader field is kept as a
	// deprecated alias.
	UserHeader string `yaml:"userHeader" mapstructure:"userHeader"`
	// AllowServiceTokens permits non-identity CF Access service tokens to
	// authenticate, using the token's common_name (client ID) as the
	// identity subject. Whether a service token can reach the app at all is
	// still gated by the app's CF Access policy. Defaults to true.
	AllowServiceTokens *bool `yaml:"allowServiceTokens" mapstructure:"allowServiceTokens"`
	// SessionCookieName overrides the session cookie name. Defaults to
	// "authenticatoor_<name>_session".
	SessionCookieName string `yaml:"sessionCookieName" mapstructure:"sessionCookieName"`
	// SessionTTL is the session cookie lifetime for logins minted at
	// the provider's login entry (/<name>/login). Defaults to "12h".
	SessionTTL time.Duration `yaml:"sessionTTL" mapstructure:"sessionTTL"`
}

// VerifyJWTEnabled reports the effective verifyJWT setting (unset = true).
func (c CloudflareAccessConfig) VerifyJWTEnabled() bool {
	return c.VerifyJWT == nil || *c.VerifyJWT
}

// ServiceTokensAllowed reports the effective allowServiceTokens setting
// (unset = true).
func (c CloudflareAccessConfig) ServiceTokensAllowed() bool {
	return c.AllowServiceTokens == nil || *c.AllowServiceTokens
}

// BasicAuthConfig configures the basic protection provider.
type BasicAuthConfig struct {
	// HtpasswdFile is the path to the htpasswd password file. Required
	// for basic providers.
	HtpasswdFile string `yaml:"htpasswdFile" mapstructure:"htpasswdFile"`
	// Realm is the value sent in WWW-Authenticate. Defaults to
	// "authenticatoor".
	Realm string `yaml:"realm" mapstructure:"realm"`
	// SessionCookieName overrides the session cookie name. Defaults to
	// "authenticatoor_<name>_session".
	SessionCookieName string `yaml:"sessionCookieName" mapstructure:"sessionCookieName"`
	// SessionTTL is the session cookie lifetime for logins minted at
	// the provider's login entry (/<name>/login). Defaults to "12h".
	SessionTTL time.Duration `yaml:"sessionTTL" mapstructure:"sessionTTL"`
}

// AnyAuthConfig configures the anyauth (dev-only) protection provider.
// All fields are optional; the provider falls back to sensible defaults.
type AnyAuthConfig struct {
	// CookieName overrides the username cookie name. Defaults to
	// "authenticatoor_anyauth_user".
	CookieName string `yaml:"cookieName" mapstructure:"cookieName"`
	// CookieTTL overrides the cookie lifetime. Defaults to "12h".
	CookieTTL time.Duration `yaml:"cookieTTL" mapstructure:"cookieTTL"`
}

// GitHubOAuthConfig configures the github protection provider.
type GitHubOAuthConfig struct {
	// ClientID is the OAuth app client_id. Required.
	ClientID string `yaml:"clientId" mapstructure:"clientId"`
	// ClientSecret takes precedence over ClientSecretFile when set
	// (typically via env-var injection). Either must be supplied.
	ClientSecret     string `yaml:"clientSecret" mapstructure:"clientSecret"`
	ClientSecretFile string `yaml:"clientSecretFile" mapstructure:"clientSecretFile"`

	// The session cookie HMAC key is derived from the JWT signing key
	// (see issuer.DeriveHMACKey), so there's no separate secret to
	// configure here.

	// CallbackPath is the path of the OAuth redirect URI registered
	// publicly. Defaults to "/<name>/callback".
	CallbackPath string `yaml:"callbackPath" mapstructure:"callbackPath"`
	// SessionCookieName is the name of the session cookie. Default
	// "authenticatoor_session".
	SessionCookieName string `yaml:"sessionCookieName" mapstructure:"sessionCookieName"`
	// StateCookieName is the name of the OAuth state cookie. Default
	// "authenticatoor_oauth_state".
	StateCookieName string `yaml:"stateCookieName" mapstructure:"stateCookieName"`
	// SessionTTL is the cookie lifetime. Default "12h".
	SessionTTL time.Duration `yaml:"sessionTTL" mapstructure:"sessionTTL"`
	// AllowedOrgs lists the GitHub orgs whose members may authenticate.
	// At least one is required. Comparison is case-insensitive.
	AllowedOrgs []string `yaml:"allowedOrgs" mapstructure:"allowedOrgs"`
}

// OIDCConfig configures the oidc protection provider.
type OIDCConfig struct {
	// IssuerURL is the IdP issuer (e.g. dex). The provider fetches
	// <IssuerURL>/.well-known/openid-configuration at startup to resolve
	// the authorize / token / jwks endpoints. Required.
	IssuerURL string `yaml:"issuerURL" mapstructure:"issuerURL"`
	// CallbackURL is the absolute URL registered at the IdP as this
	// client's redirect_uri. In a relay-fronted deployment that's the
	// relay's URL (shared across every authenticatoor instance); in a
	// direct deployment that's <externalURL>/oidc/callback. Required.
	CallbackURL string `yaml:"callbackURL" mapstructure:"callbackURL"`

	// ClientID is the OAuth client_id registered at the IdP. Required.
	ClientID string `yaml:"clientId" mapstructure:"clientId"`
	// ClientSecret takes precedence over ClientSecretFile when set.
	// Either must be supplied (the shared client is confidential, not
	// public).
	ClientSecret     string `yaml:"clientSecret" mapstructure:"clientSecret"`
	ClientSecretFile string `yaml:"clientSecretFile" mapstructure:"clientSecretFile"`

	// CallbackPath is the local path the relay forwards to. Defaults to
	// "/<name>/callback".
	CallbackPath string `yaml:"callbackPath" mapstructure:"callbackPath"`
	// SessionCookieName overrides the session cookie name. Default
	// "authenticatoor_oidc_session".
	SessionCookieName string `yaml:"sessionCookieName" mapstructure:"sessionCookieName"`
	// StateCookieName overrides the OAuth state cookie name. Default
	// "authenticatoor_oidc_state".
	StateCookieName string `yaml:"stateCookieName" mapstructure:"stateCookieName"`
	// SessionTTL is the session cookie lifetime. Default "12h".
	SessionTTL time.Duration `yaml:"sessionTTL" mapstructure:"sessionTTL"`

	// AllowedGroups lists groups (as emitted by the IdP) whose members
	// may authenticate. For dex's GitHub connector that's org names like
	// "ethpandaops" and (when teams are configured) "<org>:<team>".
	// Case-insensitive. At least one is required.
	AllowedGroups []string `yaml:"allowedGroups" mapstructure:"allowedGroups"`
	// Scopes overrides the OIDC scopes requested. Defaults to
	// ["openid", "email", "groups"]. `openid` is required.
	Scopes []string `yaml:"scopes" mapstructure:"scopes"`
}

// CORSConfig configures the CORS middleware.
type CORSConfig struct {
	AllowedOrigins []string `yaml:"allowedOrigins" mapstructure:"allowedOrigins"`
}

// SigningConfig configures the issuer's key material.
type SigningConfig struct {
	Mode  string          `yaml:"mode" mapstructure:"mode"`
	RS256 RS256SignConfig `yaml:"rs256" mapstructure:"rs256"`
}

// RS256SignConfig configures the RS256 issuer.
type RS256SignConfig struct {
	PrivateKeyFile    string        `yaml:"privateKeyFile" mapstructure:"privateKeyFile"`
	KeyID             string        `yaml:"keyId" mapstructure:"keyId"`
	GenerateIfMissing bool          `yaml:"generateIfMissing" mapstructure:"generateIfMissing"`
	PreviousKeys      []PreviousKey `yaml:"previousKeys" mapstructure:"previousKeys"`
}

// PreviousKey points to an old public key kept in JWKS during rotation.
type PreviousKey struct {
	KeyID         string `yaml:"keyId" mapstructure:"keyId"`
	PublicKeyFile string `yaml:"publicKeyFile" mapstructure:"publicKeyFile"`
}

// LoggingConfig configures logging output.
type LoggingConfig struct {
	Level  string `yaml:"level" mapstructure:"level"`
	Format string `yaml:"format" mapstructure:"format"`
}

// MetricsConfig configures the Prometheus metrics endpoint.
type MetricsConfig struct {
	Enabled bool   `yaml:"enabled" mapstructure:"enabled"`
	Listen  string `yaml:"listen" mapstructure:"listen"`
}

// Load reads configuration from a YAML file (path may be empty for
// env-only / defaults-only loads), applies AUTHENTICATOOR_* env overrides,
// fills in derived defaults, and validates the result. The returned Config
// is ready to use directly.
func Load(path string) (*Config, error) {
	v := viper.New()

	v.SetEnvPrefix("AUTHENTICATOOR")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	setDefaults(v)
	// AutomaticEnv only resolves keys viper already knows (defaults or
	// config file). These keys deliberately have no default — see
	// setDefaults — so bind them explicitly to keep their env overrides.
	for _, key := range []string{
		"authMode",
		"cloudflareAccess.verifyJWT",
		"cloudflareAccess.allowServiceTokens",
	} {
		if err := v.BindEnv(key); err != nil {
			return nil, fmt.Errorf("config: bind env %s: %w", key, err)
		}
	}

	if path != "" {
		v.SetConfigFile(path)
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("config: read %s: %w", path, err)
		}
	}

	cfg := &Config{}
	if err := v.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("config: unmarshal: %w", err)
	}

	if err := cfg.applyDerived(); err != nil {
		return nil, fmt.Errorf("config: derive: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config: validate: %w", err)
	}
	return cfg, nil
}

// setDefaults applies hard-coded defaults that don't depend on other fields.
// Fields that derive from the issuer URL are filled in by applyDerived.
func setDefaults(v *viper.Viper) {
	v.SetDefault("listen", ":8080")
	v.SetDefault("tokenTTL", "30m")
	// authMode has no viper default: applyDerived distinguishes "unset"
	// (→ all configured providers, or cloudflare) from an explicit value.

	// Deprecated top-level alias. Kept defaulted so existing configs
	// continue to populate cloudflareAccess.userHeader via applyDerived
	// without explicit migration.
	v.SetDefault("userHeader", "Cf-Access-Authenticated-User-Email")

	// cloudflareAccess.verifyJWT / allowServiceTokens intentionally have
	// no viper defaults: they are *bool fields whose nil value means
	// "true", so entries in the providers list get the same secure
	// default as the legacy top-level block.
	v.SetDefault("cloudflareAccess.jwtHeader", "Cf-Access-Jwt-Assertion")

	v.SetDefault("signing.mode", "rs256")

	v.SetDefault("logging.level", "info")
	v.SetDefault("logging.format", "text")

	v.SetDefault("metrics.enabled", false)
	v.SetDefault("metrics.listen", ":9090")
}

// applyDerived fills in fields that are derived from the issuer URL when
// not configured explicitly. The derivation rule strips the leftmost label
// of the issuer host: e.g. "https://auth.example.com" → "example.com",
// which becomes the default audience and the suffix of the default scope
// pattern and allow-lists.
//
// applyDerived also folds the deprecated top-level userHeader into
// cloudflareAccess.userHeader and records a deprecation warning when both
// are set to non-default values.
func (c *Config) applyDerived() error {
	if c.Issuer == "" {
		return errors.New("issuer is required")
	}
	// The parent zone is only needed to fill in unset defaults below. A
	// single-label issuer host (e.g. http://localhost:18080 in local dev)
	// has no parent zone, but is fine as long as every zone-derived field
	// is set explicitly — so the error is deferred until a derivation
	// actually needs it.
	parent, parentErr := parentZone(c.Issuer)
	needParent := func(field string) error {
		if parentErr != nil {
			return fmt.Errorf("%s not set and no default can be derived: %w", field, parentErr)
		}
		return nil
	}

	if c.ExternalURL == "" {
		c.ExternalURL = c.Issuer
	}
	if len(c.Audience) == 0 {
		if err := needParent("audience"); err != nil {
			return err
		}
		c.Audience = []string{parent}
	}
	if c.ScopePattern == "" {
		if err := needParent("scopePattern"); err != nil {
			return err
		}
		c.ScopePattern = "*." + parent
	}
	if len(c.AllowedReturnHosts) == 0 {
		if err := needParent("allowedReturnHosts"); err != nil {
			return err
		}
		c.AllowedReturnHosts = []string{"*." + parent}
	}
	if len(c.CORS.AllowedOrigins) == 0 {
		c.CORS.AllowedOrigins = c.AllowedReturnHosts
	}

	const defaultCFUserHeader = "Cf-Access-Authenticated-User-Email"
	switch {
	case c.CloudflareAccess.UserHeader == "":
		c.CloudflareAccess.UserHeader = c.UserHeader
	case c.UserHeader != "" && c.UserHeader != defaultCFUserHeader && c.UserHeader != c.CloudflareAccess.UserHeader:
		c.DeprecationWarnings = append(c.DeprecationWarnings,
			"top-level userHeader is set alongside cloudflareAccess.userHeader; the top-level value is ignored. The top-level userHeader field is deprecated — move it under cloudflareAccess.")
	}
	c.UserHeader = c.CloudflareAccess.UserHeader

	return c.resolveProviders()
}

// resolveProviders normalizes the providers list and the authMode
// advertised set. Afterwards c.Providers holds every defined provider
// (all of them enabled), and c.AuthMode lists the advertised providers'
// names in advertisement order.
//
// Two input shapes:
//   - providers empty (legacy): each authMode entry names a provider
//     TYPE whose top-level block is converted into an entry. The legacy
//     blocks carry the viper defaults, so converted entries inherit
//     them. Unset authMode means ["cloudflare"].
//   - providers set (canonical): each authMode entry references an
//     entry by NAME; unset authMode advertises all entries in list
//     order. Unreferenced entries stay fully enabled — they just don't
//     appear on the selector or as the direct login target.
func (c *Config) resolveProviders() error {
	converted := false
	if len(c.Providers) == 0 {
		converted = true
		modes := c.AuthMode
		if len(modes) == 0 {
			modes = []string{AuthModeCloudflare}
		}
		c.Providers = make([]ProviderConfig, 0, len(modes))
		for _, mode := range modes {
			name, known := legacyProviderNames[mode]
			if !known {
				return fmt.Errorf("authMode: unsupported value %q", mode)
			}
			pc := ProviderConfig{
				Name:             name,
				Type:             mode,
				CloudflareAccess: c.CloudflareAccess,
				BasicAuth:        c.BasicAuth,
				AnyAuth:          c.AnyAuth,
				GitHubOAuth:      c.GitHubOAuth,
				OIDC:             c.OIDC,
			}
			pc.applyLegacyDefaults()
			c.Providers = append(c.Providers, pc)
		}
	}

	// Converted entries ARE the advertised set (authMode named types,
	// not names); with an explicit providers list an unset authMode
	// advertises all. Either way authMode ends up holding names.
	if converted || len(c.AuthMode) == 0 {
		names := make([]string, 0, len(c.Providers))
		for i := range c.Providers {
			names = append(names, c.Providers[i].Name)
		}
		c.AuthMode = names
		return nil
	}

	// Explicit authMode: every entry must reference a defined provider.
	// Duplicates would produce duplicate selector entries.
	byName := make(map[string]struct{}, len(c.Providers))
	for i := range c.Providers {
		byName[c.Providers[i].Name] = struct{}{}
	}
	seen := make(map[string]struct{}, len(c.AuthMode))
	for _, name := range c.AuthMode {
		if _, ok := byName[name]; !ok {
			return fmt.Errorf("authMode: no provider named %q", name)
		}
		if _, dup := seen[name]; dup {
			return fmt.Errorf("authMode: duplicate entry %q", name)
		}
		seen[name] = struct{}{}
	}
	return nil
}

// parentZone returns the parent DNS zone of the issuer URL's host, i.e.
// strips the leftmost label. "https://auth.foo.example" → "foo.example".
func parentZone(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("parse issuer URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("issuer URL must be http(s): got %q", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return "", errors.New("issuer URL has no host")
	}
	idx := strings.IndexByte(host, '.')
	if idx < 0 || idx == len(host)-1 {
		return "", fmt.Errorf("issuer host %q has no parent zone (need at least sub.domain)", host)
	}
	return host[idx+1:], nil
}

// Validate applies semantic validation that can't be expressed in struct tags.
func (c *Config) Validate() error {
	if c.Listen == "" {
		return errors.New("listen is required")
	}
	if c.Issuer == "" {
		return errors.New("issuer is required")
	}
	if c.TokenTTL <= 0 {
		return errors.New("tokenTTL must be positive")
	}
	if len(c.Audience) == 0 {
		return errors.New("audience is required")
	}

	switch c.Signing.Mode {
	case "rs256":
		if c.Signing.RS256.PrivateKeyFile == "" {
			return errors.New("signing.rs256.privateKeyFile is required")
		}
	default:
		return fmt.Errorf("signing.mode: unsupported value %q (only rs256 is supported)", c.Signing.Mode)
	}

	if len(c.Providers) == 0 {
		return errors.New("providers: at least one provider is required")
	}
	seenNames := make(map[string]struct{}, len(c.Providers))
	for i := range c.Providers {
		p := &c.Providers[i]
		if err := validateProviderName(p.Name); err != nil {
			return fmt.Errorf("providers[%d]: %w", i, err)
		}
		if _, dup := seenNames[p.Name]; dup {
			return fmt.Errorf("providers[%d]: duplicate name %q", i, p.Name)
		}
		seenNames[p.Name] = struct{}{}
		if err := p.validate(); err != nil {
			return fmt.Errorf("providers[%d] (%s): %w", i, p.Name, err)
		}
	}

	if slices.Contains(c.AllowedReturnHosts, "") {
		return errors.New("allowedReturnHosts must not contain empty entries")
	}
	if slices.Contains(c.CORS.AllowedOrigins, "") {
		return errors.New("cors.allowedOrigins must not contain empty entries")
	}

	return nil
}

// applyLegacyDefaults pins the pre-multi-provider callback paths and
// cookie names on an entry converted from a legacy top-level block, so
// existing deployments keep their registered OAuth redirect URIs and
// live session cookie names. Entries in the providers list get the
// /<name>/... defaults instead.
func (p *ProviderConfig) applyLegacyDefaults() {
	setDefault := func(field *string, value string) {
		if *field == "" {
			*field = value
		}
	}
	switch p.Type {
	case AuthModeGitHub:
		setDefault(&p.GitHubOAuth.CallbackPath, "/auth/oauth/callback")
		setDefault(&p.GitHubOAuth.SessionCookieName, "authenticatoor_session")
		setDefault(&p.GitHubOAuth.StateCookieName, "authenticatoor_oauth_state")
	case AuthModeOIDC:
		setDefault(&p.OIDC.CallbackPath, "/auth/oidc/callback")
		setDefault(&p.OIDC.SessionCookieName, "authenticatoor_oidc_session")
		setDefault(&p.OIDC.StateCookieName, "authenticatoor_oidc_state")
	}
}

// providerNamePattern constrains provider instance names: they double as
// path segments and cookie-name fragments.
var providerNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// validateProviderName rejects empty, malformed, or reserved names.
func validateProviderName(name string) error {
	if name == "" {
		return errors.New("name is required")
	}
	if !providerNamePattern.MatchString(name) {
		return fmt.Errorf("name %q must match %s", name, providerNamePattern.String())
	}
	if _, reserved := reservedProviderNames[name]; reserved {
		return fmt.Errorf("name %q collides with a built-in route", name)
	}
	return nil
}

// validate applies per-provider semantic validation.
func (p *ProviderConfig) validate() error {
	switch p.Type {
	case AuthModeCloudflare:
		if p.CloudflareAccess.VerifyJWTEnabled() && p.CloudflareAccess.TeamDomain == "" {
			return errors.New("cloudflareAccess.teamDomain is required when verifyJWT is true")
		}
	case AuthModeBasic:
		if p.BasicAuth.HtpasswdFile == "" {
			return errors.New("basicAuth.htpasswdFile is required")
		}
	case AuthModeAny:
		// no required fields
	case AuthModeGitHub:
		if p.GitHubOAuth.ClientID == "" {
			return errors.New("githubOAuth.clientId is required")
		}
		if p.GitHubOAuth.ClientSecret == "" && p.GitHubOAuth.ClientSecretFile == "" {
			return errors.New("githubOAuth.clientSecret or githubOAuth.clientSecretFile is required")
		}
		if len(p.GitHubOAuth.AllowedOrgs) == 0 {
			return errors.New("githubOAuth.allowedOrgs must list at least one org")
		}
	case AuthModeOIDC:
		if p.OIDC.IssuerURL == "" {
			return errors.New("oidc.issuerURL is required")
		}
		if p.OIDC.CallbackURL == "" {
			return errors.New("oidc.callbackURL is required")
		}
		if p.OIDC.ClientID == "" {
			return errors.New("oidc.clientId is required")
		}
		if p.OIDC.ClientSecret == "" && p.OIDC.ClientSecretFile == "" {
			return errors.New("oidc.clientSecret or oidc.clientSecretFile is required")
		}
		// oidc.allowedGroups is optional: empty means "trust the IdP's
		// own gating" (e.g. dex's connector orgs allow-list). Set it
		// to narrow further on a per-instance basis.
	default:
		return fmt.Errorf("type: unsupported value %q", p.Type)
	}
	return nil
}

// String returns a redacted representation of the config (suitable for
// logging at startup). Sensitive paths/keys are not included verbatim, but
// presence is indicated.
func (c *Config) String() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "listen=%s ", c.Listen)
	fmt.Fprintf(&sb, "issuer=%s ", c.Issuer)
	providers := make([]string, 0, len(c.Providers))
	for _, p := range c.Providers {
		providers = append(providers, p.Name+":"+p.Type)
	}
	fmt.Fprintf(&sb, "providers=%v ", providers)
	fmt.Fprintf(&sb, "audience=%v ", c.Audience)
	fmt.Fprintf(&sb, "scope=%s ", c.ScopePattern)
	fmt.Fprintf(&sb, "tokenTTL=%s ", c.TokenTTL)
	fmt.Fprintf(&sb, "allowedReturnHosts=%v ", c.AllowedReturnHosts)
	fmt.Fprintf(&sb, "signing.mode=%s ", c.Signing.Mode)
	fmt.Fprintf(&sb, "signing.rs256.keyFile=present(%t) ", c.Signing.RS256.PrivateKeyFile != "")
	fmt.Fprintf(&sb, "previousKeys=%d", len(c.Signing.RS256.PreviousKeys))
	return sb.String()
}

// MustReadFile is a small helper used by callers that want to load a file's
// content (e.g. for non-config reasons) with a clear error message.
func MustReadFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return data, nil
}
