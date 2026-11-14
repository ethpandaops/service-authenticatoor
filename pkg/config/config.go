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
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/spf13/viper"
	"go.yaml.in/yaml/v3"

	"github.com/ethpandaops/service-authenticatoor/pkg/issuer"
	"github.com/ethpandaops/service-authenticatoor/pkg/protection"
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
	// Grants is the service grants section: a list of groups, each
	// naming its members — teams and users, always together with the
	// provider they come through — and the services they may use. When
	// set, the token's "services" claim is computed per identity from
	// it (see issuer.ServiceGrants). nil means the section is absent
	// and tokens carry no per-identity constraint; a present but empty
	// section is non-nil and grants nothing to anyone.
	//
	// Read from the YAML document by loadGrants rather than through
	// viper: its members are data and must arrive as written.
	Grants *issuer.GrantsConfig `yaml:"grants" mapstructure:"-"`

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

	// Warnings collects other messages about the config file that the
	// entrypoint logs at startup, such as unknown top-level keys.
	Warnings []string `yaml:"-" mapstructure:"-"`
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
	// Teams are static team names put into the "teams" token claim of
	// every identity this provider authenticates — service tokens
	// included. Names are lowercased; each must match
	// [a-z0-9][a-z0-9._-]{0,62}, at most 32 per provider.
	Teams []string `yaml:"teams" mapstructure:"teams"`
	// TeamRules derive further teams from the attributes the provider
	// verified about the user; see protection.TeamRule and docs/config.md.
	TeamRules []protection.TeamRule `yaml:"teamRules" mapstructure:"teamRules"`
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
	// Teams are static team names put into the "teams" token claim of
	// every identity this provider authenticates. Names are lowercased;
	// each must match [a-z0-9][a-z0-9._-]{0,62}, at most 32 per provider.
	Teams []string `yaml:"teams" mapstructure:"teams"`
	// TeamRules derive further teams from the attributes the provider
	// verified about the user; see protection.TeamRule and docs/config.md.
	TeamRules []protection.TeamRule `yaml:"teamRules" mapstructure:"teamRules"`
}

// AnyAuthConfig configures the anyauth (dev-only) protection provider.
// All fields are optional; the provider falls back to sensible defaults.
type AnyAuthConfig struct {
	// CookieName overrides the username cookie name. Defaults to
	// "authenticatoor_anyauth_user".
	CookieName string `yaml:"cookieName" mapstructure:"cookieName"`
	// CookieTTL overrides the cookie lifetime. Defaults to "12h".
	CookieTTL time.Duration `yaml:"cookieTTL" mapstructure:"cookieTTL"`
	// Teams are static team names put into the "teams" token claim of
	// every identity this provider authenticates. Names are lowercased;
	// each must match [a-z0-9][a-z0-9._-]{0,62}, at most 32 per provider.
	Teams []string `yaml:"teams" mapstructure:"teams"`
	// TeamRules derive further teams from the attributes the provider
	// verified about the user; see protection.TeamRule and docs/config.md.
	TeamRules []protection.TeamRule `yaml:"teamRules" mapstructure:"teamRules"`
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
	// Teams are static team names put into the "teams" token claim of
	// every identity this provider authenticates. Names are lowercased;
	// each must match [a-z0-9][a-z0-9._-]{0,62}, at most 32 per provider.
	Teams []string `yaml:"teams" mapstructure:"teams"`
	// TeamRules derive further teams from the attributes the provider
	// verified about the user; see protection.TeamRule and docs/config.md.
	TeamRules []protection.TeamRule `yaml:"teamRules" mapstructure:"teamRules"`
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
	// TrustUnverifiedEmail uses the id_token's email although the token
	// does not mark it email_verified. Off by default; see the docs for
	// the risk. A pointer so that "not set" — which gets a startup
	// warning explaining the rule — can be told from an explicit false.
	TrustUnverifiedEmail *bool `yaml:"trustUnverifiedEmail" mapstructure:"trustUnverifiedEmail"`
	// Teams are static team names put into the "teams" token claim of
	// every identity this provider authenticates. Names are lowercased;
	// each must match [a-z0-9][a-z0-9._-]{0,62}, at most 32 per provider.
	Teams []string `yaml:"teams" mapstructure:"teams"`
	// TeamRules derive further teams from the attributes the provider
	// verified about the user; see protection.TeamRule and docs/config.md.
	TeamRules []protection.TeamRule `yaml:"teamRules" mapstructure:"teamRules"`
	// Bearer lets non-browser clients authenticate with a JWT of the
	// IdP instead of a browser login. Off unless the block is there.
	Bearer OIDCBearerConfig `yaml:"bearer" mapstructure:"bearer"`
}

// OIDCBearerConfig is the oidc.bearer block: GET /<name>/token accepts
// "Authorization: Bearer <JWT>" for a JWT of the IdP and answers like
// /auth/token. The feature is on when Audiences is set; a block
// without audiences is a startup error.
type OIDCBearerConfig struct {
	// Audiences are the accepted "aud" values of a presented token —
	// client ids at the IdP. A token must name at least one. Required,
	// and never defaulted to oidc.clientId.
	Audiences []string `yaml:"audiences" mapstructure:"audiences"`
	// IssuerURL is the issuer of the accepted tokens when it differs
	// from oidc.issuerURL (an IdP with one issuer per client, such as
	// Authentik). Default: oidc.issuerURL.
	IssuerURL string `yaml:"issuerURL" mapstructure:"issuerURL"`
}

// Enabled reports whether bearer tokens are accepted.
func (c OIDCBearerConfig) Enabled() bool { return len(c.Audiences) > 0 }

// validate checks the block. An issuer without audiences is a block
// that was meant to switch the feature on and names nobody to accept.
func (c OIDCBearerConfig) validate() error {
	if c.IssuerURL != "" && len(c.Audiences) == 0 {
		return errors.New("oidc.bearer.audiences is required when oidc.bearer is configured: list the " +
			"client ids whose tokens are accepted")
	}
	seen := make(map[string]struct{}, len(c.Audiences))
	for i, aud := range c.Audiences {
		if strings.TrimSpace(aud) != aud || aud == "" {
			return fmt.Errorf("oidc.bearer.audiences[%d]: %q is empty or has surrounding space", i, aud)
		}
		if _, dup := seen[aud]; dup {
			return fmt.Errorf("oidc.bearer.audiences: %q is listed twice", aud)
		}
		seen[aud] = struct{}{}
	}
	return nil
}

// TrustsUnverifiedEmail reports the effective trustUnverifiedEmail
// setting (unset = false).
func (c OIDCConfig) TrustsUnverifiedEmail() bool {
	return c.TrustUnverifiedEmail != nil && *c.TrustUnverifiedEmail
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
	// config file). Most settings have no default, so every setting
	// with a fixed path is bound explicitly; otherwise its env override
	// would only work when the key also happens to be in the file.
	for _, key := range envKeys(reflect.TypeOf(Config{}), "") {
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

	raw, unchecked, err := loadRawDocument(path)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if err := checkGrantsEnv(v.GetEnvPrefix(), os.Environ()); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if unchecked != "" {
		// Nothing below can look at the file. That is tolerable for a
		// config of the kind released versions read; it is not once
		// teams or grants hang on the file being read exactly.
		if feature := cfg.checkedFeature(v); feature != "" {
			return nil, fmt.Errorf("config: %s, so the strict checks of the config file cannot run; %s is "+
				"configured and needs them. Use a YAML (or JSON) config file", unchecked, feature)
		}
		cfg.Warnings = append(cfg.Warnings, unchecked+": the strict checks of the config file (unknown and "+
			"duplicate keys, misspelled sections) are not available for it. Use a YAML (or JSON) config file")
	}
	warnings, err := checkRawDocument(raw)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	cfg.Warnings = append(cfg.Warnings, warnings...)
	if cfg.DeprecationWarnings, err = checkProviderKeys(raw); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if err := cfg.restoreRuleMaps(raw); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}

	if cfg.Grants, err = loadGrants(v, raw); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if len(cfg.Providers) > 0 {
		cfg.Warnings = append(cfg.Warnings, unusedBlockEnv(v.GetEnvPrefix(), os.Environ())...)
	}

	if err := cfg.applyDerived(); err != nil {
		return nil, fmt.Errorf("config: derive: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config: validate: %w", err)
	}
	cfg.Warnings = append(cfg.Warnings, cfg.sharedAudienceNotes()...)
	cfg.Warnings = append(cfg.Warnings, cfg.unverifiedEmailNotes()...)
	return cfg, nil
}

// envKeys returns the config paths below t that can be set through the
// environment: every setting with a fixed path. Lists of structured
// entries (providers, teamRules, previousKeys) have none; neither has
// the grants section, which is not read through viper at all.
func envKeys(t reflect.Type, prefix string) []string {
	keys := make([]string, 0, t.NumField())
	for i := range t.NumField() {
		field := t.Field(i)
		tag := field.Tag.Get("mapstructure")
		if tag == "" || tag == "-" {
			continue
		}
		ft := field.Type
		if ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		switch {
		case ft.Kind() == reflect.Struct:
			keys = append(keys, envKeys(ft, prefix+tag+".")...)
		case ft.Kind() == reflect.Slice && ft.Elem().Kind() == reflect.Struct, ft.Kind() == reflect.Map:
			// Structured: file only.
		default:
			keys = append(keys, prefix+tag)
		}
	}
	return keys
}

// unusedBlockEnv returns a warning for every environment variable that
// sets a key of a legacy top-level provider block while the config has
// a providers list. Those blocks are only read when there is no list,
// so such a variable changes nothing — and the operator who set, say,
// AUTHENTICATOOR_OIDC_TRUSTUNVERIFIEDEMAIL should hear about it.
func unusedBlockEnv(prefix string, environ []string) []string {
	var out []string
	for _, entry := range environ {
		name, _, _ := strings.Cut(entry, "=")
		upper := strings.ToUpper(name)
		for _, block := range providerBlockKeys {
			if strings.HasPrefix(upper, strings.ToUpper(prefix+"_"+block)+"_") {
				out = append(out, fmt.Sprintf("environment variable %s sets the top-level %s block, which is "+
					"not used because the config has a providers list; entries of that list are configured "+
					"in the file only", name, block))
			}
		}
	}
	slices.Sort(out)
	return out
}

// checkedFeature names a part of the config that must not be loaded
// from a file the strict checks cannot inspect: teams, team rules and
// grants, wherever they are configured — in the file or through the
// environment. It returns "" when the config has none of them.
func (c *Config) checkedFeature(v *viper.Viper) string {
	if v.IsSet(grantsKey) || v.IsSet(removedTeamServicesKey) {
		return grantsKey
	}
	blocks := make([]ProviderConfig, 0, len(c.Providers)+1)
	blocks = append(blocks, ProviderConfig{
		CloudflareAccess: c.CloudflareAccess,
		BasicAuth:        c.BasicAuth,
		AnyAuth:          c.AnyAuth,
		GitHubOAuth:      c.GitHubOAuth,
		OIDC:             c.OIDC,
	})
	blocks = append(blocks, c.Providers...)
	for i := range blocks {
		for _, block := range providerBlockKeys {
			if len(blocks[i].teamsOf(block)) > 0 {
				return block + ".teams"
			}
			if len(blocks[i].teamRulesOf(block)) > 0 {
				return block + ".teamRules"
			}
		}
	}
	return ""
}

// unverifiedEmailNotes returns one warning per oidc provider whose
// trustUnverifiedEmail is not set, saying what happens to an email the
// IdP does not vouch for. The rule changes who a user is compared with
// released versions, so an operator must not have to find it in the
// documentation.
func (c *Config) unverifiedEmailNotes() []string {
	var out []string
	for i := range c.Providers {
		p := &c.Providers[i]
		if p.Type != AuthModeOIDC || p.OIDC.TrustUnverifiedEmail != nil {
			continue
		}
		out = append(out, fmt.Sprintf("provider %q: oidc.trustUnverifiedEmail is not set. An email counts only "+
			"when the id_token says email_verified: true. A user whose token does not is identified by the "+
			"IdP's \"sub\" instead of the email (released versions used the email), gets no email claim, and "+
			"matches no email-keyed team rule or grant. If the IdP flips the flag between two logins of one "+
			"user, that user's subject alternates. Set oidc.trustUnverifiedEmail to false to keep this rule "+
			"and silence the warning, or to true if the IdP verifies addresses without saying so "+
			"(see docs/config.md, Upgrading)", p.Name))
	}
	return out
}

// grantsKey is the top-level config key of the service grants section.
const grantsKey = "grants"

// removedTeamServicesKey is the key the section had before it could
// name individual users. It was never released; a config that still
// has it must not be read as "no grants configured".
const removedTeamServicesKey = "teamServices"

// loadGrants reads the grants section from the YAML document. It
// returns nil when the section is absent, and a non-nil (possibly
// empty) config when it is present. The shape is checked here — it is
// strict: unknown keys and wrong types are errors — while members and
// grants are validated later, by Validate.
func loadGrants(v *viper.Viper, root *yaml.Node) (*issuer.GrantsConfig, error) {
	if v.IsSet(removedTeamServicesKey) || rawChild(root, removedTeamServicesKey) != nil {
		return nil, fmt.Errorf("%s: this section was replaced by %q, a list of groups with members "+
			"and services (see docs/config.md, Service grants)", removedTeamServicesKey, grantsKey)
	}

	section := rawChild(root, grantsKey)
	if section == nil {
		if v.IsSet(grantsKey) {
			// Set somewhere this reader cannot see (not a YAML file).
			// Guessing "absent" would leave every service open.
			return nil, fmt.Errorf("%s: must be configured in the YAML config file", grantsKey)
		}
		return nil, nil
	}
	const shape = "a list of groups, each with members and services (use [] to grant nothing)"
	switch {
	case section.Kind == yaml.MappingNode:
		for _, old := range []string{"everyone", "teams", "users"} {
			if rawChild(section, old) != nil {
				return nil, fmt.Errorf("%s: the keys everyone / teams / users are gone. The section is now %s; "+
					"a member names its provider: \"<provider>/team:<team>\", \"<provider>/user:<id>\" or "+
					"\"<provider>/<attribute>:<value>\"",
					grantsKey, shape)
			}
		}
		return nil, fmt.Errorf("%s: must be %s", grantsKey, shape)
	case section.Kind != yaml.SequenceNode:
		// Includes "grants:" without a value: treating that as absent
		// would leave every service open where grants were meant.
		return nil, fmt.Errorf("%s: must be %s", grantsKey, shape)
	}

	cfg := &issuer.GrantsConfig{Groups: make([]issuer.GrantGroup, 0, len(section.Content))}
	for i, item := range section.Content {
		where := fmt.Sprintf("%s[%d]", grantsKey, i)
		group, err := loadGrantGroup(resolveNode(item), where)
		if err != nil {
			return nil, err
		}
		cfg.Groups = append(cfg.Groups, group)
	}
	return cfg, nil
}

// checkGrantsEnv refuses environment variables that look like an
// attempt to configure the grants section. Settings can be overridden
// through the environment, but grants are read from the config file
// only; such a variable would be ignored, and with no grants in the
// file the instance would run ungated although its operator configured
// grants.
func checkGrantsEnv(prefix string, environ []string) error {
	for _, entry := range environ {
		name, _, _ := strings.Cut(entry, "=")
		upper := strings.ToUpper(name)
		for _, section := range []string{grantsKey, removedTeamServicesKey} {
			key := strings.ToUpper(prefix + "_" + section)
			if upper == key || strings.HasPrefix(upper, key+"_") {
				return fmt.Errorf("environment variable %s: %s cannot be set through the environment; "+
					"it is read from the YAML config file only", name, grantsKey)
			}
		}
	}
	return nil
}

// loadGrantGroup reads one group of the grants section.
func loadGrantGroup(node *yaml.Node, where string) (issuer.GrantGroup, error) {
	var group issuer.GrantGroup
	if node == nil || node.Kind != yaml.MappingNode {
		return group, fmt.Errorf("%s: must be a group: a map with the keys name (optional), members and services", where)
	}
	hasMembers, hasServices := false, false
	for i := 0; i+1 < len(node.Content); i += 2 {
		key, value := node.Content[i].Value, resolveNode(node.Content[i+1])
		var err error
		switch {
		case strings.EqualFold(key, "name"):
			if value == nil || value.Kind != yaml.ScalarNode || isNull(value) || value.Value == "" {
				err = fmt.Errorf("must be a non-empty text")
			}
			if err == nil {
				group.Name = value.Value
			}
		case strings.EqualFold(key, "members"):
			hasMembers = true
			group.Members, err = rawStringList(value)
		case strings.EqualFold(key, "services"):
			hasServices = true
			group.Services, err = rawStringList(value)
		default:
			return group, fmt.Errorf("%s: unknown key %q (the keys of a group are name, members and services)", where, key)
		}
		if err != nil {
			return group, fmt.Errorf("%s.%s: %w", where, strings.ToLower(key), err)
		}
	}
	if !hasMembers {
		return group, fmt.Errorf("%s: members is required", where)
	}
	if !hasServices {
		return group, fmt.Errorf("%s: services is required (use [] for a group that grants nothing)", where)
	}
	return group, nil
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

	if c.Grants != nil {
		if _, err := issuer.NewServiceGrants(*c.Grants, c.GrantProviders()); err != nil {
			return fmt.Errorf("%s: %w", grantsKey, err)
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
	if err := p.validateTeams(); err != nil {
		return err
	}
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
		if err := p.OIDC.Bearer.validate(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("type: unsupported value %q", p.Type)
	}
	return nil
}

// teamConfig returns the team configuration of the block matching the
// provider's type, with the block's config key.
func (p *ProviderConfig) teamConfig() (block string, static []string, rules []protection.TeamRule) {
	switch p.Type {
	case AuthModeCloudflare:
		c := &p.CloudflareAccess
		return "cloudflareAccess", c.Teams, c.TeamRules
	case AuthModeBasic:
		c := &p.BasicAuth
		return "basicAuth", c.Teams, c.TeamRules
	case AuthModeAny:
		c := &p.AnyAuth
		return "anyAuth", c.Teams, c.TeamRules
	case AuthModeGitHub:
		c := &p.GitHubOAuth
		return "githubOAuth", c.Teams, c.TeamRules
	case AuthModeOIDC:
		c := &p.OIDC
		return "oidc", c.Teams, c.TeamRules
	default:
		return "", nil, nil
	}
}

// ProducesTeams reports whether the provider is configured to put teams
// into the tokens of the identities it authenticates.
func (p *ProviderConfig) ProducesTeams() bool {
	_, static, rules := p.teamConfig()
	return len(static) > 0 || len(rules) > 0
}

// ProviderNames returns the instance names of the configured providers,
// in order.
func (c *Config) ProviderNames() []string {
	names := make([]string, 0, len(c.Providers))
	for i := range c.Providers {
		names = append(names, c.Providers[i].Name)
	}
	return names
}

// GrantProviders describes the configured providers to the grants
// section: their names and, for the types whose attributes are a fixed
// set, which attribute members can match at all.
func (c *Config) GrantProviders() []issuer.Provider {
	out := make([]issuer.Provider, 0, len(c.Providers))
	for i := range c.Providers {
		out = append(out, issuer.Provider{
			Name:           c.Providers[i].Name,
			CheckAttribute: c.Providers[i].attributeCheck(),
		})
	}
	return out
}

// attributeCheck returns the test a "<provider>/<attribute>:<value>"
// member has to pass for this provider: an error says why no identity
// the provider authenticates can ever satisfy it. nil when every
// attribute path is possible.
//
//	oidc        any claim of the id_token: every path is accepted
//	cloudflare  see cloudflareAttributeCheck
//	github      login, email, orgs
//	basic, any  username
func (p *ProviderConfig) attributeCheck() func(attribute, value string) error {
	fixed := func(names ...string) func(string, string) error {
		return func(attribute, _ string) error {
			if !slices.Contains(names, attribute) {
				return fmt.Errorf("the provider type %s has no attribute %q (it has: %s)",
					p.Type, attribute, strings.Join(names, ", "))
			}
			return nil
		}
	}
	switch p.Type {
	case AuthModeGitHub:
		return fixed("login", "email", "orgs")
	case AuthModeBasic, AuthModeAny:
		return fixed("username")
	case AuthModeCloudflare:
		return p.CloudflareAccess.attributeCheck
	default:
		return nil
	}
}

// cloudflareTokenAttributes are the claims of an Access token that a
// grants member may name, next to "principal" and "custom.<…>".
var cloudflareTokenAttributes = []string{
	"email", "sub", "common_name", "country", "type", "identity_nonce", "iss", "aud",
}

// attributeCheck is the attributeCheck of a cloudflare provider. What
// its identities can have depends on how it is configured:
//
//   - with verifyJWT there is a verified Access token: its claims
//     (cloudflareTokenAttributes, anything under "custom."), plus
//     "principal", which is "user" or "service";
//   - without verifyJWT there is no token: only "email", from the
//     trusted header, and "principal", which is always "user";
//   - service tokens, the only identities with principal "service" and
//     a "common_name", exist only with verifyJWT and
//     allowServiceTokens.
func (c CloudflareAccessConfig) attributeCheck(attribute, value string) error {
	serviceTokens := c.VerifyJWTEnabled() && c.ServiceTokensAllowed()
	const noServiceTokens = "this provider authenticates no service tokens (they need verifyJWT and " +
		"allowServiceTokens)"

	switch {
	case attribute == "principal":
		switch strings.ToLower(value) {
		case "user":
			return nil
		case "service":
			if !serviceTokens {
				return fmt.Errorf("principal is never \"service\": %s", noServiceTokens)
			}
			return nil
		default:
			return fmt.Errorf("principal is \"user\" or \"service\", never %q", value)
		}
	case attribute == "email":
		return nil
	case !c.VerifyJWTEnabled():
		return fmt.Errorf("with verifyJWT off a cloudflare provider has no attribute %q: there is no "+
			"verified Access token, only email and principal", attribute)
	case attribute == "common_name" && !serviceTokens:
		return fmt.Errorf("only service tokens have a common_name, and %s", noServiceTokens)
	case slices.Contains(cloudflareTokenAttributes, attribute):
		return nil
	case strings.HasPrefix(attribute, "custom."):
		if slices.Contains(strings.Split(attribute, "."), "") {
			return fmt.Errorf("%q names no claim: after \"custom.\" comes the name of a custom claim "+
				"(\"custom.department\")", attribute)
		}
		return nil
	default:
		return fmt.Errorf("the provider type cloudflare has no attribute %q (it has: principal, %s, custom.<claim>)",
			attribute, strings.Join(cloudflareTokenAttributes, ", "))
	}
}

// ServicesUngated reports whether the instance hands every authenticated
// identity a token valid for every service although it distinguishes
// identities: there is no grants section, yet more than one
// provider is configured or some provider produces teams. Worth a
// startup warning — a second door (or a team claim) suggests not every
// identity should reach every tool, and nothing enforces that.
func (c *Config) ServicesUngated() bool {
	if c.Grants != nil {
		return false
	}
	if len(c.Providers) > 1 {
		return true
	}
	for i := range c.Providers {
		if c.Providers[i].ProducesTeams() {
			return true
		}
	}
	return false
}

// sharedAudienceNotes returns one warning per Cloudflare provider that
// hands out teams or is named in a grants member without saying which
// Access application it is.
//
// Without audTag the verifier checks an assertion's signature and
// issuer only: it accepts the assertion of ANY Access application of
// the same Cloudflare team. The audience that the provider can detect
// on its own is enforced on /<name>/login and /<name>/token, but not
// on /auth/*, where the Access headers authenticate directly. So
// whoever is admitted to any other application of the team is this
// door's visitor too, and gets its teams and grants.
//
// That is a warning and not an error: it is how every released version
// treated a Cloudflare door without audTag, deployments rely on it, and
// where one Access policy covers all applications of a team it is
// exactly what is meant. (With verifyJWT off no assertion is looked at
// at all; that mode has its own warning.)
func (c *Config) sharedAudienceNotes() []string {
	var inGrants []string
	if c.Grants != nil {
		// Validate has accepted the section, so this cannot fail.
		if grants, err := issuer.NewServiceGrants(*c.Grants, c.GrantProviders()); err == nil {
			inGrants = grants.Providers()
		}
	}
	var out []string
	for i := range c.Providers {
		p := &c.Providers[i]
		if p.Type != AuthModeCloudflare || !p.CloudflareAccess.VerifyJWTEnabled() || p.CloudflareAccess.AudTag != "" {
			continue
		}
		var why []string
		if len(p.CloudflareAccess.Teams) > 0 || len(p.CloudflareAccess.TeamRules) > 0 {
			why = append(why, "gives teams to the identities it authenticates")
		}
		if slices.Contains(inGrants, p.Name) {
			why = append(why, "is named in grants members")
		}
		if len(why) == 0 {
			continue
		}
		out = append(out, fmt.Sprintf("provider %q %s, but cloudflareAccess.audTag is not set: /auth/* accepts "+
			"an assertion issued for any Access application of the Cloudflare team %s, so the teams and "+
			"grants of this door apply to everyone admitted to any of them. Set audTag to the AUD tag of "+
			"this application to limit the door to it",
			p.Name, strings.Join(why, " and "), p.CloudflareAccess.TeamDomain))
	}
	return out
}

// validateTeams rejects a malformed team configuration in the block
// matching the provider's type, so a typo fails startup instead of
// silently producing tokens without the team. Team names that an
// identity provider supplies at login are, by contrast, dropped with a
// warning.
func (p *ProviderConfig) validateTeams() error {
	block, static, rules := p.teamConfig()
	if block == "" {
		return nil // the type switch in validate reports it
	}
	if _, err := protection.ValidateTeams(static); err != nil {
		return fmt.Errorf("%s.teams: %w", block, err)
	}
	if err := protection.ValidateTeamRules(rules); err != nil {
		return fmt.Errorf("%s.%w", block, err)
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
	fmt.Fprintf(&sb, "grants=present(%t) ", c.Grants != nil)
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
