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
	"slices"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config is the resolved, validated, derivation-applied configuration of the
// authenticatoor service.
type Config struct {
	Listen      string `yaml:"listen" mapstructure:"listen"`
	Issuer      string `yaml:"issuer" mapstructure:"issuer"`
	ExternalURL string `yaml:"externalURL" mapstructure:"externalURL"`

	Audience     []string      `yaml:"audience" mapstructure:"audience"`
	ScopePattern string        `yaml:"scopePattern" mapstructure:"scopePattern"`
	TokenTTL     time.Duration `yaml:"tokenTTL" mapstructure:"tokenTTL"`

	UserHeader         string   `yaml:"userHeader" mapstructure:"userHeader"`
	AllowedReturnHosts []string `yaml:"allowedReturnHosts" mapstructure:"allowedReturnHosts"`

	CloudflareAccess CloudflareAccessConfig `yaml:"cloudflareAccess" mapstructure:"cloudflareAccess"`
	CORS             CORSConfig             `yaml:"cors" mapstructure:"cors"`
	Signing          SigningConfig          `yaml:"signing" mapstructure:"signing"`
	Logging          LoggingConfig          `yaml:"logging" mapstructure:"logging"`
	Metrics          MetricsConfig          `yaml:"metrics" mapstructure:"metrics"`
}

// CloudflareAccessConfig configures CF Access JWT verification.
type CloudflareAccessConfig struct {
	VerifyJWT  bool   `yaml:"verifyJWT" mapstructure:"verifyJWT"`
	TeamDomain string `yaml:"teamDomain" mapstructure:"teamDomain"`
	AudTag     string `yaml:"audTag" mapstructure:"audTag"`
	JwtHeader  string `yaml:"jwtHeader" mapstructure:"jwtHeader"`
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
	v.SetDefault("userHeader", "Cf-Access-Authenticated-User-Email")

	v.SetDefault("cloudflareAccess.verifyJWT", true)
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
func (c *Config) applyDerived() error {
	if c.Issuer == "" {
		return errors.New("issuer is required")
	}
	parent, err := parentZone(c.Issuer)
	if err != nil {
		return err
	}

	if c.ExternalURL == "" {
		c.ExternalURL = c.Issuer
	}
	if len(c.Audience) == 0 {
		c.Audience = []string{parent}
	}
	if c.ScopePattern == "" {
		c.ScopePattern = "*." + parent
	}
	if len(c.AllowedReturnHosts) == 0 {
		c.AllowedReturnHosts = []string{"*." + parent}
	}
	if len(c.CORS.AllowedOrigins) == 0 {
		c.CORS.AllowedOrigins = c.AllowedReturnHosts
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
	if c.UserHeader == "" {
		return errors.New("userHeader is required")
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

	if c.CloudflareAccess.VerifyJWT {
		if c.CloudflareAccess.TeamDomain == "" {
			return errors.New("cloudflareAccess.teamDomain is required when verifyJWT is true")
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

// String returns a redacted representation of the config (suitable for
// logging at startup). Sensitive paths/keys are not included verbatim, but
// presence is indicated.
func (c *Config) String() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "listen=%s ", c.Listen)
	fmt.Fprintf(&sb, "issuer=%s ", c.Issuer)
	fmt.Fprintf(&sb, "audience=%v ", c.Audience)
	fmt.Fprintf(&sb, "scope=%s ", c.ScopePattern)
	fmt.Fprintf(&sb, "tokenTTL=%s ", c.TokenTTL)
	fmt.Fprintf(&sb, "allowedReturnHosts=%v ", c.AllowedReturnHosts)
	fmt.Fprintf(&sb, "cf.verifyJWT=%v ", c.CloudflareAccess.VerifyJWT)
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
