// Command authenticatoor is an HTTP service that issues short-lived RS256
// JWTs to users authenticated by an external reverse-proxy SSO. The signed
// public keys are published as a JWKS so any downstream resource server can
// validate the issued tokens locally.
//
// Usage:
//
//	authenticatoor --config /etc/authenticatoor/config.yaml
package main

import (
	"context"
	"crypto/rsa"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/ethpandaops/service-authenticatoor/pkg/config"
	"github.com/ethpandaops/service-authenticatoor/pkg/issuer"
	"github.com/ethpandaops/service-authenticatoor/pkg/protection"
	"github.com/ethpandaops/service-authenticatoor/pkg/protection/anyauth"
	"github.com/ethpandaops/service-authenticatoor/pkg/protection/basic"
	"github.com/ethpandaops/service-authenticatoor/pkg/protection/cloudflare"
	"github.com/ethpandaops/service-authenticatoor/pkg/protection/github"
	"github.com/ethpandaops/service-authenticatoor/pkg/protection/oidc"
	"github.com/ethpandaops/service-authenticatoor/pkg/server"
)

// version and gitSHA are populated at build time via
// -ldflags "-X main.version=... -X main.gitSHA=...".
var (
	version = "dev"
	gitSHA  = "unknown"
)

// fullVersion is what cobra prints for --version.
func fullVersion() string {
	if gitSHA == "" || gitSHA == "unknown" {
		return version
	}
	return version + " (" + gitSHA + ")"
}

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	var cfgPath string

	cmd := &cobra.Command{
		Use:     "authenticatoor",
		Short:   "Issues short-lived RS256 JWTs for users authenticated by an upstream SSO proxy",
		Version: fullVersion(),
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(cmd.Context(), cfgPath)
		},
	}

	cmd.Flags().StringVarP(&cfgPath, "config", "c", "", "path to YAML config file")
	cmd.AddCommand(newGenKeyCmd())

	return cmd
}

// run wires up dependencies and starts the server. ctx is canceled on
// SIGINT/SIGTERM.
func run(ctx context.Context, cfgPath string) error {
	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer cancel()

	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	log, err := newLogger(cfg.Logging)
	if err != nil {
		return fmt.Errorf("init logger: %w", err)
	}
	log.WithField("config", cfg.String()).Info("starting authenticatoor")
	for _, w := range cfg.DeprecationWarnings {
		log.Warn(w)
	}

	priv, err := loadOrGeneratePrivateKey(log, cfg.Signing.RS256.PrivateKeyFile, cfg.Signing.RS256.GenerateIfMissing)
	if err != nil {
		return fmt.Errorf("load signing key: %w", err)
	}

	iss, err := buildIssuer(log, cfg, priv)
	if err != nil {
		return fmt.Errorf("build issuer: %w", err)
	}

	// Derive the protection-provider session key from the signing key so
	// cookie-shaped providers (github / oidc) don't need a separate
	// secret. Rotating the signing key invalidates active sessions —
	// users re-authenticate on the next request, which is the expected
	// posture for a security-key rotation.
	sessionKey, err := issuer.DeriveHMACKey(priv, "authenticatoor session v1")
	if err != nil {
		return fmt.Errorf("derive session key: %w", err)
	}

	prov, err := buildProvider(log, cfg, sessionKey)
	if err != nil {
		return fmt.Errorf("build provider: %w", err)
	}

	srv, err := server.New(server.Options{
		Config:   cfg,
		Issuer:   iss,
		Provider: prov,
		Log:      log,
		Registry: prometheus.NewRegistry(),
	})
	if err != nil {
		return fmt.Errorf("build server: %w", err)
	}

	return srv.Start(ctx)
}

// buildProvider constructs the protection.Provider named by cfg.AuthMode.
// sessionKey is the derived HMAC key passed to cookie-shaped providers.
// Provider.Start (heavy initialization) is deferred to server.Start.
func buildProvider(log logrus.FieldLogger, cfg *config.Config, sessionKey []byte) (protection.Provider, error) {
	switch cfg.AuthMode {
	case config.AuthModeCloudflare:
		return cloudflare.New(log, cloudflare.Config{
			VerifyJWT:  cfg.CloudflareAccess.VerifyJWT,
			TeamDomain: cfg.CloudflareAccess.TeamDomain,
			AudTag:     cfg.CloudflareAccess.AudTag,
			JwtHeader:  cfg.CloudflareAccess.JwtHeader,
			UserHeader: cfg.CloudflareAccess.UserHeader,
		}), nil
	case config.AuthModeBasic:
		return basic.New(log, basic.Config{
			HtpasswdFile: cfg.BasicAuth.HtpasswdFile,
			Realm:        cfg.BasicAuth.Realm,
		}), nil
	case config.AuthModeAny:
		return anyauth.New(log, anyauth.Config{
			CookieName: cfg.AnyAuth.CookieName,
			LoginPath:  cfg.AnyAuth.LoginPath,
			CookieTTL:  cfg.AnyAuth.CookieTTL,
		}), nil
	case config.AuthModeGitHub:
		return github.New(log, github.Config{
			ClientID:          cfg.GitHubOAuth.ClientID,
			ClientSecret:      cfg.GitHubOAuth.ClientSecret,
			ClientSecretFile:  cfg.GitHubOAuth.ClientSecretFile,
			SessionKey:        sessionKey,
			CallbackPath:      cfg.GitHubOAuth.CallbackPath,
			PublicURL:         cfg.ExternalURL,
			SessionCookieName: cfg.GitHubOAuth.SessionCookieName,
			StateCookieName:   cfg.GitHubOAuth.StateCookieName,
			SessionTTL:        cfg.GitHubOAuth.SessionTTL,
			AllowedOrgs:       cfg.GitHubOAuth.AllowedOrgs,
		}), nil
	case config.AuthModeOIDC:
		return oidc.New(log, oidc.Config{
			IssuerURL:         cfg.OIDC.IssuerURL,
			CallbackURL:       cfg.OIDC.CallbackURL,
			PublicURL:         cfg.ExternalURL,
			ClientID:          cfg.OIDC.ClientID,
			ClientSecret:      cfg.OIDC.ClientSecret,
			ClientSecretFile:  cfg.OIDC.ClientSecretFile,
			SessionKey:        sessionKey,
			CallbackPath:      cfg.OIDC.CallbackPath,
			SessionCookieName: cfg.OIDC.SessionCookieName,
			StateCookieName:   cfg.OIDC.StateCookieName,
			SessionTTL:        cfg.OIDC.SessionTTL,
			AllowedGroups:     cfg.OIDC.AllowedGroups,
			Scopes:            cfg.OIDC.Scopes,
		}), nil
	default:
		return nil, fmt.Errorf("authMode %q not implemented", cfg.AuthMode)
	}
}

// buildIssuer loads any previous public keys for rotation and constructs
// an RS256Issuer around the supplied private key.
func buildIssuer(log logrus.FieldLogger, cfg *config.Config, priv *rsa.PrivateKey) (issuer.Issuer, error) {
	rs256 := cfg.Signing.RS256

	previous := make([]issuer.PreviousKey, 0, len(rs256.PreviousKeys))
	for _, p := range rs256.PreviousKeys {
		pub, err := issuer.LoadRSAPublicKeyPEM(p.PublicKeyFile)
		if err != nil {
			return nil, fmt.Errorf("previous key %s: %w", p.KeyID, err)
		}
		previous = append(previous, issuer.PreviousKey{KeyID: p.KeyID, Public: pub})
	}

	iss, err := issuer.NewRS256Issuer(issuer.Config{
		ActiveKey:       priv,
		ActiveKeyID:     rs256.KeyID,
		Previous:        previous,
		Issuer:          cfg.Issuer,
		DefaultAudience: cfg.Audience,
		Scope:           cfg.ScopePattern,
		TTL:             cfg.TokenTTL,
	})
	if err != nil {
		return nil, err
	}

	log.WithField("kid", iss.ActiveKeyID()).
		WithField("previous_keys", len(previous)).
		Info("issuer ready")
	return iss, nil
}

// loadOrGeneratePrivateKey loads the active RSA private key from disk. If
// the file is missing and genIfMissing is true (dev only), a fresh key is
// generated and persisted. Otherwise a missing file is a fatal error.
func loadOrGeneratePrivateKey(log logrus.FieldLogger, path string, genIfMissing bool) (*rsa.PrivateKey, error) {
	if _, err := os.Stat(path); err == nil {
		k, err := issuer.LoadRSAPrivateKeyPEM(path)
		if err != nil {
			return nil, fmt.Errorf("load private key %s: %w", path, err)
		}
		log.WithField("path", path).Info("loaded existing private key")
		return k, nil
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("stat private key %s: %w", path, err)
	}

	if !genIfMissing {
		return nil, fmt.Errorf("private key %s missing and generateIfMissing is false", path)
	}

	log.WithField("path", path).Warn("generating new RSA key (generateIfMissing=true; dev only)")
	k, err := issuer.GenerateRSAKey()
	if err != nil {
		return nil, fmt.Errorf("generate: %w", err)
	}
	pem, err := issuer.MarshalRSAPrivateKeyPEM(k)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	if err := os.WriteFile(path, pem, 0o600); err != nil {
		return nil, fmt.Errorf("write %s: %w", path, err)
	}
	return k, nil
}

// newLogger builds the application logger from the logging config.
func newLogger(cfg config.LoggingConfig) (logrus.FieldLogger, error) {
	log := logrus.New()
	level, err := logrus.ParseLevel(cfg.Level)
	if err != nil {
		return nil, fmt.Errorf("parse log level %q: %w", cfg.Level, err)
	}
	log.SetLevel(level)
	switch cfg.Format {
	case "", "text":
		log.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})
	case "json":
		log.SetFormatter(&logrus.JSONFormatter{})
	default:
		return nil, fmt.Errorf("unknown log format %q", cfg.Format)
	}
	return log.WithField("service", "authenticatoor"), nil
}

// newGenKeyCmd writes a fresh RSA-2048 PKCS#8 private key to stdout.
func newGenKeyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "genkey",
		Short: "Generate a new RSA-2048 private key in PKCS#8 PEM format",
		RunE: func(cmd *cobra.Command, args []string) error {
			k, err := issuer.GenerateRSAKey()
			if err != nil {
				return err
			}
			pem, err := issuer.MarshalRSAPrivateKeyPEM(k)
			if err != nil {
				return err
			}
			_, err = os.Stdout.Write(pem)
			return err
		},
	}
}
