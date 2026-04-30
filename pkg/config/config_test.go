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
	if !cfg.CloudflareAccess.VerifyJWT {
		t.Error("cf verifyJWT default should be true")
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
