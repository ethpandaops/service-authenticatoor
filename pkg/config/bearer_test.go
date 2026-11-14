package config

import (
	"slices"
	"testing"
)

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
		{"empty map", "      bearer: {}\n", "providers[0].oidc.bearer.audiences: must be a non-empty list"},
		{"issuer only", "      bearer:\n        issuerURL: \"https://idp.example.org/cli\"\n", "providers[0].oidc.bearer.audiences: must be a non-empty list"},
		{"empty audiences", "      bearer:\n        audiences: []\n", "providers[0].oidc.bearer.audiences: must be a non-empty list"},
		{"audiences without a value", "      bearer:\n        audiences:\n", "providers[0].oidc.bearer.audiences: must be a non-empty list"},
		{"audiences is a single value", "      bearer:\n        audiences: devnet-cli\n", "providers[0].oidc.bearer.audiences: must be a non-empty list"},
		{"audiences is a map", "      bearer:\n        audiences: {devnet-cli: true}\n", "providers[0].oidc.bearer.audiences"},
		{"empty audience", "      bearer:\n        audiences: [\"devnet-cli\", \"\"]\n", "providers[0].oidc.bearer.audiences[1]: must be a non-empty string"},
		{"audience is a list", "      bearer:\n        audiences: [[devnet-cli]]\n", "providers[0].oidc.bearer.audiences[0]"},
		{"blank audience", "      bearer:\n        audiences: [\" \"]\n", "oidc.bearer.audiences[0]"},
		{"duplicate audience", "      bearer:\n        audiences: [\"devnet-cli\", \"devnet-cli\"]\n", `"devnet-cli" is listed twice`},
		{"unknown key", "      bearer:\n        audiences: [\"devnet-cli\"]\n        issuer: \"https://idp.example.org\"\n", `providers[0].oidc.bearer: unknown key "issuer"`},
		{"misspelled audiences", "      bearer:\n        audience: [\"devnet-cli\"]\n", "providers[0].oidc.bearer"},
		{"block is a list", "      bearer:\n        - audiences: [\"devnet-cli\"]\n", "providers[0].oidc.bearer"},
		{"block is a single value", "      bearer: true\n", "providers[0].oidc.bearer"},
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
	t.Run("environment, duplicate", func(t *testing.T) {
		t.Setenv("AUTHENTICATOOR_OIDC_BEARER_AUDIENCES", "devnet-cli,devnet-cli")
		wantLoadError(t, writeTempConfig(t, legacyOIDC), `"devnet-cli" is listed twice`)
	})
}
