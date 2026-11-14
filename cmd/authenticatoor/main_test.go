package main

import (
	"slices"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"

	"github.com/ethpandaops/service-authenticatoor/pkg/config"
	"github.com/ethpandaops/service-authenticatoor/pkg/issuer"
	"github.com/ethpandaops/service-authenticatoor/pkg/protection"
)

// TestLogServiceGrants covers the startup messages about the services
// claim: the warning for an ungated instance, the grant table, and the
// warning for user grants any provider can claim.
func TestLogServiceGrants(t *testing.T) {
	cf := config.ProviderConfig{Name: "cfaccess", Type: config.AuthModeCloudflare}
	oidc := config.ProviderConfig{Name: "oidc", Type: config.AuthModeOIDC}
	basic := config.ProviderConfig{Name: "htpasswd", Type: config.AuthModeBasic}

	tests := []struct {
		name      string
		providers []config.ProviderConfig
		grants    *issuer.GrantsConfig
		wantWarn  []string // substrings, one per expected warning
		wantTable []string // nil: no table logged
	}{
		{"one provider, no grants: silent", []config.ProviderConfig{cf}, nil, nil, nil},
		{"two providers, no grants: ungated warning", []config.ProviderConfig{cf, oidc}, nil, []string{"grants is not configured"}, nil},
		{
			"grants: the table, group → members → services",
			[]config.ProviderConfig{cf, oidc, basic},
			&issuer.GrantsConfig{Groups: []issuer.GrantGroup{
				{Name: "staff", Members: []string{"oidc/team:ethpandaops", "cfaccess/team:panda"}, Services: []string{"all:all"}},
				{Members: []string{"oidc/user:Alice@example.org", "oidc/groups:panda-access"}, Services: []string{"dora:reindex", "spamoor"}},
				{Name: "documented", Members: []string{"htpasswd/username:ops"}, Services: nil},
			}},
			nil,
			[]string{
				"staff: cfaccess/team:panda, oidc/team:ethpandaops → all:all",
				"grants[1]: oidc/groups:panda-access, oidc/user:alice@example.org → dora:reindex, spamoor",
				"documented: htpasswd/username:ops → (nothing)",
			},
		},
		{
			"grants present but empty: an empty table, and a warning that nobody gets a token",
			[]config.ProviderConfig{cf, oidc}, &issuer.GrantsConfig{}, []string{"nobody gets a token"}, []string{},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{Providers: tc.providers, Grants: tc.grants}
			var grants *issuer.ServiceGrants
			if tc.grants != nil {
				g, err := issuer.NewServiceGrants(*tc.grants, cfg.GrantProviders())
				if err != nil {
					t.Fatalf("grants: %v", err)
				}
				grants = g
			}

			log, hook := test.NewNullLogger()
			logServiceGrants(log, cfg, grants)

			var warns []string
			var table []string
			logged := false
			for _, e := range hook.AllEntries() {
				switch e.Level {
				case logrus.WarnLevel:
					warns = append(warns, e.Message)
				case logrus.InfoLevel:
					logged = true
					table, _ = e.Data["groups"].([]string)
				}
			}
			if len(warns) != len(tc.wantWarn) {
				t.Fatalf("warnings: got %q, want %d", warns, len(tc.wantWarn))
			}
			for i, want := range tc.wantWarn {
				if !strings.Contains(warns[i], want) {
					t.Errorf("warning %q does not contain %q", warns[i], want)
				}
			}
			if logged != (tc.wantTable != nil) {
				t.Fatalf("table logged: %t, want %t", logged, tc.wantTable != nil)
			}
			if !slices.Equal(table, tc.wantTable) {
				t.Errorf("table:\n got %q\nwant %q", table, tc.wantTable)
			}
		})
	}
}

// TestBuildProvider_OIDCBearer: the oidc.bearer block of the config
// reaches the provider, and a config without it builds a provider that
// asks for no token alias.
func TestBuildProvider_OIDCBearer(t *testing.T) {
	log, _ := test.NewNullLogger()
	build := func(bearer config.OIDCBearerConfig) protection.AmbientSwitch {
		t.Helper()
		pc := &config.ProviderConfig{Name: "corp", Type: config.AuthModeOIDC, OIDC: config.OIDCConfig{
			IssuerURL: "https://idp.example.org", ClientID: "authenticatoor", Bearer: bearer,
		}}
		prov, err := buildProvider(log, &config.Config{}, pc, make([]byte, 32), nil)
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		sw, ok := prov.(protection.AmbientSwitch)
		if !ok {
			t.Fatal("the oidc provider does not say whether it takes ambient credentials")
		}
		return sw
	}
	if build(config.OIDCBearerConfig{}).AmbientEnabled() {
		t.Error("bearer is on without the block")
	}
	if !build(config.OIDCBearerConfig{Audiences: []string{"devnet-cli"}}).AmbientEnabled() {
		t.Error("bearer is off although audiences are configured")
	}
}
