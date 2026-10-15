package oidc

import (
	"io"
	"testing"

	"github.com/sirupsen/logrus"
)

// TestStatePrefix pins the relay routing contract: the relay redirects
// to <statePrefix>/callback, so the prefix must be the public URL plus
// the callback path with exactly its "/callback" suffix removed.
func TestStatePrefix(t *testing.T) {
	log := logrus.New()
	log.SetOutput(io.Discard)

	tests := []struct {
		name         string
		publicURL    string
		callbackPath string
		want         string
	}{
		{"default path", "https://auth.example", "", "https://auth.example/oidc"},
		{"named instance", "https://auth.example/", "/corp/callback", "https://auth.example/corp"},
		{"legacy path", "https://auth.example", "/auth/oidc/callback", "https://auth.example/auth/oidc"},
		{"no callback suffix", "https://auth.example", "/cb", "https://auth.example/cb"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := New(log, Config{PublicURL: tc.publicURL, CallbackPath: tc.callbackPath})
			if got := p.statePrefix(); got != tc.want {
				t.Errorf("statePrefix: got %q, want %q", got, tc.want)
			}
		})
	}
}
