package server

import (
	"encoding/json"
	"net/http"
	"strings"
)

// oidcDiscoveryResponse is the minimal OIDC discovery document we publish.
// Downstream verifiers only need iss + jwks_uri; we list one signing
// algorithm so OIDC-aware client libraries don't fall back to defaults.
type oidcDiscoveryResponse struct {
	Issuer                           string   `json:"issuer"`
	JWKSURI                          string   `json:"jwks_uri"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
}

// handleOIDCConfig serves /.well-known/openid-configuration. We only ever
// sign with RS256.
func (s *Server) handleOIDCConfig(w http.ResponseWriter, r *http.Request) {
	base := strings.TrimRight(s.cfg.ExternalURL, "/")
	resp := oidcDiscoveryResponse{
		Issuer:                           s.cfg.Issuer,
		JWKSURI:                          base + "/jwks.json",
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.log.WithError(err).Debug("encode oidc discovery")
	}
}
