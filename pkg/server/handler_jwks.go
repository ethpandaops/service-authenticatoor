package server

import (
	"net/http"
)

// handleJWKS serves the issuer's public keys in JWKS format. The endpoint
// is intentionally outside /auth/* so verifiers can fetch it without
// passing through the upstream proxy's user authentication.
func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	raw, err := s.issuer.JWKS()
	if err != nil {
		s.log.WithError(err).Error("marshal jwks")
		http.Error(w, "jwks unavailable", http.StatusInternalServerError)
		return
	}
	s.jwksServes.Inc()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	if _, err := w.Write(raw); err != nil {
		s.log.WithError(err).Debug("write jwks response")
	}
}
