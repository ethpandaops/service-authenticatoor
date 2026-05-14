package server

import (
	"encoding/json"
	"net/http"
)

// tokenResponse is the JSON body returned by /auth/token.
type tokenResponse struct {
	Token string `json:"token"`
	User  string `json:"user"`
	Expr  int64  `json:"expr"`
	Now   int64  `json:"now"`
}

// handleToken issues a JWT for the authenticated user. The user identity
// is supplied by authMiddleware.
//
// The optional `aud` query parameter overrides the default audience; every
// requested aud must appear in the configured audience list, otherwise the
// request is rejected. This prevents callers from minting tokens for
// audiences the service isn't authoritative for.
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	id := identityFromContext(r.Context())
	if id == nil || id.Subject == "" {
		// authMiddleware enforces this; defense in depth so a future
		// refactor cannot create an anonymous-token path by accident.
		s.tokenIssueErrors.WithLabelValues("no_identity").Inc()
		http.Error(w, "no authenticated user", http.StatusUnauthorized)
		return
	}

	requested := r.URL.Query()["aud"]
	if !s.audienceAllowed(requested) {
		s.tokenIssueErrors.WithLabelValues("bad_audience").Inc()
		http.Error(w, "requested audience not allowed", http.StatusBadRequest)
		return
	}

	tok, claims, err := s.issuer.Issue(id.Subject, id.Email, requested)
	if err != nil {
		s.tokenIssueErrors.WithLabelValues("issue").Inc()
		s.log.WithError(err).Error("issue token")
		http.Error(w, "issue failed", http.StatusInternalServerError)
		return
	}
	s.tokensIssued.Inc()
	s.log.WithField("sub", id.Subject).WithField("jti", claims.ID).Info("issued token")

	user := id.Email
	if user == "" {
		user = id.Subject
	}
	resp := tokenResponse{
		Token: tok,
		User:  user,
		Expr:  claims.ExpiresAt.Unix(),
		Now:   claims.IssuedAt.Unix(),
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.log.WithError(err).Error("encode token response")
	}
}

// audienceAllowed returns true if every requested audience is in the
// configured audience list. An empty request is allowed (use defaults).
func (s *Server) audienceAllowed(requested []string) bool {
	if len(requested) == 0 {
		return true
	}
	allowed := make(map[string]struct{}, len(s.cfg.Audience))
	for _, a := range s.cfg.Audience {
		allowed[a] = struct{}{}
	}
	for _, r := range requested {
		if _, ok := allowed[r]; !ok {
			return false
		}
	}
	return true
}
