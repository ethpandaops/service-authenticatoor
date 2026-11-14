package server

import (
	"encoding/json"
	"net/http"
	"time"
)

// userinfoResponse is the small introspection blob returned by /auth/userinfo.
// Used by web UIs to display "logged in as alice@" without parsing the JWT.
// Teams mirrors the "teams" claim a token minted right now would carry.
type userinfoResponse struct {
	Email string   `json:"email"`
	Sub   string   `json:"sub"`
	Teams []string `json:"teams"`
	Aud   []string `json:"aud"`
	Scope string   `json:"scope"`
	Exp   int64    `json:"exp"`
	Now   int64    `json:"now"`
}

// handleUserinfo returns identity & scope details for the authenticated
// caller. Unlike /auth/token it does not mint a JWT — it's a cheap "who am
// I" probe that frontends can call any time.
func (s *Server) handleUserinfo(w http.ResponseWriter, r *http.Request) {
	id := identityFromContext(r.Context())
	if id == nil || id.Subject == "" {
		http.Error(w, "no authenticated user", http.StatusUnauthorized)
		return
	}

	// Always an array (never null) so frontends can iterate it as-is.
	teams := id.Teams
	if teams == nil {
		teams = []string{}
	}

	resp := userinfoResponse{
		Email: id.Email,
		Sub:   id.Subject,
		Teams: teams,
		Aud:   s.cfg.Audience,
		Scope: s.cfg.ScopePattern,
		Exp:   time.Now().Add(s.cfg.TokenTTL).Unix(),
		Now:   time.Now().Unix(),
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.log.WithError(err).Error("encode userinfo response")
	}
}
