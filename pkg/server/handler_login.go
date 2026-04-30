package server

import (
	"net/http"
	"net/url"
	"strconv"

	"github.com/ethpandaops/service-authenticatoor/pkg/auth"
)

// handleLogin mints a JWT and 302s the user to return_to with the token in
// the URL fragment. Fragments aren't sent on subsequent requests, so the
// token stays out of access logs and Referer headers on the receiving end.
//
// The return_to host is validated against AllowedReturnHosts via net/url
// hostname extraction (not substring/regex) — this rejects spoofs like
// https://victim.example.com.attacker.com and userinfo-tricks like
// https://victim.example.com@attacker.com.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	email := emailFromContext(r.Context())
	if email == "" {
		http.Error(w, "no authenticated user", http.StatusUnauthorized)
		return
	}

	returnTo := r.URL.Query().Get("return_to")
	if returnTo == "" {
		http.Error(w, "missing return_to", http.StatusBadRequest)
		return
	}

	dest, host, ok := parseReturnTo(returnTo)
	if !ok || !auth.MatchAnyHost(s.cfg.AllowedReturnHosts, host) {
		s.log.WithField("return_host", host).Warn("return_to rejected")
		http.Error(w, "return_to host not allowed", http.StatusBadRequest)
		return
	}

	tok, claims, err := s.issuer.Issue(email, nil)
	if err != nil {
		s.tokenIssueErrors.WithLabelValues("issue").Inc()
		s.log.WithError(err).Error("issue token")
		http.Error(w, "issue failed", http.StatusInternalServerError)
		return
	}
	s.tokensIssued.Inc()
	s.loginRedirects.Inc()
	s.log.WithField("email", email).WithField("jti", claims.ID).Info("login redirect")

	dest.Fragment = url.Values{
		"auth_token": {tok},
		"exp":        {strconv.FormatInt(claims.ExpiresAt.Unix(), 10)},
	}.Encode()

	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, dest.String(), http.StatusFound)
}

// parseReturnTo parses raw as an absolute http(s) URL and returns the
// parsed URL plus its hostname (lower-cased, no port, no userinfo). Returns
// ok=false if the URL is unusable as a redirect target.
func parseReturnTo(raw string) (parsed *url.URL, host string, ok bool) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, "", false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, "", false
	}
	host = u.Hostname()
	if host == "" {
		return nil, "", false
	}
	return u, host, true
}
