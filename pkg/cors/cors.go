// Package cors provides a CORS middleware with a strict server-side
// allow-list of host patterns. Origins are matched against the configured
// patterns before any Access-Control-Allow-* headers are set; values from
// the request's Origin header are never echoed blindly.
package cors

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/ethpandaops/service-authenticatoor/pkg/auth"
)

// Config configures the CORS middleware.
type Config struct {
	// AllowedOriginPatterns is a list of host glob patterns (same syntax as
	// auth.MatchHost). The middleware echoes the request's Origin only if its
	// hostname matches one of these patterns AND its scheme is http or https.
	AllowedOriginPatterns []string
	// AllowedMethods is sent in Access-Control-Allow-Methods on preflight.
	AllowedMethods []string
	// AllowedHeaders is sent in Access-Control-Allow-Headers on preflight.
	AllowedHeaders []string
	// MaxAgeSeconds is sent in Access-Control-Max-Age on preflight.
	MaxAgeSeconds int
	// AllowCredentials makes Access-Control-Allow-Credentials true.
	AllowCredentials bool
}

// DefaultConfig returns Config with reasonable defaults. Callers must still
// fill in AllowedOriginPatterns.
func DefaultConfig() Config {
	return Config{
		AllowedMethods:   []string{http.MethodGet, http.MethodOptions},
		AllowedHeaders:   []string{"Authorization", "Content-Type"},
		MaxAgeSeconds:    86400,
		AllowCredentials: true,
	}
}

// Middleware returns an http middleware that handles CORS preflight and
// enriches actual responses with the appropriate ACAO headers, but only for
// origins matching the allow-list.
func Middleware(cfg Config) func(http.Handler) http.Handler {
	methods := strings.Join(cfg.AllowedMethods, ", ")
	headers := strings.Join(cfg.AllowedHeaders, ", ")
	var maxAge string
	if cfg.MaxAgeSeconds > 0 {
		maxAge = strconv.Itoa(cfg.MaxAgeSeconds)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" && originAllowed(origin, cfg.AllowedOriginPatterns) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				if cfg.AllowCredentials {
					w.Header().Set("Access-Control-Allow-Credentials", "true")
				}
				if methods != "" {
					w.Header().Set("Access-Control-Allow-Methods", methods)
				}
				if headers != "" {
					w.Header().Set("Access-Control-Allow-Headers", headers)
				}
				if maxAge != "" {
					w.Header().Set("Access-Control-Max-Age", maxAge)
				}
				w.Header().Add("Vary", "Origin")
			}

			// Even disallowed origins get a valid response to OPTIONS so the
			// browser sees a non-network-error; the missing
			// Access-Control-Allow-Origin header is what causes the browser
			// to block the actual request.
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// originAllowed extracts the host from the supplied Origin and returns
// whether it matches any of the allow-list patterns. The scheme must be http
// or https.
func originAllowed(origin string, patterns []string) bool {
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	host := u.Hostname()
	if host == "" {
		return false
	}
	return auth.MatchAnyHost(patterns, host)
}
