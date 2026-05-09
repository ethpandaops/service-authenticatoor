package auth

import (
	"context"
	"net/http"
	"strings"
)

// ctxKey is unexported so claims can only be put on / pulled from a request's
// context via this package's helpers.
type ctxKey struct{}

var claimsKey = ctxKey{}

// Middleware extracts a Bearer token (Authorization header) or a query
// parameter (?auth=) from the request, verifies it via v, and stores the
// resulting claims on the request context.
//
// The middleware does not 401 on its own — handlers decide whether
// authentication is required by calling ClaimsFromContext or wrapping
// themselves in RequireAuth.
func Middleware(v Verifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tok := extractBearer(r)
			if tok == "" {
				next.ServeHTTP(w, r)
				return
			}
			claims, err := v.Verify(tok, WithRequestHost(stripPort(r.Host)))
			if err != nil {
				// Bad token: forward without claims; downstream handler
				// decides whether to 401.
				next.ServeHTTP(w, r)
				return
			}
			ctx := context.WithValue(r.Context(), claimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireAuth wraps a handler to enforce the presence of valid claims. If no
// claims are on the context, the wrapper responds with 401 and does not call
// next.
func RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := ClaimsFromContext(r.Context()); !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// ClaimsFromContext returns the verified claims attached by Middleware. The
// boolean is false when the request was not (successfully) authenticated.
func ClaimsFromContext(ctx context.Context) (*Claims, bool) {
	c, ok := ctx.Value(claimsKey).(*Claims)
	return c, ok
}

// WithClaims returns a context with the supplied claims attached. Exported
// for tests and for any code that needs to inject claims out-of-band.
func WithClaims(ctx context.Context, claims *Claims) context.Context {
	return context.WithValue(ctx, claimsKey, claims)
}

// extractBearer pulls the token from "Authorization: Bearer …" or, as a
// fallback, the "auth" query parameter (useful for EventSource / SSE
// callers that can't set request headers).
func extractBearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if h != "" {
		const prefix = "Bearer "
		if len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
			return strings.TrimSpace(h[len(prefix):])
		}
	}
	if q := r.URL.Query().Get("auth"); q != "" {
		return q
	}
	return ""
}

// stripPort removes a trailing ":port" from a Host header value so it
// can be matched against scope patterns. Handles bracketed IPv6 hosts.
func stripPort(host string) string {
	if host == "" {
		return host
	}
	if host[0] == '[' {
		if i := strings.IndexByte(host, ']'); i >= 0 {
			return host[1:i]
		}
		return host
	}
	if i := strings.LastIndexByte(host, ':'); i >= 0 {
		return host[:i]
	}
	return host
}
