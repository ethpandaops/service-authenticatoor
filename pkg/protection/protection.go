// Package protection authenticates incoming requests against an upstream
// identity source — Cloudflare Access, HTTP Basic auth, GitHub OAuth, etc.
//
// authenticatoor's /auth/* endpoints are gated by exactly one Provider per
// process, selected at startup by the authMode config field. Each provider
// inspects the incoming request and returns an Outcome describing the next
// step: an Identity (the request is authenticated), a RedirectTo URL (the
// provider needs to send the user through a flow), or a Status (typically
// 401, optionally with WWW-Authenticate Challenge headers).
package protection

import (
	"context"
	"net/http"

	"github.com/gorilla/mux"
)

// Identity is the authenticated user as seen by /auth/* handlers and the
// JWT issuer. Subject is the stable identifier (email for Cloudflare
// Access, GitHub login for the GitHub provider). Email is the user-facing
// email when available; it may be empty (for example when a GitHub user
// has hidden every address on their account).
type Identity struct {
	Subject string
	Email   string
}

// Outcome describes what the auth middleware should do next after a
// provider has inspected a request. Exactly one of Identity / RedirectTo
// is set on success or flow-required; otherwise the middleware writes
// Status (default 401) with the optional Challenge headers attached.
type Outcome struct {
	// Identity is set when the request carries valid authentication.
	Identity *Identity
	// RedirectTo is set when the provider needs to send the user to a
	// login flow (e.g. a GitHub authorize URL). The middleware emits a
	// 302 to this URL.
	RedirectTo string
	// Challenge holds headers the middleware writes before the 401
	// response (e.g. "WWW-Authenticate: Basic realm=…"). Ignored when
	// Identity or RedirectTo is set.
	Challenge http.Header
	// Status overrides the default 401 status when no Identity or
	// RedirectTo is set. Only meaningful for the unauthenticated path.
	Status int
	// SetCookies holds cookies the middleware writes on the response
	// before the redirect / status code (e.g. an OAuth state cookie set
	// alongside the redirect to the IdP). Use a cookie with MaxAge=-1
	// to clear an existing cookie.
	SetCookies []*http.Cookie
}

// Provider authenticates requests for a single auth backend. Implementations
// must be safe for concurrent use after Start completes.
type Provider interface {
	// Name returns a short identifier used in startup logs.
	Name() string
	// Start performs heavy initialization (e.g. fetching an upstream
	// JWKS). Called once before the server starts accepting traffic.
	Start(ctx context.Context) error
	// Stop releases any resources held by the provider. Called once on
	// shutdown.
	Stop() error
	// Authenticate inspects the request and returns the outcome.
	Authenticate(ctx context.Context, r *http.Request) (Outcome, error)
	// Logout writes the appropriate logout response for this provider.
	// Called from /auth/logout regardless of the request's authentication
	// state. Cookie-based providers clear their session cookie; Basic-
	// shaped providers return 401 with a rotated realm to coax the
	// browser to drop cached credentials; proxy-trusted providers point
	// the user at the upstream's logout URL.
	Logout(w http.ResponseWriter, r *http.Request)
	// RegisterRoutes lets the provider attach auxiliary public routes
	// (e.g. /auth/oauth/callback) that don't go through the auth
	// middleware. May be a no-op.
	RegisterRoutes(r *mux.Router)
}
