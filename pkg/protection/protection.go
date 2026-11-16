// Package protection authenticates incoming requests against an upstream
// identity source — Cloudflare Access, HTTP Basic auth, GitHub OAuth, etc.
//
// authenticatoor's /auth/* endpoints are gated by one or more Providers,
// configured at startup via the providers list (or the legacy authMode
// field, which promotes to a single-entry list). On each request the auth
// middleware runs every provider's Authenticate in order and the first
// Identity wins. Authenticate is passive: it only inspects credentials
// already on the request (a session cookie, ambient headers injected by
// an edge proxy, an Authorization header) and never initiates a login
// flow itself. When no provider authenticates the request, the middleware
// falls back to the single provider's Outcome (redirect / challenge), or
// — with multiple providers — redirects to the provider selector page.
//
// Interactive login lives on per-provider entry paths (e.g.
// /cfaccess/login, /htpasswd/login, /github/login). Those routes convert
// a successful upstream authentication into a signed session cookie and
// redirect back to the originally-requested /auth/* URL. This keeps
// /auth/* independent of any edge protection: an instance whose edge
// proxy (Cloudflare Access) still covers /auth/* authenticates via the
// ambient headers and never redirects, while an instance that narrows
// the edge protection to the provider's login prefix authenticates via
// the session cookie.
package protection

import (
	"context"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
)

// Identity is the authenticated user as seen by /auth/* handlers and the
// JWT issuer. Subject is the stable identifier (email for Cloudflare
// Access, GitHub login for the GitHub provider). Email is the user-facing
// email when available; it may be empty (for example when a GitHub user
// has hidden every address on their account). A provider only sets an
// Email that was verified to belong to the user.
//
// Teams lists the teams the authenticating provider resolved for the
// user, in normal form (see auth.NormalizeTeam), de-duplicated, sorted
// and bounded by auth.MaxTeams; nil when there are none. It only ever
// holds what the provider that produced this Identity resolved — its
// configured static teams plus whatever it derived from its identity
// source at login — never anything taken from the request itself.
type Identity struct {
	Subject string
	Email   string
	// SubjectIsEmail reports what kind of identifier Subject is: true
	// when it is an email address the provider verified to belong to
	// the user, false when it is a raw provider subject — an IdP "sub",
	// a GitHub login, a username, a service token id. Every provider
	// has to say which; the zero value is the safe one. A raw subject
	// can look like an email address without anyone having checked it,
	// and a grant that names an address must not be given to it.
	SubjectIsEmail bool
	Teams          []string
	// Matches lists the attribute members of the grants section that
	// the identity satisfies at this provider, as "<attribute>:<value>"
	// keys (see MatchKey). Like Teams it only holds what the provider
	// that produced this Identity established from attributes it
	// verified. It is not put into tokens.
	Matches []string
	// Provider is the instance name of the provider that authenticated
	// the identity. The server sets it after a provider returned the
	// identity; providers leave it empty. It is not put into tokens.
	Provider string
}

// Outcome describes what the auth middleware should do next after a
// provider has inspected a request. Exactly one of Identity / RedirectTo
// is set on success or flow-required; otherwise the middleware writes
// Status (default 401) with the optional Challenge headers attached.
type Outcome struct {
	// Identity is set when the request carries valid authentication.
	Identity *Identity
	// RedirectTo is set when the provider needs to send the user to a
	// login flow (e.g. its own login entry path). The middleware emits a
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
	// before the redirect / status code. Use a cookie with MaxAge=-1
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
	// Authenticate passively inspects the request — session cookie,
	// ambient proxy headers, Authorization header — and returns the
	// outcome. It must not initiate a login flow with side effects (no
	// state cookies); an unauthenticated outcome either points at the
	// provider's login entry (RedirectTo) or carries a challenge.
	Authenticate(ctx context.Context, r *http.Request) (Outcome, error)
	// LoginURL returns the URL of the provider's interactive login entry
	// point, carrying returnTo (a same-origin path to resume after
	// login). The selector page links here; the provider's own
	// unauthenticated Outcome typically redirects here too. Empty when
	// the provider has no interactive entry.
	LoginURL(returnTo string) string
	// Logout writes the appropriate logout response for this provider.
	// Called from /auth/logout when this provider is the only one
	// configured. Cookie-based providers clear their session cookie;
	// Basic-shaped providers explain the browser credential cache;
	// proxy-trusted providers point the user at the upstream's logout
	// URL. With multiple providers the server clears every provider's
	// session cookie instead (see SessionClearer).
	Logout(w http.ResponseWriter, r *http.Request)
	// RegisterRoutes lets the provider attach auxiliary public routes
	// (login entries, OAuth callbacks) that don't go through the auth
	// middleware. May be a no-op.
	RegisterRoutes(r *mux.Router)
}

// AmbientAuthenticator is implemented by providers whose credentials ride
// on the request itself, injected by an edge proxy (e.g. Cloudflare
// Access assertion headers). The server mounts a machine-friendly token
// alias (/<name>/token) for these providers: the alias path can stay
// behind the edge protection while /auth/* is opened up, so
// non-interactive clients (service tokens) keep a direct JSON endpoint
// that never redirects.
type AmbientAuthenticator interface {
	// AuthenticateAmbient inspects only the ambient edge credentials —
	// no session cookies, no redirects. The outcome carries either an
	// Identity or an unauthenticated Status.
	AuthenticateAmbient(ctx context.Context, r *http.Request) (Outcome, error)
}

// AmbientSwitch is implemented by an AmbientAuthenticator for which
// authenticating from the request itself is a setting (the oidc
// provider's bearer tokens). The server mounts the token alias of such
// a provider only when AmbientEnabled reports true; a provider without
// this method always gets it.
type AmbientSwitch interface {
	// AmbientEnabled reports whether the provider is configured to
	// authenticate ambient credentials. It is called before Start.
	AmbientEnabled() bool
}

// SessionClearer is implemented by providers that track their session in
// a clearable cookie. The server's multi-provider logout collects and
// clears every provider's session cookie in one response.
type SessionClearer interface {
	// ClearSessionCookie returns a cookie that deletes the provider's
	// session cookie (MaxAge=-1, attributes matching the live cookie).
	ClearSessionCookie() *http.Cookie
}

// SessionTooLargeMessage is what a login entry answers (with 403) when
// the session of the identity it just authenticated would not fit a
// cookie (session.ErrTooLarge). Setting the cookie anyway would have
// the browser drop it and send the user round the login again.
const SessionTooLargeMessage = "login refused: your subject and email are too long to be stored in a " +
	"session cookie. Ask the operator of this service"

// SafeReturnTo sanitizes a return_to value supplied to a login entry
// path. Only same-origin relative paths are accepted — absolute URLs and
// protocol-relative forms ("//", "/\") would turn the login entry into
// an open redirect. Invalid or empty values fall back to "/".
func SafeReturnTo(raw string) string {
	if raw == "" || !strings.HasPrefix(raw, "/") {
		return "/"
	}
	if strings.HasPrefix(raw, "//") || strings.HasPrefix(raw, "/\\") {
		return "/"
	}
	return raw
}
