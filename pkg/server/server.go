// Package server wires the HTTP routes, middleware, and lifecycle. Two
// listeners are exposed:
//
//   - the main listener serves /auth/*, the per-provider login prefixes
//     (/<name>/...), /jwks.json, OIDC discovery, /healthz, and /
//   - when metrics are enabled, a separate listener serves /metrics
//
// /auth/* is gated by an ordered chain of protection.Providers: each
// provider passively inspects the request (session cookie, ambient edge
// headers, Authorization header) and the first Identity wins. When no
// provider authenticates, a single-provider instance applies that
// provider's own outcome (redirect to its login entry, or a challenge),
// and a multi-provider instance redirects to the /login selector page.
package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"

	"github.com/ethpandaops/service-authenticatoor/pkg/config"
	"github.com/ethpandaops/service-authenticatoor/pkg/cors"
	"github.com/ethpandaops/service-authenticatoor/pkg/issuer"
	"github.com/ethpandaops/service-authenticatoor/pkg/protection"
)

// NamedProvider pairs a protection.Provider with its instance name from
// the config. The name doubles as the provider's path prefix (the server
// mounts machine token aliases at /<name>/token) and as the label shown
// on the /login selector page.
type NamedProvider struct {
	Name     string
	Provider protection.Provider
}

// Server is the lifecycle-managed HTTP entrypoint for authenticatoor.
type Server struct {
	cfg       *config.Config
	issuer    issuer.Issuer
	providers []NamedProvider
	// advertised is the subset of providers offered to unauthenticated
	// users (the config's authMode entries, in order): the direct
	// redirect target when it holds one entry, the /login selector's
	// contents otherwise. Every provider in providers authenticates
	// regardless.
	advertised []NamedProvider
	log        logrus.FieldLogger

	main    *http.Server
	metrics *http.Server

	// Built (templated + optionally minified/mapped) client scripts,
	// keyed by embed path plus variant. Sources and cfg are immutable, so
	// entries are built once on first use.
	clientAssetMu    sync.Mutex
	clientAssetCache map[string]*builtClientAsset

	tokensIssued     prometheus.Counter
	tokenIssueErrors *prometheus.CounterVec
	loginRedirects   prometheus.Counter
	jwksServes       prometheus.Counter
}

// Options bundles the dependencies needed to construct a Server.
type Options struct {
	Config    *config.Config
	Issuer    issuer.Issuer
	Providers []NamedProvider
	Log       logrus.FieldLogger
	Registry  prometheus.Registerer
}

// New constructs a Server. Heavy initialization (binding sockets, fetching
// upstream JWKS) happens in Start.
func New(opts Options) (*Server, error) {
	if opts.Config == nil {
		return nil, errors.New("server: Config is required")
	}
	if opts.Issuer == nil {
		return nil, errors.New("server: Issuer is required")
	}
	if len(opts.Providers) == 0 {
		return nil, errors.New("server: at least one Provider is required")
	}
	if opts.Log == nil {
		return nil, errors.New("server: Log is required")
	}
	if opts.Registry == nil {
		opts.Registry = prometheus.NewRegistry()
	}

	s := &Server{
		cfg:              opts.Config,
		issuer:           opts.Issuer,
		providers:        opts.Providers,
		advertised:       advertisedProviders(opts.Config.AuthMode, opts.Providers),
		log:              opts.Log.WithField("package", "server"),
		clientAssetCache: make(map[string]*builtClientAsset, 4),
	}
	s.registerMetrics(opts.Registry)
	s.main = &http.Server{
		Addr:              opts.Config.Listen,
		Handler:           s.routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	if opts.Config.Metrics.Enabled {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.HandlerFor(opts.Registry.(prometheus.Gatherer), promhttp.HandlerOpts{}))
		s.metrics = &http.Server{
			Addr:              opts.Config.Metrics.Listen,
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
		}
	}
	return s, nil
}

// Start binds the HTTP listener(s) and serves until ctx is canceled or Stop
// is called. It returns an error from the underlying ListenAndServe if it
// fails for any reason other than http.ErrServerClosed. The protection
// providers' Start is invoked first; failures there are returned without
// binding any listener.
func (s *Server) Start(ctx context.Context) error {
	for _, np := range s.providers {
		if err := np.Provider.Start(ctx); err != nil {
			return fmt.Errorf("provider %s start: %w", np.Name, err)
		}
	}

	errCh := make(chan error, 2)

	go func() {
		s.log.WithField("addr", s.main.Addr).Info("starting main listener")
		if err := s.main.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("main listener: %w", err)
		}
	}()

	if s.metrics != nil {
		go func() {
			s.log.WithField("addr", s.metrics.Addr).Info("starting metrics listener")
			if err := s.metrics.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("metrics listener: %w", err)
			}
		}()
	}

	select {
	case <-ctx.Done():
		return s.shutdown()
	case err := <-errCh:
		_ = s.shutdown()
		return err
	}
}

// Stop gracefully shuts down the server. Safe to call multiple times.
func (s *Server) Stop() error {
	return s.shutdown()
}

func (s *Server) shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var err error
	if e := s.main.Shutdown(ctx); e != nil && !errors.Is(e, http.ErrServerClosed) {
		err = e
	}
	if s.metrics != nil {
		if e := s.metrics.Shutdown(ctx); e != nil && !errors.Is(e, http.ErrServerClosed) {
			err = e
		}
	}
	for _, np := range s.providers {
		if e := np.Provider.Stop(); e != nil && err == nil {
			err = e
		}
	}
	return err
}

// routes builds the gorilla/mux router with all routes and their middleware
// chains.
func (s *Server) routes() http.Handler {
	r := mux.NewRouter()

	// Public routes (no auth, no CORS needed — server-to-server).
	r.HandleFunc("/healthz", s.handleHealth).Methods(http.MethodGet)
	r.HandleFunc("/jwks.json", s.handleJWKS).Methods(http.MethodGet)
	r.HandleFunc("/.well-known/openid-configuration", s.handleOIDCConfig).Methods(http.MethodGet)
	r.HandleFunc("/client.js", s.handleClientJS).Methods(http.MethodGet)
	r.HandleFunc("/client-v{version:[0-9]{1,2}}.js", s.handleClientJSVersioned).Methods(http.MethodGet)
	r.HandleFunc("/client-v{version:[0-9]{1,2}}.js.map", s.handleClientJSMap).Methods(http.MethodGet)
	r.HandleFunc("/clientFrame", s.handleClientFrame).Methods(http.MethodGet)
	r.HandleFunc("/", s.handleIndex).Methods(http.MethodGet)

	// Provider-owned auxiliary routes (login entries, OAuth callbacks)
	// under each provider's own path prefix. These run without the auth
	// middleware because the request is the act of authenticating. The
	// provider is responsible for any input validation it needs.
	for _, np := range s.providers {
		np.Provider.RegisterRoutes(r)
	}

	// Machine token aliases: providers whose credentials are injected by
	// an edge proxy (Cloudflare Access) get /<name>/token — the same
	// contract as /auth/token, but authenticated purely from the ambient
	// edge credentials. The alias lives inside the provider's prefix so
	// it can stay behind the edge protection when /auth/* is opened up,
	// giving non-interactive clients (CF service tokens) an endpoint
	// that never redirects.
	for _, np := range s.providers {
		if amb, ok := np.Provider.(protection.AmbientAuthenticator); ok {
			r.HandleFunc("/"+np.Name+"/token", s.ambientTokenHandler(amb)).Methods(http.MethodGet)
		}
	}

	// Provider selector: the multi-provider fallback target. With a
	// single provider it just forwards to that provider's login entry.
	r.HandleFunc("/login", s.handleLoginSelector).Methods(http.MethodGet)

	// Protected routes. The active provider's Authenticate is run via
	// authMiddleware; CORS allows allow-listed browser origins to fetch
	// tokens directly.
	corsMW := cors.Middleware(cors.Config{
		AllowedOriginPatterns: s.cfg.CORS.AllowedOrigins,
		AllowedMethods:        []string{http.MethodGet, http.MethodOptions},
		AllowedHeaders:        []string{"Authorization", "Content-Type"},
		MaxAgeSeconds:         86400,
		AllowCredentials:      true,
	})

	authRouter := r.PathPrefix("/auth").Subrouter()
	authRouter.Use(corsMW)
	authRouter.Use(s.authMiddleware)
	authRouter.HandleFunc("/token", s.handleToken).Methods(http.MethodGet, http.MethodOptions)
	authRouter.HandleFunc("/login", s.handleLogin).Methods(http.MethodGet)
	authRouter.HandleFunc("/userinfo", s.handleUserinfo).Methods(http.MethodGet, http.MethodOptions)
	authRouter.HandleFunc("/embed", s.handleEmbed).Methods(http.MethodGet)
	// /auth/logout is in /auth/* so it gets CORS, but the auth
	// middleware skips its identity check so a stale-session user can
	// still log out cleanly. The provider's Logout writes the response.
	authRouter.HandleFunc("/logout", s.handleLogout).Methods(http.MethodGet, http.MethodPost, http.MethodOptions)

	// Top-level access logger / panic recovery.
	return s.recover(s.accessLog(r))
}

// handleLogout clears the authentication state. With a single provider
// it dispatches to that provider's Logout (preserving provider-specific
// behavior like the Cloudflare edge-logout redirect); with several it
// clears every provider's session cookie in one response. It runs
// without an authenticated identity so a user with a stale or missing
// session can still hit it.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if len(s.providers) == 1 {
		s.providers[0].Provider.Logout(w, r)
		return
	}
	for _, np := range s.providers {
		if sc, ok := np.Provider.(protection.SessionClearer); ok {
			http.SetCookie(w, sc.ClearSessionCookie())
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"loggedOut":true}` + "\n"))
}

// authMiddleware runs the protection provider chain on the request and
// stamps the first returned Identity onto the request context. When no
// provider authenticates, a single-provider instance applies that
// provider's own outcome (redirect to its login flow, or Status plus
// challenge headers); a multi-provider instance redirects to the /login
// selector instead — it cannot know which provider the user wants.
//
// On preflight (OPTIONS) the middleware is a no-op — CORS preflight is
// handled by the cors middleware ahead of it. /auth/logout is also
// skipped so a stale-session user can clear their state.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions || isLogoutPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// Every defined provider gets a passive shot at the request;
		// the fallback for unauthenticated requests comes from the
		// advertised set only.
		var fallback protection.Outcome
		for _, np := range s.providers {
			out, err := np.Provider.Authenticate(r.Context(), r)
			if err != nil {
				s.log.WithError(err).WithField("provider", np.Name).Error("provider authenticate")
				http.Error(w, "auth provider error", http.StatusInternalServerError)
				return
			}
			if out.Identity != nil {
				for _, c := range out.SetCookies {
					http.SetCookie(w, c)
				}
				next.ServeHTTP(w, r.WithContext(withIdentity(r.Context(), out.Identity)))
				return
			}
			if len(s.advertised) == 1 && np.Name == s.advertised[0].Name {
				fallback = out
			}
		}

		if len(s.advertised) != 1 {
			w.Header().Set("Cache-Control", "no-store")
			http.Redirect(w, r, "/login?"+url.Values{"return_to": {r.URL.RequestURI()}}.Encode(),
				http.StatusFound)
			return
		}

		for _, c := range fallback.SetCookies {
			http.SetCookie(w, c)
		}

		if fallback.RedirectTo != "" {
			w.Header().Set("Cache-Control", "no-store")
			http.Redirect(w, r, fallback.RedirectTo, http.StatusFound)
			return
		}

		// Suppress WWW-Authenticate-style challenges on /auth/embed so
		// invisible iframes don't trigger a credential dialog.
		if !isEmbedPath(r.URL.Path) {
			for k, vs := range fallback.Challenge {
				for _, v := range vs {
					w.Header().Add(k, v)
				}
			}
		}
		status := fallback.Status
		if status == 0 {
			status = http.StatusUnauthorized
		}
		http.Error(w, "unauthorized", status)
	})
}

// ambientTokenHandler adapts the /auth/token contract onto a provider's
// ambient edge credentials. No cookies, no redirects: either the edge
// injected a verifiable identity or the response is the outcome's status.
func (s *Server) ambientTokenHandler(amb protection.AmbientAuthenticator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		out, err := amb.AuthenticateAmbient(r.Context(), r)
		if err != nil {
			s.log.WithError(err).Error("ambient authenticate")
			http.Error(w, "auth provider error", http.StatusInternalServerError)
			return
		}
		if out.Identity == nil {
			status := out.Status
			if status == 0 {
				status = http.StatusUnauthorized
			}
			http.Error(w, "unauthorized", status)
			return
		}
		s.handleToken(w, r.WithContext(withIdentity(r.Context(), out.Identity)))
	}
}

// isEmbedPath reports whether p targets the silent-iframe handler. The
// /auth subrouter strips the prefix before matching, so subrouter handlers
// see "/embed"; the top-level recover/accessLog stack sees "/auth/embed".
// Both forms appear depending on where the middleware sits.
func isEmbedPath(p string) bool {
	return p == "/auth/embed" || p == "/embed"
}

// isLogoutPath reports whether p targets the logout handler. The auth
// middleware skips identity checks here so a stale-session user can still
// clear their state.
func isLogoutPath(p string) bool {
	return p == "/auth/logout" || p == "/logout"
}

// accessLog writes one structured log line per request. It intentionally
// omits the response body, the Authorization header, and any Location
// header — Location may carry a token in the URL fragment of /auth/login
// redirects.
func (s *Server) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)
		s.log.WithFields(logrus.Fields{
			"method": r.Method,
			"path":   r.URL.Path,
			"status": rw.status,
			"dur_ms": time.Since(start).Milliseconds(),
			"remote": clientIP(r),
		}).Info("request")
	})
}

func (s *Server) recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.log.WithField("panic", rec).Error("panic in handler")
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// identityKey is the unexported context key used to pass the verified
// identity from the auth middleware into the handlers.
type identityKey struct{}

func withIdentity(ctx context.Context, id *protection.Identity) context.Context {
	return context.WithValue(ctx, identityKey{}, id)
}

func identityFromContext(ctx context.Context) *protection.Identity {
	v, _ := ctx.Value(identityKey{}).(*protection.Identity)
	return v
}

// advertisedProviders resolves the authMode names against the provider
// list, preserving authMode order. Unknown names are skipped (config
// validation rejects them for loaded configs; hand-built test configs
// fall back gracefully). An empty result advertises everything.
func advertisedProviders(names []string, providers []NamedProvider) []NamedProvider {
	byName := make(map[string]NamedProvider, len(providers))
	for _, np := range providers {
		byName[np.Name] = np
	}
	out := make([]NamedProvider, 0, len(names))
	for _, name := range names {
		if np, ok := byName[name]; ok {
			out = append(out, np)
		}
	}
	if len(out) == 0 {
		return providers
	}
	return out
}

// clientIP returns the remote IP, preferring X-Forwarded-For when present.
// Used for logging only — never trust this for auth decisions.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// First IP in the comma-separated list is the original client.
		first, _, _ := strings.Cut(xff, ",")
		return strings.TrimSpace(first)
	}
	return r.RemoteAddr
}

// registerMetrics creates and registers Prometheus metrics on the supplied
// registry. Names follow the prom convention.
func (s *Server) registerMetrics(reg prometheus.Registerer) {
	s.tokensIssued = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "authenticatoor_tokens_issued_total",
		Help: "Total number of JWTs successfully issued.",
	})
	s.tokenIssueErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "authenticatoor_token_issue_errors_total",
		Help: "Total number of token issuance errors, labeled by reason.",
	}, []string{"reason"})
	s.loginRedirects = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "authenticatoor_login_redirects_total",
		Help: "Total number of /auth/login redirects served.",
	})
	s.jwksServes = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "authenticatoor_jwks_serves_total",
		Help: "Total number of /jwks.json responses served.",
	})

	reg.MustRegister(s.tokensIssued, s.tokenIssueErrors, s.loginRedirects, s.jwksServes)
}
