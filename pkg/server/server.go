// Package server wires the HTTP routes, middleware, and lifecycle. Two
// listeners are exposed:
//
//   - the main listener serves /auth/*, /jwks.json, OIDC discovery,
//     /healthz, and /
//   - when metrics are enabled, a separate listener serves /metrics
//
// User-facing access control on /auth/* is expected to be enforced at the
// upstream proxy. When configured, this package additionally verifies the
// proxy's assertion JWT on the protected routes.
package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ethpandaops/service-authenticatoor/pkg/cfaccess"
	"github.com/ethpandaops/service-authenticatoor/pkg/config"
	"github.com/ethpandaops/service-authenticatoor/pkg/cors"
	"github.com/ethpandaops/service-authenticatoor/pkg/issuer"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

// Server is the lifecycle-managed HTTP entrypoint for authenticatoor.
type Server struct {
	cfg        *config.Config
	issuer     issuer.Issuer
	cfVerifier cfaccess.Verifier
	log        logrus.FieldLogger

	main    *http.Server
	metrics *http.Server

	tokensIssued     prometheus.Counter
	tokenIssueErrors *prometheus.CounterVec
	loginRedirects   prometheus.Counter
	jwksServes       prometheus.Counter
}

// Options bundles the dependencies needed to construct a Server.
type Options struct {
	Config     *config.Config
	Issuer     issuer.Issuer
	CFVerifier cfaccess.Verifier
	Log        logrus.FieldLogger
	Registry   prometheus.Registerer
}

// New constructs a Server. Heavy initialization (binding sockets) happens in
// Start.
func New(opts Options) (*Server, error) {
	if opts.Config == nil {
		return nil, errors.New("server: Config is required")
	}
	if opts.Issuer == nil {
		return nil, errors.New("server: Issuer is required")
	}
	if opts.CFVerifier == nil {
		return nil, errors.New("server: CFVerifier is required (use cfaccess.NoopVerifier{} to disable)")
	}
	if opts.Log == nil {
		return nil, errors.New("server: Log is required")
	}
	if opts.Registry == nil {
		opts.Registry = prometheus.NewRegistry()
	}

	s := &Server{
		cfg:        opts.Config,
		issuer:     opts.Issuer,
		cfVerifier: opts.CFVerifier,
		log:        opts.Log.WithField("package", "server"),
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
// fails for any reason other than http.ErrServerClosed.
func (s *Server) Start(ctx context.Context) error {
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
	r.HandleFunc("/", s.handleIndex).Methods(http.MethodGet)

	// Protected routes. The upstream proxy enforces user-facing auth on
	// /auth/*; this middleware additionally verifies the proxy's assertion
	// JWT when configured. CORS allows allow-listed browser origins to
	// fetch tokens directly.
	corsMW := cors.Middleware(cors.Config{
		AllowedOriginPatterns: s.cfg.CORS.AllowedOrigins,
		AllowedMethods:        []string{http.MethodGet, http.MethodOptions},
		AllowedHeaders:        []string{"Authorization", "Content-Type"},
		MaxAgeSeconds:         86400,
		AllowCredentials:      true,
	})

	authRouter := r.PathPrefix("/auth").Subrouter()
	authRouter.Use(corsMW)
	authRouter.Use(s.cfAccessMiddleware)
	authRouter.HandleFunc("/token", s.handleToken).Methods(http.MethodGet, http.MethodOptions)
	authRouter.HandleFunc("/login", s.handleLogin).Methods(http.MethodGet)
	authRouter.HandleFunc("/userinfo", s.handleUserinfo).Methods(http.MethodGet, http.MethodOptions)

	// Top-level access logger / panic recovery.
	return s.recover(s.accessLog(r))
}

// cfAccessMiddleware verifies the CF Access assertion JWT (when configured)
// and stamps the authenticated email onto the request context.
//
// When verification is enabled the email comes from the verified assertion,
// not the trust-the-header value, so a forged user-email header alone
// cannot mint a token.
//
// On preflight (OPTIONS) this middleware is a no-op — CORS preflight is
// handled by the cors middleware ahead of it.
func (s *Server) cfAccessMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}

		email := r.Header.Get(s.cfg.UserHeader)

		if s.cfg.CloudflareAccess.VerifyJWT {
			cfJWT := r.Header.Get(s.cfg.CloudflareAccess.JwtHeader)
			if cfJWT == "" {
				http.Error(w, "missing cf access assertion", http.StatusUnauthorized)
				return
			}
			cfClaims, err := s.cfVerifier.Verify(r.Context(), cfJWT)
			if err != nil {
				s.log.WithError(err).Debug("cf access verification failed")
				http.Error(w, "cf access assertion invalid", http.StatusUnauthorized)
				return
			}
			// Trust the verified JWT, not the header.
			email = cfClaims.Email
		}

		if email == "" {
			http.Error(w, "no authenticated user", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r.WithContext(withEmail(r.Context(), email)))
	})
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

// emailKey is the unexported context key used to pass the verified email
// from the CF middleware into the handlers.
type emailKey struct{}

func withEmail(ctx context.Context, email string) context.Context {
	return context.WithValue(ctx, emailKey{}, email)
}

func emailFromContext(ctx context.Context) string {
	v, _ := ctx.Value(emailKey{}).(string)
	return v
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
