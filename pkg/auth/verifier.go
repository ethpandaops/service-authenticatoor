package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

// Verifier validates a serialized JWT and returns the parsed claims on
// success. Implementations check signature, exp, iss, aud, and
// (optionally) scope/host and services. The error is non-nil iff
// verification fails. VerifyOptions carry per-request information that
// can't come from configuration — currently the request host for scope
// matching.
type Verifier interface {
	Verify(tokenString string, opts ...VerifyOption) (*Claims, error)
}

// VerifyOption customizes a single Verify call. Build with WithRequestHost.
type VerifyOption func(*verifyOpts)

type verifyOpts struct {
	host    string
	hostSet bool
}

// WithRequestHost binds this Verify call to a specific host (typically
// r.Host stripped of any port). The verifier matches this against the
// token's scope claim using MatchHost. Overrides any HostFn set on the
// VerifierConfig. Passing the empty string explicitly disables host
// checking for this call.
func WithRequestHost(host string) VerifyOption {
	return func(o *verifyOpts) {
		o.host = host
		o.hostSet = true
	}
}

// VerifierConfig configures a JWKSVerifier.
type VerifierConfig struct {
	// JWKSURL is the URL the verifier fetches public keys from.
	JWKSURL string
	// ExpectedIssuer (iss claim). Required.
	ExpectedIssuer string
	// ExpectedAudience (one of aud claim entries). Required.
	ExpectedAudience string
	// ExpectedScope, when non-empty, requires the token's scope claim to
	// equal this string exactly. Independent of host matching; most
	// callers should leave it empty and rely on the host check instead.
	ExpectedScope string
	// HostFn returns a static host for scope matching. Per-request hosts
	// should be passed via WithRequestHost rather than this. When both
	// are set, WithRequestHost wins.
	HostFn func() string
	// ExpectedService, when non-empty, gates verification on the token's
	// "services" claim via ServiceAllowed. When empty, the services
	// claim is ignored.
	ExpectedService string
	// RefreshInterval governs how often JWKS is refreshed in the background.
	// Defaults to 5 minutes.
	RefreshInterval time.Duration
	// HTTPClient is used for JWKS fetches; defaults to http.DefaultClient.
	HTTPClient *http.Client
	// Now is overridable for tests; defaults to time.Now.
	Now func() time.Time
}

// JWKSVerifier verifies tokens whose signing keys are published as a JWKS at
// JWKSURL. Keys are cached and refreshed in the background.
type JWKSVerifier struct {
	cfg VerifierConfig
	kf  keyfunc.Keyfunc
}

// NewJWKSVerifier constructs a JWKSVerifier with auto-refreshing key cache.
func NewJWKSVerifier(ctx context.Context, cfg VerifierConfig) (*JWKSVerifier, error) {
	if cfg.JWKSURL == "" {
		return nil, errors.New("verifier: JWKSURL is required")
	}
	if cfg.ExpectedIssuer == "" {
		return nil, errors.New("verifier: ExpectedIssuer is required")
	}
	if cfg.ExpectedAudience == "" {
		return nil, errors.New("verifier: ExpectedAudience is required")
	}
	if cfg.RefreshInterval <= 0 {
		cfg.RefreshInterval = 5 * time.Minute
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = http.DefaultClient
	}

	kf, err := keyfunc.NewDefaultCtx(ctx, []string{cfg.JWKSURL})
	if err != nil {
		return nil, fmt.Errorf("verifier: jwks init: %w", err)
	}

	return &JWKSVerifier{cfg: cfg, kf: kf}, nil
}

// Verify parses and validates a JWT string. Returns nil claims and a non-nil
// error on any failure (signature, exp, iss, aud, scope, host, services).
//
// Use WithRequestHost(r.Host) to enable per-request host binding: the
// token's scope claim must be a host wildcard pattern that matches the
// supplied host. When neither WithRequestHost nor HostFn is set, host
// checking is skipped.
func (v *JWKSVerifier) Verify(tokenString string, opts ...VerifyOption) (*Claims, error) {
	if tokenString == "" {
		return nil, errors.New("verifier: empty token")
	}

	o := verifyOpts{}
	for _, opt := range opts {
		opt(&o)
	}

	claims := &Claims{}
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		jwt.WithIssuer(v.cfg.ExpectedIssuer),
		jwt.WithAudience(v.cfg.ExpectedAudience),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(v.cfg.Now),
	)
	tok, err := parser.ParseWithClaims(tokenString, claims, v.kf.Keyfunc)
	if err != nil {
		return nil, fmt.Errorf("verifier: parse: %w", err)
	}
	if !tok.Valid {
		return nil, errors.New("verifier: token not valid")
	}

	// Scope literal check (rare; most callers leave ExpectedScope empty).
	if v.cfg.ExpectedScope != "" && claims.Scope != v.cfg.ExpectedScope {
		return nil, fmt.Errorf("verifier: scope mismatch: got %q want %q", claims.Scope, v.cfg.ExpectedScope)
	}

	// Host binding. WithRequestHost wins over HostFn; either can be empty
	// to opt out for this call. When a host *is* provided, the token must
	// carry a non-empty scope and that scope must match.
	host := ""
	switch {
	case o.hostSet:
		host = o.host
	case v.cfg.HostFn != nil:
		host = v.cfg.HostFn()
	}
	if host != "" {
		if claims.Scope == "" {
			return nil, errors.New("verifier: host check enabled but token has no scope claim")
		}
		if !MatchHost(claims.Scope, host) {
			return nil, fmt.Errorf("verifier: scope %q does not match host %q", claims.Scope, host)
		}
	}

	// Service ACL.
	if v.cfg.ExpectedService != "" {
		if !ServiceAllowed(claims.Services, v.cfg.ExpectedService) {
			return nil, fmt.Errorf("verifier: service %q not allowed by token (services=%q)",
				v.cfg.ExpectedService, claims.Services)
		}
	}

	return claims, nil
}

// DiscoveryDocument is the minimal subset of an OIDC discovery document
// needed to bootstrap a verifier from the issuer's URL alone.
type DiscoveryDocument struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

// FetchDiscovery fetches /.well-known/openid-configuration relative to
// baseURL and returns the parsed document.
func FetchDiscovery(ctx context.Context, httpClient *http.Client, baseURL string) (*DiscoveryDocument, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	url := strings.TrimRight(baseURL, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("discovery: request: %w", err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("discovery: fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery: status %d", resp.StatusCode)
	}
	var doc DiscoveryDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("discovery: decode: %w", err)
	}
	if doc.Issuer == "" || doc.JWKSURI == "" {
		return nil, errors.New("discovery: missing issuer or jwks_uri")
	}
	return &doc, nil
}
