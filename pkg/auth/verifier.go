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
// success. Implementations check signature, exp, iss, aud, and (optionally)
// scope. The error is non-nil iff verification fails.
type Verifier interface {
	Verify(tokenString string) (*Claims, error)
}

// VerifierConfig configures a JWKSVerifier.
type VerifierConfig struct {
	// JWKSURL is the URL the verifier fetches public keys from.
	JWKSURL string
	// ExpectedIssuer (iss claim). Required.
	ExpectedIssuer string
	// ExpectedAudience (one of aud claim entries). Required.
	ExpectedAudience string
	// ExpectedScope is the scope claim the verifier expects. If empty, scope
	// is not validated. If non-empty, the token's scope must equal it AND, if
	// HostFn is non-nil, the request host must match the pattern.
	ExpectedScope string
	// HostFn returns the host of the current request for scope matching.
	// Optional; if nil, only the equality check on the scope claim runs.
	HostFn func() string
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
// error on any failure (signature, exp, iss, aud, scope).
func (v *JWKSVerifier) Verify(tokenString string) (*Claims, error) {
	if tokenString == "" {
		return nil, errors.New("verifier: empty token")
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

	if v.cfg.ExpectedScope != "" {
		if claims.Scope != v.cfg.ExpectedScope {
			return nil, fmt.Errorf("verifier: scope mismatch: got %q want %q", claims.Scope, v.cfg.ExpectedScope)
		}
		if v.cfg.HostFn != nil {
			host := v.cfg.HostFn()
			if !MatchHost(claims.Scope, host) {
				return nil, fmt.Errorf("verifier: scope %q does not match host %q", claims.Scope, host)
			}
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
