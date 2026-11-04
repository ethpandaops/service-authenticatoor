package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

// discovery is the subset of the OIDC discovery document the provider
// needs. Fetched once at Start from <issuer>/.well-known/openid-configuration.
type discovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// fetchDiscovery loads and validates the OIDC discovery document. The
// returned issuer is compared against the configured one to detect
// misconfiguration before the first user flow.
func fetchDiscovery(ctx context.Context, client *http.Client, issuerURL string) (*discovery, error) {
	docURL := strings.TrimRight(issuerURL, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, docURL, nil)
	if err != nil {
		return nil, fmt.Errorf("discovery request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("discovery fetch %s: %w", docURL, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("discovery fetch %s: status %d: %s", docURL, resp.StatusCode, body)
	}

	var d discovery
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, fmt.Errorf("discovery decode: %w", err)
	}
	if d.Issuer == "" || d.AuthorizationEndpoint == "" || d.TokenEndpoint == "" || d.JWKSURI == "" {
		return nil, errors.New("discovery: missing required endpoint")
	}
	// Per OIDC Discovery §4.3, the issuer returned in the doc must equal
	// the URL the doc was fetched from (minus the well-known suffix).
	expectIssuer := strings.TrimRight(issuerURL, "/")
	if strings.TrimRight(d.Issuer, "/") != expectIssuer {
		return nil, fmt.Errorf("discovery issuer mismatch: configured %q, document %q", expectIssuer, d.Issuer)
	}
	return &d, nil
}

// idTokenClaims is the subset of the id_token claims the provider reads.
// Standard claims live in RegisteredClaims; nonce / email / groups are
// extensions but ubiquitous (groups is set by dex's github connector
// when the `groups` scope is requested).
type idTokenClaims struct {
	jwt.RegisteredClaims

	Email         string   `json:"email,omitempty"`
	EmailVerified bool     `json:"email_verified,omitempty"`
	Name          string   `json:"name,omitempty"`
	Groups        []string `json:"groups,omitempty"`
	Nonce         string   `json:"nonce,omitempty"`
}

// idTokenVerifier validates dex-issued id_tokens against the published
// JWKS, checks iss/aud/exp, and matches the embedded nonce against the
// value the originating flow generated.
type idTokenVerifier struct {
	kf       keyfunc.Keyfunc
	issuer   string
	clientID string
	now      func() time.Time
}

// newIDTokenVerifier wires up a background-refreshing JWKS keyfunc against
// the IdP's JWKS URI.
func newIDTokenVerifier(ctx context.Context, jwksURI, issuer, clientID string, now func() time.Time) (*idTokenVerifier, error) {
	kf, err := keyfunc.NewDefaultCtx(ctx, []string{jwksURI})
	if err != nil {
		return nil, fmt.Errorf("oidc: jwks load %s: %w", jwksURI, err)
	}
	return &idTokenVerifier{
		kf:       kf,
		issuer:   issuer,
		clientID: clientID,
		now:      now,
	}, nil
}

// verify parses and validates the id_token. expectedNonce must equal the
// nonce we sent in the authorize request; an empty value disables the
// nonce check (callers should always pass the originating nonce).
func (v *idTokenVerifier) verify(token, expectedNonce string) (*idTokenClaims, error) {
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(v.now),
		jwt.WithIssuer(v.issuer),
		jwt.WithAudience(v.clientID),
	)
	claims := &idTokenClaims{}
	tok, err := parser.ParseWithClaims(token, claims, v.kf.Keyfunc)
	if err != nil {
		return nil, fmt.Errorf("id_token parse: %w", err)
	}
	if !tok.Valid {
		return nil, errors.New("id_token not valid")
	}
	if claims.Subject == "" {
		return nil, errors.New("id_token missing sub")
	}
	if expectedNonce != "" && claims.Nonce != expectedNonce {
		return nil, errors.New("id_token nonce mismatch")
	}
	return claims, nil
}

// defaultScopes are requested when Config.Scopes is empty. `openid` is
// required for OIDC; `email` returns the email claim; `groups` instructs
// dex's connectors (notably github) to include the user's groups.
var defaultScopes = []string{"openid", "email", "groups"}

// scopes returns the configured scopes if any, else defaultScopes. The
// returned slice is freshly allocated so callers can safely sort/dedupe.
func scopes(cfg []string) []string {
	if len(cfg) == 0 {
		return slices.Clone(defaultScopes)
	}
	return slices.Clone(cfg)
}
