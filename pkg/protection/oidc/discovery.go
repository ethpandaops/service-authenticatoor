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
	EmailVerified verified `json:"email_verified,omitempty"`
	Name          string   `json:"name,omitempty"`
	Groups        []string `json:"groups,omitempty"`
	Nonce         string   `json:"nonce,omitempty"`
}

// idTokenClaimNames are the claims idTokenClaims reads, spelled as the
// specifications spell them.
var idTokenClaimNames = []string{
	"iss", "sub", "aud", "exp", "nbf", "iat", "jti",
	"email", "email_verified", "name", "groups", "nonce",
}

// UnmarshalJSON reads the claims by their exact names. encoding/json
// on its own matches the keys of an object to struct fields without
// regard to case, so "Email_Verified": true would verify an email and
// "Sub" would be a subject — while team rules and grant members, which
// read the same token as a map, take claim names exactly. A claim is
// the one the specification names, or it is another claim.
func (c *idTokenClaims) UnmarshalJSON(data []byte) error {
	var all map[string]json.RawMessage
	if err := json.Unmarshal(data, &all); err != nil {
		return err
	}
	exact := make(map[string]json.RawMessage, len(idTokenClaimNames))
	for _, name := range idTokenClaimNames {
		if value, ok := all[name]; ok {
			exact[name] = value
		}
	}
	filtered, err := json.Marshal(exact)
	if err != nil {
		return err
	}
	// plain has the fields of idTokenClaims without this method.
	type plain idTokenClaims
	var out plain
	if err := json.Unmarshal(filtered, &out); err != nil {
		return err
	}
	*c = idTokenClaims(out)
	return nil
}

// verified is the id_token's email_verified claim. OpenID Connect
// defines it as a JSON boolean; some identity providers send the string
// "true" instead. Both count as verified. Anything else — false, a
// missing claim, another string, another type — does not, and never
// makes the token unreadable.
type verified bool

// UnmarshalJSON accepts true and "true" as verified.
func (v *verified) UnmarshalJSON(data []byte) error {
	switch strings.TrimSpace(string(data)) {
	case "true", `"true"`:
		*v = true
	default:
		*v = false
	}
	return nil
}

// idTokenVerifier validates JWTs of one issuer against its published
// JWKS and checks iss/aud/exp/sub. The callback uses one for the
// id_token of the login flow (audience: the client id, plus the nonce
// of the flow); the bearer path uses one for tokens a non-browser
// client presents (audiences: Config.Bearer.Audiences, no nonce).
type idTokenVerifier struct {
	kf     keyfunc.Keyfunc
	issuer string
	// audiences are the accepted "aud" values: a token must name at
	// least one of them. Never empty.
	audiences []string
	now       func() time.Time
}

// newIDTokenVerifier wires up a background-refreshing JWKS keyfunc against
// the IdP's JWKS URI.
//
// A JWKS that cannot be fetched now is not an error: the keyfunc starts
// without keys, refuses every token, and fetches again every hour and
// when a token names a key it does not know (at most once in five
// minutes).
func newIDTokenVerifier(
	ctx context.Context, jwksURI, issuer string, audiences []string, now func() time.Time,
) (*idTokenVerifier, error) {
	kf, err := keyfunc.NewDefaultCtx(ctx, []string{jwksURI})
	if err != nil {
		return nil, fmt.Errorf("oidc: jwks load %s: %w", jwksURI, err)
	}
	return &idTokenVerifier{
		kf:        kf,
		issuer:    issuer,
		audiences: audiences,
		now:       now,
	}, nil
}

// verify parses and validates the id_token. expectedNonce must equal the
// nonce we sent in the authorize request; an empty value disables the
// nonce check (callers should always pass the originating nonce).
func (v *idTokenVerifier) verify(token, expectedNonce string) (*idTokenClaims, error) {
	claims, err := v.parse(token)
	if err != nil {
		return nil, err
	}
	if expectedNonce != "" && claims.Nonce != expectedNonce {
		return nil, errors.New("id_token nonce mismatch")
	}
	return claims, nil
}

// parse validates everything about a token that does not depend on a
// login flow: the signature against the issuer's JWKS (RS256 only — no
// "none", no HMAC), "iss" equal to the issuer, "aud" naming at least
// one accepted audience (as a string or in a list; "azp" is not looked
// at), "exp" present and in the future, "nbf" when present, and a
// non-empty "sub".
func (v *idTokenVerifier) parse(token string) (*idTokenClaims, error) {
	if len(v.audiences) == 0 {
		// Without an expected audience the parser would not check the
		// claim at all.
		return nil, errors.New("id_token verifier has no audience")
	}
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(v.now),
		jwt.WithIssuer(v.issuer),
		jwt.WithAudience(v.audiences...),
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
	return claims, nil
}

// groupAllowed reports whether any of the token's groups is in the
// allow-list.
//
// Matching rules (case-insensitive):
//   - Exact match: allow-list entry "foo:bar" matches token group "foo:bar".
//   - Org-prefix match: allow-list entry "foo" (no colon) matches both
//     token group "foo" and any "foo:<team>". Lets ops grant access to
//     an entire org without enumerating its teams.
//   - An empty allow-list is treated as "permit all" — the upstream IdP's
//     own gating (e.g. dex's connector `orgs:` filter) is then the
//     authoritative authorization layer.
//
// The matching asymmetry is deliberate: dex's github connector emits
// `<org>:<team>` even for orgs configured without a `teams:` filter, so
// a bare "org" in the allow-list would never match without this rule.
// The exact-match path still allows narrowing to specific teams when
// the allow-list explicitly uses `<org>:<team>`.
func groupAllowed(tokenGroups []string, allowed map[string]struct{}) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, g := range tokenGroups {
		gl := strings.ToLower(g)
		if _, ok := allowed[gl]; ok {
			return true
		}
		if i := strings.IndexByte(gl, ':'); i > 0 {
			if _, ok := allowed[gl[:i]]; ok {
				return true
			}
		}
	}
	return false
}

// allowedGroupsSet lowercases an allow-list into a lookup set so the
// per-request check stays O(1).
func allowedGroupsSet(allowed []string) map[string]struct{} {
	out := make(map[string]struct{}, len(allowed))
	for _, g := range allowed {
		out[strings.ToLower(g)] = struct{}{}
	}
	return out
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
