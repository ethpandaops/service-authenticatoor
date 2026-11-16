// Package issuer mints RS256-signed JWTs and publishes the matching JWKS.
//
// The issuer is the private side of the auth service; downstream verifiers
// only need the public JWKS exposed by JWKS().
package issuer

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/ethpandaops/service-authenticatoor/pkg/auth"
)

// Issuer mints signed JWTs and exposes the public key material verifiers
// need to validate them.
type Issuer interface {
	// Issue mints a token for the supplied subject and email. If audience
	// is non-nil it overrides the issuer's default audience for this
	// token. Subject and email are kept separate so providers like the
	// GitHub OAuth provider can put a stable login in "sub" while still
	// emitting a "email" claim — downstream services pick whichever
	// fits their model.
	//
	// The token is that of an identity about which nothing else is
	// known: it carries no teams, and since service grants name their
	// members by provider, it is a member of no group — on an instance
	// with grants its services claim is "-all". Issue is the one path
	// that mints for an identity no group names; it is here for callers
	// from before identities. Nothing that serves a user may use it:
	// the server mints through IdentityIssuer.IssueFor only, which
	// refuses such an identity (ErrNotGranted).
	Issue(subject, email string, audience []string) (token string, claims *auth.Claims, err error)
	// JWKS returns the set of public keys (active + previous) as serialized
	// JSON.
	JWKS() ([]byte, error)
	// ActiveKeyID returns the kid currently used for signing.
	ActiveKeyID() string
}

// Identity is what the issuer is told about the user a token is for.
type Identity struct {
	// Subject is the "sub" claim. Required.
	Subject string
	// Email is the "email" claim; may be empty. Providers only put an
	// address here that was verified to belong to the user.
	Email string
	// SubjectIsEmail reports that Subject is an email address the
	// provider verified, as opposed to a raw provider subject (an IdP
	// "sub", a login, a service token id). It never goes into the
	// token. Service grants need it: a "user:" member that names an
	// email address must not match a raw subject that only looks like
	// one.
	SubjectIsEmail bool
	// Teams becomes the "teams" claim. Only names in normal form are
	// kept (nothing is folded); they are de-duplicated, sorted and
	// capped at auth.MaxTeams, and the claim is omitted when none
	// remains. With service grants configured, the teams also decide
	// the "services" claim.
	Teams []string
	// Matches are the attribute members of the grants section that the
	// provider found the identity to satisfy, as "<attribute>:<value>"
	// keys. They never go into the token.
	Matches []string
	// Provider is the name of the provider that authenticated the
	// identity. It never goes into the token. Service grants name their
	// members together with a provider, so an identity without one is a
	// member of no group.
	Provider string
}

// IdentityIssuer is an Issuer that can mint a token for a full
// Identity. It is a separate interface so that Issuer — which code
// outside this repository implements and calls — keeps the shape it has
// always had.
type IdentityIssuer interface {
	Issuer
	// IssueFor mints a token for the identity. If audience is non-nil
	// it overrides the issuer's default audience for this token.
	//
	// With service grants configured, an identity that no group names
	// gets no token: the error is ErrNotGranted (test it with
	// errors.Is). Without grants every identity gets one.
	IssueFor(id Identity, audience []string) (token string, claims *auth.Claims, err error)
	// Granted reports whether IssueFor would mint a token for the
	// identity as far as the grants go: always true without service
	// grants, otherwise whether a group names the identity.
	Granted(id Identity) bool
}

// PreviousKey is a public-only key kept in the JWKS during rotation so
// already-issued tokens still verify until they expire.
type PreviousKey struct {
	KeyID  string
	Public *rsa.PublicKey
}

// Config is the static configuration of an RS256Issuer.
type Config struct {
	// ActiveKey is the RSA private key currently used for signing.
	ActiveKey *rsa.PrivateKey
	// ActiveKeyID is the kid put in the JWT header. If empty, derived from
	// the active public key.
	ActiveKeyID string
	// Previous holds public keys retained in JWKS during rotation.
	Previous []PreviousKey
	// Issuer is the canonical URL of the auth service ("iss" claim).
	Issuer string
	// DefaultAudience is the "aud" claim when the caller doesn't override it.
	DefaultAudience []string
	// Scope is the "scope" claim — a host wildcard pattern.
	Scope string
	// Services is the default "services" claim — a comma-separated
	// allow/deny directive list (see auth.ServiceAllowed). Empty means
	// no constraint is encoded into the token: downstream verifiers
	// will accept it for any service, with basic access and no granted
	// feature. A blank value is treated as
	// empty. When Grants is set, this is the upper bound on base access
	// and must not name features (no ":").
	Services string
	// Grants, when non-nil, makes the "services" claim depend on the
	// identity: each token carries the directive computed by
	// ServiceGrants.Directive, with Services as the upper bound, and an
	// identity that no group names gets no token (ErrNotGranted). When
	// nil, every token carries Services as it is.
	Grants *ServiceGrants
	// TTL is how long issued tokens are valid for.
	TTL time.Duration
	// Now is overridable for tests; defaults to time.Now.
	Now func() time.Time
}

// RS256Issuer signs JWTs with RS256.
type RS256Issuer struct {
	cfg       Config
	jwks      []byte
	activeKid string
}

// NewRS256Issuer builds an RS256Issuer. It derives the active kid if not
// configured and pre-marshals the JWKS.
func NewRS256Issuer(cfg Config) (*RS256Issuer, error) {
	if cfg.ActiveKey == nil {
		return nil, fmt.Errorf("issuer: active key is required")
	}
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("issuer: issuer URL is required")
	}
	if cfg.TTL <= 0 {
		return nil, fmt.Errorf("issuer: TTL must be positive")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}

	// A blank directive is no directive. Left as it is it would be
	// minted as a non-empty claim (" ") that verifiers do not read as
	// the absent claim.
	cfg.Services = strings.TrimSpace(cfg.Services)
	// With grants, Services is the upper bound on base access, and only
	// that. A bound naming features has no consistent meaning: it would
	// take a feature from an identity granted "all" but not from one
	// granted the service alone, and verifiers from before features
	// would read it differently from current ones.
	if cfg.Grants != nil && strings.Contains(cfg.Services, ":") {
		return nil, fmt.Errorf("issuer: Services %q names features (\":\"); together with Grants the "+
			"instance-wide directive bounds base access only and must consist of +service / -service "+
			"entries", cfg.Services)
	}

	kid := cfg.ActiveKeyID
	if kid == "" {
		kid = DeriveKeyID(&cfg.ActiveKey.PublicKey)
	}

	jwks := JWKS{Keys: make([]JWK, 0, 1+len(cfg.Previous))}
	jwks.Keys = append(jwks.Keys, PublicKeyToJWK(&cfg.ActiveKey.PublicKey, kid))
	for _, p := range cfg.Previous {
		jwks.Keys = append(jwks.Keys, PublicKeyToJWK(p.Public, p.KeyID))
	}
	out, err := json.Marshal(jwks)
	if err != nil {
		return nil, fmt.Errorf("marshal JWKS: %w", err)
	}

	return &RS256Issuer{cfg: cfg, jwks: out, activeKid: kid}, nil
}

var _ IdentityIssuer = (*RS256Issuer)(nil)

// Issue mints and signs a JWT for the supplied subject and email, with
// no teams. It is the token of an identity about which nothing else is
// known; with service grants its services claim is "-all" (see
// Issuer.Issue).
func (i *RS256Issuer) Issue(subject, email string, audience []string) (string, *auth.Claims, error) {
	services := i.cfg.Services
	if i.cfg.Grants != nil {
		services = noServices
	}
	return i.mint(Identity{Subject: subject, Email: email}, nil, services, audience)
}

// Granted reports whether a group of the service grants names the
// identity; true when there are no service grants.
func (i *RS256Issuer) Granted(id Identity) bool {
	if i.cfg.Grants == nil {
		return true
	}
	id.Teams = claimTeams(id.Teams)
	return i.cfg.Grants.Member(id)
}

// IssueFor mints and signs a JWT for the identity. With service grants
// it returns ErrNotGranted, and no token, for an identity that no group
// names.
func (i *RS256Issuer) IssueFor(id Identity, audience []string) (string, *auth.Claims, error) {
	// The grant is computed from the teams as they go into the token.
	teams := claimTeams(id.Teams)
	services := i.cfg.Services
	if i.cfg.Grants != nil {
		id.Teams = teams
		directive, err := i.cfg.Grants.Directive(id, i.cfg.Services)
		if err != nil {
			return "", nil, err
		}
		services = directive
	}
	return i.mint(id, teams, services, audience)
}

// mint signs a JWT for the identity with the teams and services claims
// the caller decided on.
func (i *RS256Issuer) mint(
	id Identity, teams []string, services string, audience []string,
) (string, *auth.Claims, error) {
	subject, email := id.Subject, id.Email
	if subject == "" {
		return "", nil, fmt.Errorf("issuer: subject is required")
	}

	aud := audience
	if len(aud) == 0 {
		aud = i.cfg.DefaultAudience
	}

	now := i.cfg.Now()
	jti, err := randomJTI()
	if err != nil {
		return "", nil, fmt.Errorf("issuer: jti: %w", err)
	}

	claims := &auth.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    i.cfg.Issuer,
			Subject:   subject,
			Audience:  jwt.ClaimStrings(aud),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(i.cfg.TTL)),
			ID:        jti,
		},
		Email:    email,
		Scope:    i.cfg.Scope,
		Services: services,
		Teams:    teams,
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = i.activeKid

	signed, err := tok.SignedString(i.cfg.ActiveKey)
	if err != nil {
		return "", nil, fmt.Errorf("issuer: sign: %w", err)
	}
	return signed, claims, nil
}

// claimTeams puts a team list into the form the "teams" claim carries:
// names in normal form only (nothing is folded), de-duplicated, sorted and capped at
// auth.MaxTeams. Providers hand over lists that already have this form;
// the issuer re-applies it so nothing malformed or unbounded can reach a
// token whatever the caller. nil (claim omitted) when no team remains.
func claimTeams(teams []string) []string {
	out, _ := auth.CanonicalTeams(teams)
	if len(out) > auth.MaxTeams {
		out = out[:auth.MaxTeams]
	}
	return out
}

// JWKS returns a copy of the pre-marshaled JWKS bytes.
func (i *RS256Issuer) JWKS() ([]byte, error) {
	out := make([]byte, len(i.jwks))
	copy(out, i.jwks)
	return out, nil
}

// ActiveKeyID returns the kid used for new tokens.
func (i *RS256Issuer) ActiveKeyID() string {
	return i.activeKid
}

// randomJTI returns a 128-bit random base64url-encoded value.
func randomJTI() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
