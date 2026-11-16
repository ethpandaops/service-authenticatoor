// Package session provides HMAC-signed session and state cookies for
// cookie-based protection providers (github OAuth, OIDC, ...).
//
// The cookie payloads are tiny HS256 JWTs:
//
//   - Session: carries Subject + Email + the teams derived from the
//     identity source at login, so /auth/* handlers can rebuild a
//     protection.Identity on subsequent requests. Built via Sign /
//     Parse.
//   - State:   carries a random Nonce + the original request URL so the
//     OAuth/OIDC callback can verify the round-trip came from the same
//     browser (CSRF) and redirect back to the originating URL. For OIDC
//     flows the Nonce also seeds the id_token `nonce` claim, giving
//     replay defense on top of CSRF defense. Built via SignState /
//     ParseState.
//
// The signing secret is typically derived from the JWT signing key via
// issuer.DeriveHMACKey, so providers don't need to manage independent
// secret material.
package session

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/ethpandaops/service-authenticatoor/pkg/auth"
	"github.com/ethpandaops/service-authenticatoor/pkg/protection"
)

// Payload is what a session cookie carries about the authenticated user.
type Payload struct {
	// Subject is the stable identifier of the user. Required.
	Subject string
	// Email is the user-facing email; may be empty.
	Email string
	// SubjectIsEmail records what protection.Identity.SubjectIsEmail
	// says: Subject is an email address the provider verified, not a
	// raw provider subject. It is stored in the cookie rather than
	// guessed from the look of the subject when the session is read.
	SubjectIsEmail bool
	// Teams holds the teams the provider derived from its identity
	// source at login (id_token groups, GitHub orgs). The provider's
	// configured static teams are deliberately not stored: they are
	// re-applied from the current config on every request. Empty for
	// sessions issued before the field existed.
	Teams []string
	// Matches holds the attribute members of the grants section that
	// the identity satisfied at login, as "<attribute>:<value>" keys.
	// Only the matches are kept — never the attributes themselves.
	Matches []string
}

// Door identifies the door a session was opened at: the kind of
// provider and what it authenticates against. It is derived by NewDoor
// and stored in every session cookie, inside the signed payload.
//
// The cookie's signing key is derived from the provider's NAME only.
// The name alone does not say what stands behind it: an entry can keep
// its name while its type changes (oidc → basic), or while it is
// pointed at another identity provider. The door does say it, and a
// session only counts for the door it was opened at.
//
// A Door can only be made by NewDoor. The zero value is not a door:
// Sign and Parse refuse it, so no code path can mint or accept a
// session that belongs to no door.
type Door struct {
	id string
}

// NewDoor derives the door of a provider from its kind ("oidc",
// "cloudflare", …) and the details that make it the same door: the
// IdP's issuer, the Cloudflare team. Changing any of them yields
// another door. kind must not be empty; with an empty kind the result
// is the zero Door, which nothing accepts.
func NewDoor(kind string, details ...string) Door {
	if kind == "" {
		return Door{}
	}
	// Every part is written with its length in front, so that no two
	// different lists of parts give the same bytes: with a separator,
	// ("a\x00b") and ("a", "b") would be one door.
	h := sha256.New()
	var size [8]byte
	for _, part := range append([]string{kind}, details...) {
		binary.BigEndian.PutUint64(size[:], uint64(len(part)))
		h.Write(size[:])
		h.Write([]byte(part))
	}
	return Door{id: hex.EncodeToString(h.Sum(nil)[:8])}
}

// String returns the door's identifier, for logs.
func (d Door) String() string { return d.id }

// errNoDoor is returned when Sign or Parse is handed the zero Door.
var errNoDoor = errors.New("session: no door (use session.NewDoor)")

// sessionClaims is the payload of the signed session cookie.
type sessionClaims struct {
	jwt.RegisteredClaims

	Email string   `json:"email,omitempty"`
	Teams []string `json:"teams,omitempty"`
	Match []string `json:"match,omitempty"`
	Door  string   `json:"door,omitempty"`
	// SubjectIsEmail is Payload.SubjectIsEmail ("sem": subject is an
	// email).
	SubjectIsEmail bool `json:"sem,omitempty"`
}

// MaxCookieBytes is the size browsers allow a cookie: its name and its
// value together (RFC 6265bis; Chrome and Firefox enforce exactly
// this). A larger cookie is dropped by the browser without a word, and
// its user would go round the login in circles.
const MaxCookieBytes = 4096

// ErrTooLarge is returned by Sign and SignCookie when the session
// would not fit a cookie. Teams and attribute matches are bounded
// before they get here, so what makes a session too large is a subject
// or an email of several hundred bytes. The login has to be refused.
var ErrTooLarge = errors.New("session: too large for a cookie")

// SignCookie is Sign for a session stored in the cookie called name.
// It fails with ErrTooLarge unless name and value together stay within
// MaxCookieBytes, so a provider never sets a cookie the browser drops.
func SignCookie(
	name string, secret []byte, door Door, p Payload, ttl time.Duration, now time.Time,
) (string, error) {
	signed, err := Sign(secret, door, p, ttl, now)
	if err != nil {
		return "", err
	}
	if size := len(name) + len(signed); size > MaxCookieBytes {
		return "", fmt.Errorf("%w: cookie %q would be %d bytes, browsers allow %d (subject: %d bytes, "+
			"email: %d bytes)", ErrTooLarge, name, size, MaxCookieBytes, len(p.Subject), len(p.Email))
	}
	return signed, nil
}

// Sign produces a compact signed JWT carrying the session payload. ttl
// bounds the cookie's lifetime independently of the cookie's MaxAge so a
// tampered cookie that survives client-side extension still expires
// server-side.
//
// Teams are stored in normal form and capped at auth.MaxTeams entries,
// and the attribute matches share a byte budget with them
// (protection.BoundMatches): 32 names of up to 63 characters make for a
// cookie of about 3.3 KB. Callers are expected to have bounded (and
// logged) both lists already — protection.Teams.Capture and
// protection.Members.Capture do — so the cap here is a backstop that
// does not bite on any path the providers take.
//
// Subject and email have no bound of their own. What is bounded is the
// result: a session larger than a cookie can be is refused with
// ErrTooLarge. Providers that store the session in a cookie use
// SignCookie, which counts the cookie's name as well.
func Sign(secret []byte, door Door, p Payload, ttl time.Duration, now time.Time) (string, error) {
	if door.id == "" {
		return "", errNoDoor
	}
	claims := sessionClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   p.Subject,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
		Email:          p.Email,
		Teams:          boundTeams(p.Teams),
		Door:           door.id,
		SubjectIsEmail: p.SubjectIsEmail,
	}
	claims.Match, _ = protection.BoundMatches(p.Matches, claims.Teams)
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString(secret)
	if err != nil {
		return "", fmt.Errorf("session: sign: %w", err)
	}
	if len(signed) >= MaxCookieBytes {
		return "", fmt.Errorf("%w: the value alone is %d bytes, browsers allow %d for name and value "+
			"(subject: %d bytes, email: %d bytes)", ErrTooLarge, len(signed), MaxCookieBytes,
			len(p.Subject), len(p.Email))
	}
	return signed, nil
}

// Parse verifies the signature and expiration of a session cookie and
// returns the embedded payload. A cookie that fails verification yields
// an error and no payload at all — callers never see unverified teams.
//
// door is the door of the provider reading the cookie. A session opened
// at another door — the provider entry changed its type or its identity
// source while keeping its name — is rejected. So is a cookie without a
// door, as versions before doors issued them: nothing in it says what
// it was opened at, and accepting it would let it count at whatever
// the entry is now. Their users log in again.
func Parse(secret []byte, door Door, raw string, now time.Time) (Payload, error) {
	if door.id == "" {
		return Payload{}, errNoDoor
	}
	if raw == "" {
		return Payload{}, errors.New("session: empty token")
	}
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(func() time.Time { return now }),
	)
	claims := &sessionClaims{}
	tok, err := parser.ParseWithClaims(raw, claims, func(_ *jwt.Token) (any, error) { return secret, nil })
	if err != nil {
		return Payload{}, fmt.Errorf("session: parse: %w", err)
	}
	if !tok.Valid {
		return Payload{}, errors.New("session: token not valid")
	}
	if claims.Subject == "" {
		return Payload{}, errors.New("session: missing subject")
	}
	switch claims.Door {
	case door.id:
		teams := boundTeams(claims.Teams)
		matches, _ := protection.BoundMatches(claims.Match, teams)
		return Payload{
			Subject:        claims.Subject,
			Email:          claims.Email,
			SubjectIsEmail: claims.SubjectIsEmail,
			Teams:          teams,
			Matches:        matches,
		}, nil
	case "":
		return Payload{}, errors.New("session: cookie without a door (issued by an earlier version); log in again")
	default:
		return Payload{}, errors.New("session: opened at another door (the provider's type or identity source changed)")
	}
}

// boundTeams returns the valid team names in normal form, de-duplicated,
// sorted and capped at auth.MaxTeams.
func boundTeams(names []string) []string {
	teams, _ := auth.CanonicalTeams(names)
	if len(teams) > auth.MaxTeams {
		teams = teams[:auth.MaxTeams]
	}
	return teams
}

// stateClaims is the payload of the OAuth state cookie.
type stateClaims struct {
	jwt.RegisteredClaims

	Nonce    string `json:"nonce"`
	ReturnTo string `json:"return_to,omitempty"`
}

// SignState issues the state cookie value, binding the random nonce to
// the originally-requested URL.
func SignState(secret []byte, nonce, returnTo string, now time.Time, ttl time.Duration) (string, error) {
	claims := stateClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
		Nonce:    nonce,
		ReturnTo: returnTo,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString(secret)
	if err != nil {
		return "", fmt.Errorf("state: sign: %w", err)
	}
	return signed, nil
}

// ParseState verifies the state cookie and returns the embedded nonce
// and original-URL.
func ParseState(secret []byte, raw string, now time.Time) (nonce, returnTo string, err error) {
	if raw == "" {
		return "", "", errors.New("state: empty token")
	}
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(func() time.Time { return now }),
	)
	claims := &stateClaims{}
	tok, err := parser.ParseWithClaims(raw, claims, func(_ *jwt.Token) (any, error) { return secret, nil })
	if err != nil {
		return "", "", fmt.Errorf("state: parse: %w", err)
	}
	if !tok.Valid {
		return "", "", errors.New("state: token not valid")
	}
	if claims.Nonce == "" {
		return "", "", errors.New("state: missing nonce")
	}
	return claims.Nonce, claims.ReturnTo, nil
}

// NewNonce returns a 128-bit random base64url-encoded value. Used as
// both the OAuth state nonce (CSRF defense) and the OIDC `nonce`
// authorize-request parameter (id_token replay defense).
func NewNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// LoadSecret returns inline if non-empty, else reads the file. Used to
// load OAuth client secrets from either an inline string (typically
// via env-var injection) or a mounted file. One of the two must be
// non-empty; name is used in error messages.
func LoadSecret(inline, file, name string) ([]byte, error) {
	if inline != "" {
		return []byte(inline), nil
	}
	if file == "" {
		return nil, fmt.Errorf("%s or %sFile is required", name, name)
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", file, err)
	}
	return []byte(strings.TrimSpace(string(data))), nil
}
