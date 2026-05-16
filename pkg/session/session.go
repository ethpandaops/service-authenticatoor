// Package session provides HMAC-signed session and state cookies for
// cookie-based protection providers (github OAuth, OIDC, ...).
//
// The cookie payloads are tiny HS256 JWTs:
//
//   - Session: carries Subject + Email so /auth/* handlers can rebuild
//     a protection.Identity on subsequent requests. Built via Sign /
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
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// sessionClaims is the payload of the signed session cookie.
type sessionClaims struct {
	jwt.RegisteredClaims

	Email string `json:"email,omitempty"`
}

// Sign produces a compact signed JWT carrying the session for the
// supplied subject/email. ttl bounds the cookie's lifetime independently
// of the cookie's MaxAge so a tampered cookie that survives client-side
// extension still expires server-side.
func Sign(secret []byte, subject, email string, ttl time.Duration, now time.Time) (string, error) {
	claims := sessionClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   subject,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
		Email: email,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString(secret)
	if err != nil {
		return "", fmt.Errorf("session: sign: %w", err)
	}
	return signed, nil
}

// Parse verifies the signature and expiration of a session cookie and
// returns the embedded subject/email.
func Parse(secret []byte, raw string, now time.Time) (subject, email string, err error) {
	if raw == "" {
		return "", "", errors.New("session: empty token")
	}
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(func() time.Time { return now }),
	)
	claims := &sessionClaims{}
	tok, err := parser.ParseWithClaims(raw, claims, func(_ *jwt.Token) (any, error) { return secret, nil })
	if err != nil {
		return "", "", fmt.Errorf("session: parse: %w", err)
	}
	if !tok.Valid {
		return "", "", errors.New("session: token not valid")
	}
	if claims.Subject == "" {
		return "", "", errors.New("session: missing subject")
	}
	return claims.Subject, claims.Email, nil
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
