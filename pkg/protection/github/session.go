package github

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// sessionClaims is the payload of the signed session cookie. It carries
// just enough to reconstruct an Identity on subsequent requests.
type sessionClaims struct {
	jwt.RegisteredClaims

	Login string `json:"login,omitempty"`
	Email string `json:"email,omitempty"`
}

// signSession produces a compact signed JWT carrying the session for the
// supplied login/email. ttl bounds the cookie's lifetime independently of
// the cookie's MaxAge so a tampered cookie that survives client-side
// extension still expires server-side.
func signSession(secret []byte, login, email string, ttl time.Duration, now time.Time) (string, error) {
	claims := sessionClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   login,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
		Login: login,
		Email: email,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString(secret)
	if err != nil {
		return "", fmt.Errorf("session: sign: %w", err)
	}
	return signed, nil
}

// parseSession verifies the signature and expiration of a session cookie
// and returns the embedded login/email.
func parseSession(secret []byte, raw string, now time.Time) (login, email string, err error) {
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
	if claims.Login == "" {
		return "", "", errors.New("session: missing login")
	}
	return claims.Login, claims.Email, nil
}

// stateClaims is the payload of the OAuth state cookie. It binds the
// random state nonce to the originally-requested URL so the callback can
// (a) verify the round-trip came from the same browser, and (b) redirect
// back to where the user wanted to go.
type stateClaims struct {
	jwt.RegisteredClaims

	State    string `json:"state"`
	ReturnTo string `json:"return_to,omitempty"`
}

// signState issues the state cookie value.
func signState(secret []byte, state, returnTo string, now time.Time, ttl time.Duration) (string, error) {
	claims := stateClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
		State:    state,
		ReturnTo: returnTo,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString(secret)
	if err != nil {
		return "", fmt.Errorf("state: sign: %w", err)
	}
	return signed, nil
}

// parseState verifies the state cookie and returns the embedded nonce
// and original-URL.
func parseState(secret []byte, raw string, now time.Time) (state, returnTo string, err error) {
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
	if claims.State == "" {
		return "", "", errors.New("state: missing nonce")
	}
	return claims.State, claims.ReturnTo, nil
}
