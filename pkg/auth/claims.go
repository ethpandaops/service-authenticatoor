// Package auth provides the JWT claim format, JWKS-based verification, and
// HTTP middleware needed to consume tokens issued by an auth service.
//
// This package is intended to be imported by resource servers that want to
// validate bearer tokens issued elsewhere. It does not contain any signing
// or key-generation logic.
package auth

import (
	"github.com/golang-jwt/jwt/v5"
)

// Claims is the JWT payload format. It embeds the standard registered
// claims and adds three custom fields:
//
//   - Email mirrors Subject for convenience.
//   - Scope is a host wildcard pattern naming the set of hosts this token
//     is valid for.
//   - Services is a comma-separated allow/deny directive list naming the
//     set of logical applications this token may be used against
//     (e.g. "+all,-spamoor", "-all,+buildoor"). Empty ⇒ no constraint.
//     Evaluated by ServiceAllowed.
type Claims struct {
	jwt.RegisteredClaims

	Email    string `json:"email,omitempty"`
	Scope    string `json:"scope,omitempty"`
	Services string `json:"services,omitempty"`
}
