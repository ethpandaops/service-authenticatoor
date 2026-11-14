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
// claims and adds four custom fields:
//
//   - Email mirrors Subject for convenience.
//   - Scope is a host wildcard pattern naming the set of hosts this token
//     is valid for.
//   - Services is a comma-separated allow/deny directive list naming the
//     set of logical applications this token may be used against
//     (e.g. "+all,-spamoor", "-all,+buildoor"), optionally naming
//     features per service ("-all,+spamoor,+spamoor:plugins"). Empty ⇒
//     basic access to every service and no granted feature. Evaluated by ServiceAllowed and FeatureAllowed /
//     HasFeature.
//   - Teams lists the teams the user belongs to, as resolved by the
//     provider that authenticated them (e.g. "panda", "lighthouse").
//     Entries are in normal form (see NormalizeTeam), de-duplicated and
//     sorted. The claim is omitted when the user has no teams, and is
//     absent from tokens issued before it existed. Resource servers
//     authorize with HasTeam / HasAnyTeam.
type Claims struct {
	jwt.RegisteredClaims

	Email    string   `json:"email,omitempty"`
	Scope    string   `json:"scope,omitempty"`
	Services string   `json:"services,omitempty"`
	Teams    []string `json:"teams,omitempty"`
}
