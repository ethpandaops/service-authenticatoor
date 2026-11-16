package auth

import (
	"regexp"
	"slices"
	"strings"
)

// MaxTeams bounds the number of entries in the "teams" claim. The issuer
// truncates beyond it so a hostile or misconfigured identity provider
// cannot inflate session cookies and tokens.
const MaxTeams = 32

// teamPattern is the normal form of a team name: lowercase, 1-63
// characters, starting with a letter or digit.
var teamPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// ValidTeam reports whether name is a team name in normal form, byte
// for byte: [a-z0-9][a-z0-9._-]{0,62}. Nothing is trimmed or folded.
// Names that come from an identity provider are held to this, so two
// distinct upstream values can never become the same team.
func ValidTeam(name string) bool {
	return teamPattern.MatchString(name)
}

// CanonicalTeams returns the names that are team names in normal form
// (see ValidTeam), de-duplicated and sorted, and separately the names
// that are not, as given. It never changes a name.
func CanonicalTeams(names []string) (teams, invalid []string) {
	teams = make([]string, 0, len(names))
	for _, name := range names {
		if !ValidTeam(name) {
			invalid = append(invalid, name)
			continue
		}
		teams = append(teams, name)
	}
	slices.Sort(teams)
	teams = slices.Compact(teams)
	if len(teams) == 0 {
		teams = nil
	}
	return teams, invalid
}

// NormalizeTeam returns the normal form of a team name written by a
// person — in code or in a config: surrounding ASCII whitespace trimmed
// and ASCII letters lowercased. ok is false when the result is not a
// valid team name ([a-z0-9][a-z0-9._-]{0,62}). Only ASCII is folded:
// no Unicode space is trimmed and no Unicode letter is mapped onto an
// ASCII one, so a name with such a character is simply invalid.
func NormalizeTeam(name string) (team string, ok bool) {
	team = asciiLower(strings.Trim(name, " \t\r\n"))
	if !teamPattern.MatchString(team) {
		return "", false
	}
	return team, true
}

// asciiLower lowercases the ASCII letters of s and leaves every other
// byte alone.
func asciiLower(s string) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if b[j] >= 'A' && b[j] <= 'Z' {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}

// HasTeam reports whether the token carries the named team. The name is
// normalized (trimmed, lowercased) and then compared exactly against the
// claim's entries; there is no prefix or wildcard matching. A token
// without the "teams" claim has no teams.
func (c *Claims) HasTeam(name string) bool {
	if c == nil {
		return false
	}
	team, ok := NormalizeTeam(name)
	if !ok {
		return false
	}
	return slices.Contains(c.Teams, team)
}

// HasAnyTeam reports whether the token carries at least one of the named
// teams. With no names it returns false.
func (c *Claims) HasAnyTeam(names ...string) bool {
	return slices.ContainsFunc(names, c.HasTeam)
}
