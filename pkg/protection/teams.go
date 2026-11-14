package protection

import (
	"fmt"
	"slices"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/ethpandaops/service-authenticatoor/pkg/auth"
)

// StaticTeams holds a provider's configured team list: the teams given to
// every identity the provider authenticates. It also merges in the teams
// a provider derived from its identity source at login (id_token groups,
// GitHub orgs), keeping the result within auth.MaxTeams.
//
// The zero value is an empty list.
type StaticTeams struct {
	teams []string
	err   error
}

// NewStaticTeams validates a configured team list. Invalid names and
// lists longer than auth.MaxTeams are configuration errors, reported by
// Err so the provider can fail its Start.
func NewStaticTeams(names []string) StaticTeams {
	teams, err := ValidateTeams(names)
	return StaticTeams{teams: teams, err: err}
}

// Err returns the configuration error found by NewStaticTeams, if any.
func (s StaticTeams) Err() error { return s.err }

// List returns the configured teams: normalized, de-duplicated, sorted.
func (s StaticTeams) List() []string { return slices.Clone(s.teams) }

// Capture prepares the teams a provider derived from its identity source
// for storage in the session. It runs once, at login: names that are not
// team names in normal form byte for byte (nothing is trimmed or
// lowercased — see auth.ValidTeam) are dropped with a warning, and when the derived
// teams together with the configured ones exceed auth.MaxTeams the
// surplus is dropped with a warning (see With for the order). The result
// is normalized, de-duplicated and sorted; nil when empty.
func (s StaticTeams) Capture(log logrus.FieldLogger, derived []string) []string {
	teams, invalid := auth.CanonicalTeams(derived)
	if len(invalid) > 0 {
		log.WithFields(logrus.Fields{
			"count":   len(invalid),
			"invalid": quoteTeams(invalid),
		}).Warn("dropping invalid team names from the identity source")
	}
	kept, dropped := s.bound(teams)
	if len(dropped) > 0 {
		log.WithFields(logrus.Fields{
			"limit":   auth.MaxTeams,
			"kept":    len(kept),
			"dropped": len(dropped),
		}).Warn("identity source supplied too many teams; truncating")
	}
	return kept
}

// With returns the teams of an identity: the configured teams plus the
// captured ones (as stored in the session at login). The result is
// normalized, de-duplicated, sorted and holds at most auth.MaxTeams
// entries; nil when empty.
//
// When the bound is exceeded the configured teams are kept first and
// the remaining room is filled with the captured teams in sorted order,
// so an identity source cannot push a configured team out of the token.
// With never logs: it runs on every request, and the truncation was
// already reported by Capture at login.
func (s StaticTeams) With(captured []string) []string {
	derived, _ := auth.CanonicalTeams(captured)
	kept, _ := s.bound(derived)

	teams := make([]string, 0, len(s.teams)+len(kept))
	teams = append(teams, s.teams...)
	teams = append(teams, kept...)
	slices.Sort(teams)
	teams = slices.Compact(teams)
	if len(teams) > auth.MaxTeams {
		// Only reachable with an unvalidated, oversized configured list.
		teams = teams[:auth.MaxTeams]
	}
	if len(teams) == 0 {
		return nil
	}
	return teams
}

// bound splits the (normalized, sorted) derived teams into those that fit
// next to the configured teams within auth.MaxTeams and those that do
// not. A derived team that is also configured takes no extra room and is
// always kept.
func (s StaticTeams) bound(derived []string) (kept, dropped []string) {
	room := max(auth.MaxTeams-len(s.teams), 0)
	for _, team := range derived {
		switch {
		case slices.Contains(s.teams, team):
			kept = append(kept, team)
		case room > 0:
			kept = append(kept, team)
			room--
		default:
			dropped = append(dropped, team)
		}
	}
	return kept, dropped
}

// ValidateTeams checks a configured team list and returns it
// de-duplicated and sorted. Every name has to be written in its normal
// form — lowercase [a-z0-9][a-z0-9._-]{0,62}. A name in the config is
// not folded into it: "Panda" is an error rather than another spelling
// of "panda", so that what the config says is what tokens carry. Lists
// with more than auth.MaxTeams distinct entries are an error too.
func ValidateTeams(names []string) ([]string, error) {
	teams, invalid := auth.CanonicalTeams(names)
	if len(invalid) > 0 {
		hint := ""
		for _, name := range invalid {
			if folded, ok := auth.NormalizeTeam(name); ok && folded != name {
				hint = "; write them lowercase and without surrounding whitespace"
				break
			}
		}
		return nil, fmt.Errorf("invalid team name(s) %s: a team is 1-63 characters of [a-z0-9._-], "+
			"starting with a letter or digit%s", quoteTeams(invalid), hint)
	}
	if len(teams) > auth.MaxTeams {
		return nil, fmt.Errorf("too many teams: %d (at most %d)", len(teams), auth.MaxTeams)
	}
	return teams, nil
}

// maxLoggedTeams and maxLoggedTeamLen bound how much of an untrusted
// team list ends up in one log line.
const (
	maxLoggedTeams   = 8
	maxLoggedTeamLen = 80
)

// quoteTeams renders team names for logs and error messages, quoted so
// whitespace and control characters stay visible, and bounded so a
// hostile identity source cannot flood the log.
func quoteTeams(names []string) string {
	shown := names
	if len(shown) > maxLoggedTeams {
		shown = shown[:maxLoggedTeams]
	}
	parts := make([]string, 0, len(shown)+1)
	for _, name := range shown {
		if len(name) > maxLoggedTeamLen {
			name = name[:maxLoggedTeamLen] + "…"
		}
		parts = append(parts, fmt.Sprintf("%q", name))
	}
	if len(names) > len(shown) {
		parts = append(parts, fmt.Sprintf("… (%d more)", len(names)-len(shown)))
	}
	return "[" + strings.Join(parts, ", ") + "]"
}
