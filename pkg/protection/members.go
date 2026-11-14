package protection

import (
	"slices"
	"strings"

	"github.com/sirupsen/logrus"
)

// Bounds on the attribute matches a session carries. Together with the
// bound on teams they keep a session cookie under the browsers' 4 KB
// limit. They apply where matches are stored in a cookie (Capture,
// session.Sign) and nowhere else.
const (
	// MaxMatches is the most attribute matches kept for one identity.
	MaxMatches = 64
	// MaxMatchLen is the longest attribute match ("<attribute>:<value>")
	// there can be; the config refuses a member that would exceed it.
	MaxMatchLen = 300
	// maxCapturedBytes is the room a session has for its teams and its
	// attribute matches together, counted as JSON (each entry plus
	// quotes and a comma). MaxMatches entries of MaxMatchLen bytes would
	// be 19 KB and can never fit a cookie; this is the bound that
	// actually holds. 32 teams of 63 bytes take 2112 of it.
	maxCapturedBytes = 2400
)

// AttributeMember is one "<provider>/<attribute>:<value>" member of a
// grants group, as far as the provider is concerned: the identity is a
// member when the attribute, read the way a team rule reads it, has a
// value equal to Value (ASCII letters compared case-insensitively).
type AttributeMember struct {
	// Attribute is the attribute path, as in a team rule's claim.
	Attribute string
	// Value is the value to find.
	Value string
}

// MatchKey is the form in which a satisfied AttributeMember is
// remembered on an identity and in a session: "<attribute>:<value>"
// with the value's ASCII letters lowercased.
func MatchKey(attribute, value string) string {
	return attribute + ":" + asciiLower(value)
}

// Members evaluates the attribute members that the grants section
// names for one provider. Like team rules, it only ever looks at
// attributes the provider verified.
//
// The zero value has no members and matches nothing.
type Members struct {
	members []compiledMember
}

type compiledMember struct {
	path  []string
	value string // ASCII-lowercased
	key   string
}

// NewMembers prepares the attribute members of one provider.
func NewMembers(members []AttributeMember) Members {
	out := Members{members: make([]compiledMember, 0, len(members))}
	for _, m := range members {
		out.members = append(out.members, compiledMember{
			path:  strings.Split(m.Attribute, "."),
			value: asciiLower(m.Value),
			key:   MatchKey(m.Attribute, m.Value),
		})
	}
	return out
}

// Len returns the number of members.
func (m Members) Len() int { return len(m.members) }

// match returns the keys of the members the attributes satisfy, sorted
// and de-duplicated.
func (m Members) match(attrs Attributes) []string {
	if len(m.members) == 0 || len(attrs) == 0 {
		return nil
	}
	var keys []string
	for i := range m.members {
		member := &m.members[i]
		value, ok := lookupAttribute(attrs, member.path)
		if !ok {
			continue
		}
		for _, v := range ruleValues(value, "") {
			if asciiLower(v) == member.value {
				keys = append(keys, member.key)
				break
			}
		}
	}
	slices.Sort(keys)
	return slices.Compact(keys)
}

// Capture evaluates the members at login and returns the matches to
// store in the session, next to the captured teams. The result is
// bounded: at most MaxMatches entries, and no more bytes than the
// session has left after teams. What does not fit is dropped from the
// end of the sorted list, with a warning.
func (m Members) Capture(log logrus.FieldLogger, attrs Attributes, teams []string) []string {
	kept, dropped := BoundMatches(m.match(attrs), teams)
	if dropped > 0 {
		log.WithFields(logrus.Fields{
			"limit":   MaxMatches,
			"kept":    len(kept),
			"dropped": dropped,
		}).Warn("identity satisfies more grant members than a session can hold; truncating")
	}
	return kept
}

// ForRequest evaluates the members for an identity authenticated from
// the request itself: ambient edge headers, an Authorization header, a
// cookie that holds nothing but a username. The result is used for
// this request and stored nowhere, so the bounds of a session cookie
// do not apply and nothing is cut: every member the identity satisfies
// counts. (The list cannot grow beyond the members the config names.)
// A provider that then opens a session for the identity bounds what
// goes into it with Capture, which logs what it drops.
func (m Members) ForRequest(attrs Attributes) []string {
	return m.match(attrs)
}

// BoundMatches cuts a list of attribute matches down to what an
// identity may carry next to its teams: de-duplicated, sorted, no entry
// longer than MaxMatchLen, at most MaxMatches entries, and — teams and
// matches together — no more than the bytes a session cookie has room
// for. It keeps the head of the sorted list and reports how many
// entries it dropped.
func BoundMatches(matches, teams []string) (kept []string, dropped int) {
	sorted := slices.Clone(matches)
	slices.Sort(sorted)
	sorted = slices.Compact(sorted)

	room := maxCapturedBytes
	for _, team := range teams {
		room -= len(team) + 3
	}
	for _, key := range sorted {
		if len(key) == 0 || len(key) > MaxMatchLen || len(kept) >= MaxMatches || len(key)+3 > room {
			dropped++
			continue
		}
		room -= len(key) + 3
		kept = append(kept, key)
	}
	return kept, dropped
}
