package protection

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"regexp/syntax"
	"slices"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/ethpandaops/service-authenticatoor/pkg/auth"
)

// Bounds on what a team rule looks at. They keep rule evaluation cheap
// and predictable whatever an identity provider sends.
const (
	// maxRuleValueLen is the longest attribute value a rule considers;
	// longer values are ignored.
	maxRuleValueLen = 256
	// maxRuleValues is the most values of one attribute a rule
	// considers (elements of a list, parts of a split string).
	maxRuleValues = 1024
	// maxRulePatternLen bounds map keys, prefixes and regular
	// expressions in the config.
	maxRulePatternLen = 256
)

// Attributes are the facts a provider has verified about the user it
// authenticated, by name: the claims of a verified token, a login, a
// list of organizations. Values are strings, numbers, booleans, lists
// and nested maps, as decoded from JSON. Team rules read them; nothing
// a client merely sent may be put in here.
type Attributes map[string]any

// TokenAttributes returns the claims of a JWT as Attributes. The caller
// must have verified the token: this only decodes its payload.
func TokenAttributes(verifiedJWT string) (Attributes, error) {
	parts := strings.Split(verifiedJWT, ".")
	if len(parts) != 3 {
		return nil, errors.New("not a compact JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	dec := json.NewDecoder(strings.NewReader(string(payload)))
	dec.UseNumber()
	attrs := make(Attributes, 16)
	if err := dec.Decode(&attrs); err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	return attrs, nil
}

// TeamRule turns the values of one attribute into teams. It is the
// config shape of an entry of a provider's teamRules list.
//
// Exactly one of Prefix, Map, Regex and Value has to be set. There is
// no default: a rule that names none of them — a misspelled key, an
// empty value — is an error, never "every value is a team".
type TeamRule struct {
	// Claim is the attribute to read, as a dotted path into nested
	// attributes ("groups", "realm_access.roles"). Required.
	Claim string `yaml:"claim" mapstructure:"claim"`
	// Prefix selects the values that start with it (ASCII letters
	// compared case-insensitively); the rest of the value is the team.
	Prefix string `yaml:"prefix" mapstructure:"prefix"`
	// Map lists, per value, the teams it grants. Keys are compared with
	// the whole value, ASCII case-insensitively; "*" in a key matches
	// any run of characters, including none.
	Map map[string][]string `yaml:"map" mapstructure:"map"`
	// Regex is an RE2 expression with exactly one capture group, which
	// is the team. It has to match the whole value.
	Regex string `yaml:"regex" mapstructure:"regex"`
	// Value, when true, takes every value of the attribute itself as a
	// team.
	Value bool `yaml:"value" mapstructure:"value"`
	// Split, when set, splits a string value at this separator into
	// several values before the rule is applied.
	Split string `yaml:"split" mapstructure:"split"`
}

// teamRule is a validated TeamRule.
type teamRule struct {
	path   []string
	split  string
	prefix string // ASCII-lowercased; "" when unused
	keys   []mapKey
	regex  *regexp.Regexp
}

// mapKey is one entry of a rule's map.
type mapKey struct {
	pattern string // ASCII-lowercased glob
	teams   []string
}

// TeamRules is a provider's validated list of team rules.
//
// The zero value has no rules.
type TeamRules struct {
	rules []teamRule
	err   error
}

// NewTeamRules validates a provider's team rules. Problems are
// configuration errors, reported by Err.
func NewTeamRules(rules []TeamRule) TeamRules {
	out := TeamRules{rules: make([]teamRule, 0, len(rules))}
	for i, cfg := range rules {
		rule, err := compileTeamRule(cfg)
		if err != nil {
			out.err = fmt.Errorf("teamRules[%d]: %w", i, err)
			return out
		}
		out.rules = append(out.rules, rule)
	}
	return out
}

// ValidateTeamRules reports the configuration error in a provider's
// team rules, if any.
func ValidateTeamRules(rules []TeamRule) error {
	return NewTeamRules(rules).Err()
}

// compileTeamRule validates one rule.
func compileTeamRule(cfg TeamRule) (teamRule, error) {
	if strings.TrimSpace(cfg.Claim) == "" {
		return teamRule{}, errors.New("claim is required")
	}
	rule := teamRule{path: strings.Split(cfg.Claim, "."), split: cfg.Split}

	forms := 0
	for _, set := range []bool{cfg.Prefix != "", len(cfg.Map) > 0, cfg.Regex != "", cfg.Value} {
		if set {
			forms++
		}
	}
	switch {
	case forms > 1:
		return teamRule{}, fmt.Errorf("claim %q: only one of prefix, map, regex and value may be set", cfg.Claim)
	case forms == 0:
		return teamRule{}, fmt.Errorf("claim %q: one of prefix, map, regex or \"value: true\" is required "+
			"(value: true takes every value of the attribute as a team)", cfg.Claim)
	}

	switch {
	case cfg.Prefix != "":
		if len(cfg.Prefix) > maxRulePatternLen {
			return teamRule{}, fmt.Errorf("claim %q: prefix is longer than %d bytes", cfg.Claim, maxRulePatternLen)
		}
		rule.prefix = asciiLower(cfg.Prefix)

	case len(cfg.Map) > 0:
		seen := make(map[string]string, len(cfg.Map))
		for _, key := range slices.Sorted(maps.Keys(cfg.Map)) {
			if key == "" || len(key) > maxRulePatternLen {
				return teamRule{}, fmt.Errorf("claim %q: map key %q must be 1-%d bytes long",
					cfg.Claim, key, maxRulePatternLen)
			}
			pattern := asciiLower(key)
			if other, dup := seen[pattern]; dup {
				return teamRule{}, fmt.Errorf("claim %q: map keys %q and %q are the same key "+
					"(keys are case-insensitive)", cfg.Claim, other, key)
			}
			seen[pattern] = key
			teams, err := ValidateTeams(cfg.Map[key])
			if err != nil {
				return teamRule{}, fmt.Errorf("claim %q: map key %q: %w", cfg.Claim, key, err)
			}
			rule.keys = append(rule.keys, mapKey{pattern: pattern, teams: teams})
		}

	case cfg.Regex != "":
		if len(cfg.Regex) > maxRulePatternLen {
			return teamRule{}, fmt.Errorf("claim %q: regex is longer than %d bytes", cfg.Claim, maxRulePatternLen)
		}
		re, err := compileWholeValueRegex(cfg.Regex)
		if err != nil {
			return teamRule{}, fmt.Errorf("claim %q: regex: %w", cfg.Claim, err)
		}
		rule.regex = re
	}
	return rule, nil
}

// compileWholeValueRegex compiles a rule's regular expression so that
// it has to match the whole value, whether or not its author anchored
// it.
//
// The operator's pattern is compiled on its own first: it has to be a
// complete expression with exactly one capture group. Only then is it
// anchored — not by pasting text around it, which an unbalanced pattern
// such as "team)|(.*" would break out of, but by re-rendering the
// parsed expression (always a balanced, self-contained form) inside
// the anchors. The result is checked to have kept its single group.
//
// Go's regexp is RE2: matching is linear in the input, there is no
// backtracking to exploit.
func compileWholeValueRegex(pattern string) (*regexp.Regexp, error) {
	parsed, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil, err
	}
	if n := parsed.MaxCap(); n != 1 {
		return nil, fmt.Errorf("must have exactly one capture group (the team), has %d", n)
	}
	anchored, err := regexp.Compile("^(?:" + parsed.String() + ")$")
	if err != nil {
		return nil, fmt.Errorf("cannot be anchored: %w", err)
	}
	if anchored.NumSubexp() != 1 {
		return nil, fmt.Errorf("must have exactly one capture group (the team), has %d once anchored",
			anchored.NumSubexp())
	}
	return anchored, nil
}

// Err returns the configuration error found by NewTeamRules, if any.
func (r TeamRules) Err() error { return r.err }

// Len returns the number of rules.
func (r TeamRules) Len() int { return len(r.rules) }

// Resolve applies the rules to the attributes. teams are the resulting
// team names in normal form, de-duplicated and sorted. rejected are the
// results that were thrown away: names derived from an attribute value
// that are not in normal form byte for byte (nothing is trimmed or
// lowercased — two distinct upstream values must never become the same
// team).
func (r TeamRules) Resolve(attrs Attributes) (teams, rejected []string) {
	if len(r.rules) == 0 || len(attrs) == 0 {
		return nil, nil
	}
	var derived []string
	for i := range r.rules {
		rule := &r.rules[i]
		value, ok := lookupAttribute(attrs, rule.path)
		if !ok {
			continue
		}
		for _, v := range ruleValues(value, rule.split) {
			derived = rule.apply(v, derived)
		}
	}

	teams, rejected = auth.CanonicalTeams(derived)
	if len(teams) == 0 {
		teams = nil
	}
	return teams, rejected
}

// apply appends the teams the rule derives from one value.
func (rule *teamRule) apply(value string, out []string) []string {
	switch {
	case rule.prefix != "":
		if len(value) >= len(rule.prefix) && asciiLower(value[:len(rule.prefix)]) == rule.prefix {
			out = append(out, value[len(rule.prefix):])
		}
	case rule.keys != nil:
		lowered := asciiLower(value)
		for _, key := range rule.keys {
			if globMatch(key.pattern, lowered) {
				out = append(out, key.teams...)
			}
		}
	case rule.regex != nil:
		if m := rule.regex.FindStringSubmatchIndex(value); m != nil && m[2] >= 0 {
			out = append(out, value[m[2]:m[3]])
		}
	default:
		out = append(out, value)
	}
	return out
}

// lookupAttribute walks a dotted path into nested attributes. At each
// level the longest key that exists wins, so an attribute whose own
// name contains dots ("https://example.org/groups") can be addressed.
func lookupAttribute(attrs map[string]any, path []string) (any, bool) {
	for n := len(path); n >= 1; n-- {
		value, ok := attrs[strings.Join(path[:n], ".")]
		if !ok {
			continue
		}
		if n == len(path) {
			return value, true
		}
		switch nested := value.(type) {
		case map[string]any:
			if v, found := lookupAttribute(nested, path[n:]); found {
				return v, true
			}
		case Attributes:
			if v, found := lookupAttribute(nested, path[n:]); found {
				return v, true
			}
		}
	}
	return nil, false
}

// ruleValues flattens an attribute value into the strings a rule works
// on: a string, number or boolean is one value, a list contributes its
// string, number and boolean elements. Anything else — a map, a nested
// list, null — is ignored; it is never turned into text. Values longer
// than maxRuleValueLen are ignored too.
func ruleValues(value any, split string) []string {
	var raw []string
	switch v := value.(type) {
	case []any:
		for _, elem := range v {
			if len(raw) >= maxRuleValues {
				break
			}
			if s, ok := scalarString(elem); ok {
				raw = append(raw, s)
			}
		}
	case []string:
		raw = v
		if len(raw) > maxRuleValues {
			raw = raw[:maxRuleValues]
		}
	default:
		if s, ok := scalarString(value); ok {
			raw = append(raw, s)
		}
	}

	out := make([]string, 0, len(raw))
	for _, s := range raw {
		if split == "" {
			if s != "" && len(s) <= maxRuleValueLen {
				out = append(out, s)
			}
			continue
		}
		// Bound the work before splitting: a part can be no longer than
		// the whole, so an oversized whole is cut down first.
		if len(s) > maxRuleValueLen*maxRuleValues {
			continue
		}
		for _, part := range strings.Split(s, split) {
			if len(out) >= maxRuleValues {
				return out
			}
			if part != "" && len(part) <= maxRuleValueLen {
				out = append(out, part)
			}
		}
	}
	return out
}

// scalarString renders a string, number or boolean attribute value.
func scalarString(value any) (string, bool) {
	switch v := value.(type) {
	case string:
		return v, true
	case bool:
		return strconv.FormatBool(v), true
	case json.Number:
		return v.String(), true
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), true
	case int:
		return strconv.Itoa(v), true
	case int64:
		return strconv.FormatInt(v, 10), true
	default:
		return "", false
	}
}

// globMatch reports whether value matches pattern, in which "*" stands
// for any run of characters (including none, and including separators
// such as ":" or "/"); every other character stands for itself. Both
// are expected ASCII-lowercased. The match is the classic two-pointer
// walk with a single backtrack point: O(len(pattern)·len(value)) at
// worst, no recursion, no regular expression.
func globMatch(pattern, value string) bool {
	p, v := 0, 0
	star, mark := -1, 0
	for v < len(value) {
		switch {
		case p < len(pattern) && pattern[p] == '*':
			star, mark = p, v
			p++
		case p < len(pattern) && pattern[p] == value[v]:
			p++
			v++
		case star >= 0:
			p = star + 1
			mark++
			v = mark
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

// asciiLower lowercases the ASCII letters of s and leaves every other
// byte alone. Rule matching folds case with this and nothing else: no
// Unicode letter is ever mapped onto an ASCII one.
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

// Teams resolves the teams of the identities one provider
// authenticates: its static teams, given to everyone, plus what its
// team rules derive from the attributes the provider verified.
//
// The zero value yields no teams.
type Teams struct {
	static StaticTeams
	rules  TeamRules
}

// NewTeams validates a provider's team configuration: the static team
// list and the team rules. Problems are reported by Err so the provider
// can fail its Start.
func NewTeams(static []string, rules []TeamRule) Teams {
	return Teams{static: NewStaticTeams(static), rules: NewTeamRules(rules)}
}

// Err returns the configuration error, if any.
func (t Teams) Err() error {
	if err := t.static.Err(); err != nil {
		return fmt.Errorf("teams: %w", err)
	}
	return t.rules.Err()
}

// Static returns the static teams: normalized, de-duplicated, sorted.
func (t Teams) Static() []string { return t.static.List() }

// Rules returns the number of team rules.
func (t Teams) Rules() int { return t.rules.Len() }

// Capture evaluates the team rules at login and returns the teams to
// store in the session. It logs, once per login: a warning for results
// that were dropped because they are not in normal form, and
// one when the bound of auth.MaxTeams cut the list. The static teams
// are not part of the result; With adds them on every request.
func (t Teams) Capture(log logrus.FieldLogger, attrs Attributes) []string {
	derived, rejected := t.rules.Resolve(attrs)
	if len(rejected) > 0 {
		log.WithFields(logrus.Fields{
			"count":    len(rejected),
			"rejected": quoteTeams(rejected),
		}).Warn("dropping team names produced by team rules: not in normal form")
	}
	return t.static.Capture(log, derived)
}

// With returns the teams of an identity restored from a session: the
// static teams of the current config plus the teams captured at login.
func (t Teams) With(captured []string) []string {
	return t.static.With(captured)
}

// ForRequest returns the teams of an identity authenticated from the
// request itself (ambient edge headers, an Authorization header): the
// static teams plus the rules applied to the attributes verified on
// this request. It never logs, since it runs on every request.
func (t Teams) ForRequest(attrs Attributes) []string {
	derived, _ := t.rules.Resolve(attrs)
	return t.static.With(derived)
}
