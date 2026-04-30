package auth

import (
	"strings"
)

// MatchHost reports whether host matches pattern. The pattern is a glob
// over DNS labels (separated by '.'):
//
//   - "foo.bar"   matches only "foo.bar"
//   - "*.foo.bar" matches "x.foo.bar" and "x.y.foo.bar" — but NOT "foo.bar"
//     (the leading "*" requires at least one label) and NOT "evil-foo.bar"
//     (label boundary is enforced)
//   - "*"         matches anything
//
// Comparison is case-insensitive. Partial wildcards ("foo*.bar") and
// non-leading wildcards ("a.*.b", "a.b.*") are deliberately not supported.
func MatchHost(pattern, host string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	host = strings.ToLower(strings.TrimSpace(host))

	if pattern == "" || host == "" {
		return false
	}

	if pattern == "*" {
		return true
	}

	pl := strings.Split(pattern, ".")
	hl := strings.Split(host, ".")

	for i, l := range pl {
		if l == "*" && i != 0 {
			return false
		}
		if strings.Contains(l, "*") && l != "*" {
			return false
		}
	}

	if pl[0] == "*" {
		suffix := pl[1:]
		if len(hl) <= len(suffix) {
			return false
		}
		for i := range suffix {
			if suffix[len(suffix)-1-i] != hl[len(hl)-1-i] {
				return false
			}
		}
		return true
	}

	if len(pl) != len(hl) {
		return false
	}
	for i := range pl {
		if pl[i] != hl[i] {
			return false
		}
	}
	return true
}

// MatchAnyHost reports whether host matches any of the patterns.
func MatchAnyHost(patterns []string, host string) bool {
	for _, p := range patterns {
		if MatchHost(p, host) {
			return true
		}
	}
	return false
}
