package protection

import "strings"

// GroupSet is a case-insensitive allow-list of IdP groups, as emitted in
// an OIDC token's `groups` claim.
type GroupSet map[string]struct{}

// NewGroupSet lowercases an allow-list into a lookup set so the
// per-request check stays O(1).
func NewGroupSet(groups []string) GroupSet {
	out := make(GroupSet, len(groups))
	for _, g := range groups {
		out[strings.ToLower(g)] = struct{}{}
	}
	return out
}

// Allows reports whether any of the token's groups is in the allow-list.
//
// Matching rules (case-insensitive):
//   - Exact match: allow-list entry "foo:bar" matches token group "foo:bar".
//   - Org-prefix match: allow-list entry "foo" (no colon) matches both
//     token group "foo" and any "foo:<team>". Lets ops grant access to
//     an entire org without enumerating its teams.
//   - An empty allow-list is treated as "permit all" — the upstream IdP's
//     own gating (e.g. dex's connector `orgs:` filter) is then the
//     authoritative authorization layer. Providers that must not inherit
//     that posture reject an empty allow-list at config validation.
//
// The matching asymmetry is deliberate: GitHub-backed IdPs (dex's github
// connector, Authentik's GitHub source) emit `<org>:<team>` even for orgs
// configured without a team filter, so a bare "org" in the allow-list
// would never match without this rule. The exact-match path still allows
// narrowing to specific teams when the allow-list uses `<org>:<team>`.
func (s GroupSet) Allows(tokenGroups []string) bool {
	if len(s) == 0 {
		return true
	}
	for _, g := range tokenGroups {
		gl := strings.ToLower(g)
		if _, ok := s[gl]; ok {
			return true
		}
		if i := strings.IndexByte(gl, ':'); i > 0 {
			if _, ok := s[gl[:i]]; ok {
				return true
			}
		}
	}
	return false
}
