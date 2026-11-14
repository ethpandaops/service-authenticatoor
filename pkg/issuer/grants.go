package issuer

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/ethpandaops/service-authenticatoor/pkg/auth"
	"github.com/ethpandaops/service-authenticatoor/pkg/protection"
)

// GrantAll is the name that stands for every service (as the service of
// a grant) and for every feature (as a feature of a grant).
const GrantAll = "all"

// The reserved attribute names of a member: "<provider>/team:<team>"
// and "<provider>/user:<id>". Every other "<provider>/<attribute>:<value>"
// names an attribute the provider verified.
const (
	memberTeam = "team"
	memberUser = "user"
)

// memberForms is the reminder appended to every error about a member.
const memberForms = `a member is "<provider>/team:<team>", "<provider>/user:<id>" or ` +
	`"<provider>/<attribute>:<value>"`

// Provider describes a configured provider to the grants section.
type Provider struct {
	// Name is the provider's instance name.
	Name string
	// CheckAttribute says why no identity of this provider can ever
	// have the attribute with that value, so that a member which can
	// never match is caught at startup; nil when it can. A nil func
	// accepts every attribute path and value.
	CheckAttribute func(attribute, value string) error
}

// GrantsConfig is the grants config section: a list of groups, each
// naming its members and the services they may use.
type GrantsConfig struct {
	Groups []GrantGroup
}

// GrantGroup is one entry of the grants section.
type GrantGroup struct {
	// Name is an optional label, used in logs and error messages.
	// Unique when given.
	Name string
	// Members lists who is in the group. Required, not empty. A member
	// always names the provider it comes through, and what that
	// provider vouched for:
	//
	//	<provider>/team:<team>          identities the provider gave the
	//	                                team (static teams, team rules)
	//	<provider>/user:<id>            the identity whose subject or
	//	                                email is id; an id with an "@"
	//	                                only ever matches an email the
	//	                                provider verified
	//	<provider>/<attribute>:<value>  identities for which the provider
	//	                                verified the attribute — by the
	//	                                names and paths team rules use —
	//	                                to have that value
	//
	// Ids and values are compared exactly but for the case of ASCII
	// letters. There is no form without a provider, none that stands
	// for several providers or for everyone, and no wildcard.
	Members []string
	// Services lists the grants of the group, in the forms documented
	// on ServiceGrants. An empty list is allowed: the group then grants
	// nothing, and only documents its members.
	Services []string
}

// grantNamePattern is the form of a service name and of a feature name
// in a grant.
var grantNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// featurePrefixPattern is the form of a prefix grant: a feature name
// with one trailing "*".
var featurePrefixPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*\*$`)

// ServiceGrants is the validated grants section. It turns an identity —
// the provider that authenticated it, the teams that provider gave it,
// its subject and email — into the token's "services" directive.
//
// Access never hangs on a bare team name: a team counts only together
// with the provider it came through, so "panda" from one door and
// "panda" from another are different subjects.
//
// A grant has one of these forms, all of them positive:
//
//	svc          base access to svc
//	svc:basic    the same: "basic" is the reserved feature name for it
//	svc:f1:f2    base access to svc plus its features f1 and f2
//	svc:user*    base access to svc plus every feature starting "user"
//	svc:all      base access to svc plus every feature of it
//	all          base access to every service
//	all:f1       every service: base access plus feature f1
//	all:all      every service, every feature
//
// A nil *ServiceGrants means the section is absent: tokens then carry
// the instance-wide services directive unchanged.
type ServiceGrants struct {
	// byTeam, byUser and byMatch map a subject — a provider with a
	// team, with an ASCII-lowercased id, with an attribute match key —
	// to the union of the grants of the groups it is a member of.
	byTeam  map[subject]grantSet
	byUser  map[subject]grantSet
	byMatch map[subject]grantSet
	// attributes lists, per provider, the attribute members the section
	// names: what the provider has to look for.
	attributes map[string][]protection.AttributeMember
	// groups is the validated section in config order, for logging.
	groups []GrantGroup
}

// subject is a member of a group: a team, a user id or an attribute
// match at a provider.
type subject struct {
	provider string
	name     string
}

// grantSet maps a service name (or GrantAll) to the features granted on
// it. A service being present means base access to it.
type grantSet map[string]*featureSet

// featureSet is the set of features granted on one service.
type featureSet struct {
	// all reports that every feature is granted.
	all bool
	// names are the individually granted features; unused once all is
	// set.
	names map[string]struct{}
}

// add merges other into f.
func (f *featureSet) add(other *featureSet) {
	if other.all {
		f.all = true
	}
	for name := range other.names {
		f.names[name] = struct{}{}
	}
}

// list returns the granted features in sorted order; ["all"] when every
// feature is granted.
func (f *featureSet) list() []string {
	if f.all {
		return []string{GrantAll}
	}
	return slices.Sorted(maps.Keys(f.names))
}

// merge adds every grant of other to s.
func (s grantSet) merge(other grantSet) {
	for service, features := range other {
		s.service(service).add(features)
	}
}

// service returns the feature set of a service, granting base access to
// it if it was not granted yet.
func (s grantSet) service(name string) *featureSet {
	features, ok := s[name]
	if !ok {
		features = &featureSet{names: make(map[string]struct{}, 2)}
		s[name] = features
	}
	return features
}

// entries renders the set in the config's grant form, sorted with the
// GrantAll service first: "all", "dora:hold:roll", "spamoor".
func (s grantSet) entries() []string {
	out := make([]string, 0, len(s))
	for _, service := range sortedServices(s) {
		out = append(out, strings.Join(append([]string{service}, s[service].list()...), ":"))
	}
	return out
}

// sortedServices returns the services of a set in emission order:
// GrantAll first, then by name.
func sortedServices(s grantSet) []string {
	names := slices.Sorted(maps.Keys(s))
	if i := slices.Index(names, GrantAll); i > 0 {
		names = slices.Insert(slices.Delete(names, i, i+1), 0, GrantAll)
	}
	return names
}

// NewServiceGrants validates a grants section. providers are the
// configured providers; every member has to name one of them. Anything
// malformed is an error. A section without groups is valid: it grants
// nothing to anyone.
func NewServiceGrants(cfg GrantsConfig, providers []Provider) (*ServiceGrants, error) {
	g := &ServiceGrants{
		byTeam:     make(map[subject]grantSet, len(cfg.Groups)),
		byUser:     make(map[subject]grantSet, len(cfg.Groups)),
		byMatch:    make(map[subject]grantSet, len(cfg.Groups)),
		attributes: make(map[string][]protection.AttributeMember, len(providers)),
		groups:     make([]GrantGroup, 0, len(cfg.Groups)),
	}

	names := make(map[string]int, len(cfg.Groups))
	for i, group := range cfg.Groups {
		label := fmt.Sprintf("grants[%d]", i)
		if group.Name != "" {
			if group.Name != strings.TrimSpace(group.Name) {
				return nil, fmt.Errorf("%s: name %q has surrounding whitespace", label, group.Name)
			}
			if first, dup := names[group.Name]; dup {
				return nil, fmt.Errorf("%s: the name %q is already used by grants[%d]", label, group.Name, first)
			}
			names[group.Name] = i
			label += fmt.Sprintf(" (%s)", group.Name)
		}

		grants, err := newGrantSet(group.Services)
		if err != nil {
			return nil, fmt.Errorf("%s: services: %w", label, err)
		}
		if len(group.Members) == 0 {
			return nil, fmt.Errorf("%s: members must list at least one member; %s", label, memberForms)
		}

		seen := make(map[string]string, len(group.Members))
		members := make([]string, 0, len(group.Members))
		for _, raw := range group.Members {
			m, err := parseMember(raw, providers)
			if err != nil {
				return nil, fmt.Errorf("%s: members: %w", label, err)
			}
			canonical := m.canonical()
			if other, dup := seen[canonical]; dup {
				return nil, fmt.Errorf("%s: members: %q and %q are the same member; list it once",
					label, other, raw)
			}
			seen[canonical] = raw
			members = append(members, canonical)

			target := g.byMatch
			switch m.attribute {
			case memberTeam:
				target = g.byTeam
			case memberUser:
				target = g.byUser
			default:
				wanted := protection.AttributeMember{Attribute: m.attribute, Value: m.value}
				if !slices.Contains(g.attributes[m.provider], wanted) {
					g.attributes[m.provider] = append(g.attributes[m.provider], wanted)
				}
			}
			sub := m.subject()
			if target[sub] == nil {
				target[sub] = make(grantSet, len(grants))
			}
			target[sub].merge(grants)
		}

		slices.Sort(members)
		g.groups = append(g.groups, GrantGroup{Name: group.Name, Members: members, Services: grants.entries()})
	}
	return g, nil
}

// member is a parsed member of a group.
type member struct {
	provider  string
	attribute string // memberTeam, memberUser, or an attribute path
	value     string // team, id or attribute value; ids and values ASCII-lowercased
}

// subject returns the key under which the member's grants are stored.
func (m member) subject() subject {
	switch m.attribute {
	case memberTeam, memberUser:
		return subject{provider: m.provider, name: m.value}
	default:
		return subject{provider: m.provider, name: protection.MatchKey(m.attribute, m.value)}
	}
}

// canonical renders the member in its normal spelling.
func (m member) canonical() string {
	return m.provider + "/" + m.attribute + ":" + m.value
}

// parseMember parses one member of a group: the provider is the text
// before the first "/", the attribute the text up to the first ":"
// after that, the value the rest, verbatim — it may itself contain
// ":", "/", "@" or "|".
func parseMember(raw string, providers []Provider) (member, error) {
	fail := func(format string, args ...any) (member, error) {
		return member{}, fmt.Errorf("%q: %s; %s", raw, fmt.Sprintf(format, args...), memberForms)
	}

	if raw == "" || raw != strings.TrimSpace(raw) {
		return fail("empty or with surrounding whitespace")
	}
	name, rest, found := strings.Cut(raw, "/")
	if !found {
		return fail("no provider: every member names the provider it comes through")
	}
	var provider *Provider
	configured := make([]string, 0, len(providers))
	for i := range providers {
		configured = append(configured, providers[i].Name)
		if providers[i].Name == name {
			provider = &providers[i]
		}
	}
	if provider == nil {
		list := "[" + strings.Join(configured, ", ") + "]"
		for _, other := range configured {
			if strings.EqualFold(other, name) {
				return fail("no provider named %q — did you mean %q? Provider names are case-sensitive (configured: %s)",
					name, other, list)
			}
		}
		return fail("no provider named %q (configured: %s)", name, list)
	}

	attribute, value, found := strings.Cut(rest, ":")
	switch {
	case !found:
		return fail("after the provider comes \"<attribute>:<value>\" (\"team:<team>\", \"user:<id>\", …)")
	case attribute == "":
		return fail("the attribute before the \":\" is empty")
	case attribute != strings.TrimSpace(attribute):
		return fail("the attribute %q has surrounding whitespace", attribute)
	case value == "":
		return fail("the value after %q is empty", attribute+":")
	case strings.Contains(value, "*"):
		return fail("members are exact, there are no wildcards — to match a pattern, turn it into a team " +
			"with a teamRules entry and name the team")
	}

	m := member{provider: name, attribute: attribute, value: value}
	switch attribute {
	case memberTeam:
		if !auth.ValidTeam(value) {
			return fail("%q is not a team name (lowercase [a-z0-9][a-z0-9._-]{0,62})", value)
		}
	case memberUser:
		if value != strings.TrimSpace(value) {
			return fail("the user id has surrounding whitespace")
		}
		m.value = asciiLower(value)
	default:
		// Only the exact names "team" and "user" are reserved. Anything
		// else — "teams", "Team" — is the name of an attribute.
		if provider.CheckAttribute != nil {
			if err := provider.CheckAttribute(attribute, value); err != nil {
				return fail("this member can never match at the provider %q: %v", name, err)
			}
		}
		m.value = asciiLower(value)
		if len(protection.MatchKey(attribute, value)) > protection.MaxMatchLen {
			return fail("attribute and value together are longer than %d bytes", protection.MaxMatchLen)
		}
	}
	return m, nil
}

// userIDs returns the ids under which a "<provider>/user:<id>" member
// can name the identity: its email, and its subject.
//
// An id that looks like an email address — it contains "@" — is a
// statement about who owns that address, so it matches only what the
// provider verified as one: the identity's Email (providers only ever
// set a verified address there), or a Subject the provider marked as a
// verified email. A raw provider subject that merely contains "@" — an
// IdP "sub" that happens to be, or was chosen to be, an email address
// nobody confirmed — is never a user id.
func (id Identity) userIDs() []string {
	ids := make([]string, 0, 2)
	if id.Email != "" {
		ids = append(ids, id.Email)
	}
	if id.Subject != "" && id.Subject != id.Email &&
		(id.SubjectIsEmail || !strings.Contains(id.Subject, "@")) {
		ids = append(ids, id.Subject)
	}
	return ids
}

// newGrantSet parses a list of configured grants.
func newGrantSet(entries []string) (grantSet, error) {
	set := make(grantSet, len(entries))
	for _, raw := range entries {
		if err := set.addEntry(raw); err != nil {
			return nil, err
		}
	}
	return set, nil
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

// addEntry parses one configured grant and adds it to the set.
func (s grantSet) addEntry(raw string) error {
	fields := strings.Split(strings.ToLower(strings.TrimSpace(raw)), ":")
	for i := range fields {
		fields[i] = strings.TrimSpace(fields[i])
	}

	// Denials are spelled out as their own error: the grammar of the
	// claim has them, and they are the one thing a grant list must not
	// contain.
	for _, field := range fields {
		if strings.HasPrefix(field, "-") {
			return fmt.Errorf("invalid grant %q: a grant cannot deny. The grants of all groups an "+
				"identity is a member of are added up, so a denial in one group's list would depend on "+
				"the order the groups are evaluated in; leave out what a group should not have", raw)
		}
	}

	service := fields[0]
	if !grantNamePattern.MatchString(service) {
		return fmt.Errorf("invalid service name %q in grant %q (want [a-z0-9][a-z0-9-]* or %q)",
			service, raw, GrantAll)
	}
	features := s.service(service)
	for _, feature := range fields[1:] {
		switch {
		case feature == "*":
			feature = GrantAll
		case grantNamePattern.MatchString(feature), featurePrefixPattern.MatchString(feature):
		case strings.Contains(feature, "*"):
			return fmt.Errorf("invalid feature %q in grant %q: \"*\" is a prefix wildcard and may only "+
				"be the last character (\"user*\"); a lone \"*\" means %q", feature, raw, GrantAll)
		default:
			return fmt.Errorf("invalid feature name %q in grant %q (want [a-z0-9][a-z0-9-]*, "+
				"optionally ending in \"*\", or %q)", feature, raw, GrantAll)
		}
		switch feature {
		case GrantAll:
			features.all = true
		case auth.FeatureBasic:
			// Base access, which naming the service already grants.
		default:
			features.names[feature] = struct{}{}
		}
	}
	return nil
}

// Directive returns the "services" claim for an identity. instanceWide
// is the instance-wide services directive, which stays an upper bound
// on the base access any identity gets.
//
// The identity's grant is the union of the grants of every group it is
// a member of — always at the provider that authenticated it: through
// any of its teams, through its subject or email (see userIDs for
// which of them count), or through an attribute member the provider
// found it to satisfy (id.Matches).
// An identity without a provider — as the plain Issuer.Issue mints
// tokens for — is a member of no group:
//
//   - nothing granted: "-all";
//   - specific services only: "-all", then for each granted service the
//     instance-wide directive allows, in sorted order, "+svc" and — when
//     features are granted — "+svc:f1:f2" (sorted) or "+svc:all";
//   - base access to every service ("all" in any form): the
//     instance-wide directive, or "+all" when that is empty, followed by
//     the feature directives: "+all:…" for the features granted on every
//     service, then "+svc:…" for services with features beyond those.
//
// Prefix grants ("user*") are emitted as written, sorted among the
// other features; nothing is expanded or folded into a broader prefix.
// Only exact duplicates are dropped, and everything once "all" is
// granted.
//
// Every feature directive comes in addition to a bare directive for the
// same base access. Verifiers that predate feature grants read
// "+svc:f1" as an unknown service and skip it, so the bare directives
// alone must — and do — decide base access for them exactly as the full
// list does for current verifiers.
//
// The reserved feature "basic" is never emitted: the bare directive
// says it, and old verifiers would not understand it. A service the
// instance-wide directive denies gets no directive at all, hence no
// features either. The result is never empty, because an
// empty claim means basic access to every service to a verifier.
func (g *ServiceGrants) Directive(id Identity, instanceWide string) string {
	granted := make(grantSet, 4)
	if id.Provider != "" {
		for _, team := range id.Teams {
			// Exact names: nothing is folded.
			granted.merge(g.byTeam[subject{provider: id.Provider, name: team}])
		}
		for _, userID := range id.userIDs() {
			granted.merge(g.byUser[subject{provider: id.Provider, name: asciiLower(userID)}])
		}
		// A match that the current config no longer names — a session
		// remembers the matches of the config it was opened under —
		// finds nothing here.
		for _, key := range id.Matches {
			granted.merge(g.byMatch[subject{provider: id.Provider, name: key}])
		}
	}

	everywhere, allServices := granted[GrantAll]
	if !allServices {
		return specificDirective(granted, instanceWide)
	}
	return allServicesDirective(granted, everywhere, instanceWide)
}

// specificDirective builds the claim for an identity that is granted
// individual services only (or nothing).
func specificDirective(granted grantSet, instanceWide string) string {
	out := []string{"-" + GrantAll}
	for _, service := range sortedServices(granted) {
		if !auth.ServiceAllowed(instanceWide, service) {
			continue
		}
		out = append(out, "+"+service)
		if features := granted[service].list(); len(features) > 0 {
			out = append(out, featureDirective(service, features))
		}
	}
	return strings.Join(out, ",")
}

// allServicesDirective builds the claim for an identity with base access
// to every service; everywhere holds the features granted on all of
// them.
func allServicesDirective(granted grantSet, everywhere *featureSet, instanceWide string) string {
	if instanceWide == "" {
		out := []string{"+" + GrantAll}
		if features := everywhere.list(); len(features) > 0 {
			out = append(out, featureDirective(GrantAll, features))
		}
		for _, service := range sortedServices(granted) {
			if features := beyond(granted[service], everywhere); service != GrantAll && len(features) > 0 {
				out = append(out, featureDirective(service, features))
			}
		}
		return strings.Join(out, ",")
	}

	// With an instance-wide directive, base access is that directive as
	// it stands. Feature directives are positive and would re-grant base
	// access to whatever the instance denies, so they are placed, and
	// where needed undone, so that base access stays what the bound
	// says — for old and current verifiers alike.
	out := []string{instanceWide}
	named := boundServices(instanceWide)

	// Services the bound does not name share one verdict. Only when that
	// verdict is "allowed" can the features granted everywhere be
	// emitted as one "+all:…" directive; the services the bound names
	// and denies are then denied again after it.
	othersAllowed := auth.ServiceAllowed(instanceWide, unnamedService(named, granted))
	repeatDenials := false
	if features := everywhere.list(); othersAllowed && len(features) > 0 {
		out = append(out, featureDirective(GrantAll, features))
		repeatDenials = true
	}

	// Per-service feature directives: for services with features beyond
	// the ones emitted for all, and — when "+all:…" could not be used —
	// for every service the bound names and allows.
	services := sortedServices(granted)
	if !othersAllowed {
		services = slices.Compact(slices.Sorted(slices.Values(append(services, named...))))
	}
	for _, service := range services {
		if service == GrantAll || !auth.ServiceAllowed(instanceWide, service) {
			continue
		}
		features := &featureSet{names: make(map[string]struct{}, 2)}
		if own, ok := granted[service]; ok {
			features.add(own)
		}
		var list []string
		if othersAllowed {
			list = beyond(features, everywhere)
		} else {
			features.add(everywhere)
			list = features.list()
		}
		if len(list) > 0 {
			out = append(out, featureDirective(service, list))
		}
	}

	if repeatDenials {
		for _, service := range named {
			if !auth.ServiceAllowed(instanceWide, service) {
				out = append(out, "-"+service)
			}
		}
	}
	return strings.Join(out, ",")
}

// featureDirective renders "+service:f1:f2".
func featureDirective(service string, features []string) string {
	return "+" + service + ":" + strings.Join(features, ":")
}

// beyond returns the features of a service that are not already covered
// by the features granted on every service.
func beyond(features, everywhere *featureSet) []string {
	if everywhere.all {
		return nil
	}
	if features.all {
		return []string{GrantAll}
	}
	out := make([]string, 0, len(features.names))
	for _, name := range slices.Sorted(maps.Keys(features.names)) {
		if _, covered := everywhere.names[name]; !covered {
			out = append(out, name)
		}
	}
	return out
}

// boundServices returns the specific services an instance-wide directive
// names, sorted and de-duplicated.
func boundServices(instanceWide string) []string {
	var names []string
	for _, raw := range strings.Split(instanceWide, ",") {
		raw = strings.TrimSpace(raw)
		if len(raw) < 2 || (raw[0] != '+' && raw[0] != '-') {
			continue
		}
		name, _, _ := strings.Cut(strings.ToLower(raw[1:]), ":")
		name = strings.TrimSpace(name)
		if name != "" && name != GrantAll {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return slices.Compact(names)
}

// unnamedService returns a service name that neither the bound nor the
// grants mention, to ask the bound for its verdict on "everything else".
func unnamedService(named []string, granted grantSet) string {
	name := "unnamed"
	for {
		_, isGranted := granted[name]
		if !isGranted && !slices.Contains(named, name) {
			return name
		}
		name += "-x"
	}
}

// Groups returns the validated section in config order: members in
// their canonical spelling and sorted, services in the config's grant
// form. For logging.
func (g *ServiceGrants) Groups() []GrantGroup {
	out := make([]GrantGroup, 0, len(g.groups))
	for _, group := range g.groups {
		out = append(out, GrantGroup{
			Name:     group.Name,
			Members:  slices.Clone(group.Members),
			Services: slices.Clone(group.Services),
		})
	}
	return out
}

// Table renders the validated groups one per line, "label: members →
// services", for the startup log.
func (g *ServiceGrants) Table() []string {
	out := make([]string, 0, len(g.groups))
	for i, group := range g.groups {
		label := group.Name
		if label == "" {
			label = fmt.Sprintf("grants[%d]", i)
		}
		services := "(nothing)"
		if len(group.Services) > 0 {
			services = strings.Join(group.Services, ", ")
		}
		out = append(out, label+": "+strings.Join(group.Members, ", ")+" → "+services)
	}
	return out
}

// Providers returns the names of the providers that members of any
// group come through, sorted.
func (g *ServiceGrants) Providers() []string {
	seen := make(map[string]struct{}, 4)
	for sub := range g.byTeam {
		seen[sub.provider] = struct{}{}
	}
	for sub := range g.byUser {
		seen[sub.provider] = struct{}{}
	}
	for sub := range g.byMatch {
		seen[sub.provider] = struct{}{}
	}
	return slices.Sorted(maps.Keys(seen))
}

// AttributeMembers returns the attribute members the section names for
// a provider: what that provider has to evaluate for the identities it
// authenticates. Team and user members are not among them.
func (g *ServiceGrants) AttributeMembers(provider string) []protection.AttributeMember {
	if g == nil {
		return nil
	}
	return slices.Clone(g.attributes[provider])
}
