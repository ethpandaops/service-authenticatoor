package auth

import "strings"

// grantAll is the reserved name that stands for every service (in the
// service position of a directive) and for every feature (in a grant
// segment).
const grantAll = "all"

// FeatureBasic is the reserved feature name for base access to a
// service: what a bare "+svc" directive grants, and what ServiceAllowed
// asks for. Every positive directive for a service grants it, and only a
// denial of the service takes it away. A resource server must not use
// the name for a feature of its own.
const FeatureBasic = "basic"

// ServiceAllowed reports whether the named service is permitted by a
// comma-separated directive list — the token's "services" claim. It
// answers the base question "may this token be used against the service
// at all"; FeatureAllowed answers the question for one feature of a
// service.
//
// The model: a service directive grants basic access; features are
// extras on top. Basic access is itself a feature with the reserved
// name "basic" (FeatureBasic), so ServiceAllowed(d, svc) is
// FeatureAllowed(d, svc, "basic", …) in either mode.
//
// Directive grammar:
//
//	directive = [+|-]service(:grantSpec)*
//	grantSpec = feature | -feature | all
//	feature   = name | prefix*
//
// The service position also takes the pseudo-name "all", which matches
// every service. A feature ending in "*" is a prefix: "user*" stands
// for "user", "userxyz", "user-admin". A segment that is only "*" is
// "all".
//
//	+spamoor                 basic access, no further features
//	+spamoor:basic           the same, spelled out
//	+spamoor:all             basic + every feature
//	+spamoor:f1:f2           basic + f1 + f2
//	+spamoor:all:-plugins    basic + every feature except plugins
//	+spamoor:user*           basic + every feature starting with "user"
//	+spamoor:all:-user*      basic + every feature except those
//	+all:featA               every service: basic + featA
//	-spamoor                 deny spamoor entirely (features included)
//	-spamoor:basic           the same, spelled out
//	-spamoor:f1              remove f1, basic access untouched
//
// Evaluation:
//
//   - An empty directive string — a token without the claim — means
//     basic access to every service and nothing more. For a feature it
//     reads like "+all": nothing is said about any feature.
//   - Directives apply left to right and a later verdict overrides an
//     earlier one. Inside one directive the grant segments also apply
//     left to right (":all:-x" is not ":-x:all").
//   - Basic access defaults to ALLOW when no directive matches the
//     service: "+spamoor,+buildoor" still allows everything else. Write
//     "-all,+x" for "only x".
//   - Every positive directive grants basic access, whatever features
//     it lists ("+spamoor:f1", "+spamoor:-plugins"). Basic access is
//     taken away only by denying the service: "-spamoor", "-all", or a
//     negative directive that lists basic ("-spamoor:basic").
//   - A feature query (FeatureAllowed) never succeeds without basic
//     access. Beyond that it depends on the mode the caller picks: the
//     feature follows basic access unless it was excluded
//     (FeatureDefaultAllow), or it needs its own grant, by name or by
//     "all" (FeatureDefaultDeny).
//   - A positive directive without a segment for the queried feature
//     leaves what was said about that feature as it was, so
//     "+spamoor:f1,+spamoor" keeps f1.
//   - A negative directive without segments denies the service and
//     forgets what was said about its features. With segments it
//     excludes just those features and leaves basic access alone.
//   - Wildcards: "*" is a prefix match only at the very end of a
//     feature segment. A prefix never covers the reserved feature
//     "basic": "-spamoor:b*" does not take basic access away. There is
//     no wildcard for services — "all" is the only way to address
//     every service. Queries never contain wildcards.
//   - A malformed directive is skipped AS A WHOLE, for basic access and
//     for features alike — it grants nothing and denies nothing. A
//     directive is malformed when it has no +/- prefix or an empty
//     service name, or when ANY of its segments is: an empty segment
//     ("+spamoor:", "+spamoor::f1", "+spamoor:-"), a misplaced wildcard
//     ("us*er", "*admin", "u**"), "-basic" in a positive directive
//     ("+spamoor:all:-basic"), a signed segment in a negative one
//     ("-spamoor:-x"), or a wildcard in the service position
//     ("+spam*:x"). So "-all,+spamoor:us*er" grants nothing, and
//     "+spamoor:all:-us*er" grants nothing. All segments are checked
//     before any of them takes effect.
//   - The one exception, kept for compatibility: a directive without
//     any ":" is read exactly as earlier versions read it, so a bare
//     "+spam*" stays the literal name of a service that does not
//     exist, not a malformed entry.
//
// Whitespace and case are ignored throughout.
//
// Compatibility with earlier versions of this package (v0.0.3 and
// before, which know no segments):
//
//   - For every directive list WITHOUT a ":" the verdict is identical.
//   - A list WITH a ":" can read differently, because those versions
//     take "+spamoor:f1" for a service called "spamoor:f1" and skip it:
//     "-all,+spamoor:x" denies spamoor there and allows it here,
//     "-all,+all:x" denies everything there and allows it here, and
//     "-spamoor:basic" denies spamoor here and is ignored there.
//   - What this repository's issuer emits reads the same for both: it
//     always writes the bare directive ("+spamoor") next to a feature
//     directive, emits no denial with segments, and never writes
//     "basic". Anyone writing a claim by hand must do the same —
//     repeat the bare directive — for it to mean one thing to all
//     verifiers.
func ServiceAllowed(directives, service string) bool {
	if directives == "" || service == "" {
		return true
	}
	service = strings.ToLower(strings.TrimSpace(service))
	if service == "" {
		return true
	}

	allowed := true
	for _, d := range parseDirectives(directives) {
		if !d.matches(service) {
			continue
		}
		switch {
		case d.allow:
			allowed = true
		case !d.targeted:
			allowed = false
		}
		// A negative directive with segments excludes features only.
	}
	return allowed
}

// FeatureDefault selects what FeatureAllowed answers for a feature the
// directive list says nothing about.
type FeatureDefault int

const (
	// FeatureDefaultDeny: the feature is allowed only when it is
	// explicitly granted ("+svc:feat") or every feature is ("+svc:all"),
	// and it is not excluded later. For anything privileged that must be
	// handed out deliberately.
	FeatureDefaultDeny FeatureDefault = iota
	// FeatureDefaultAllow: the feature is allowed whenever base access
	// to the service is, unless it is explicitly excluded ("-svc:feat",
	// "+svc:all:-feat", ...). For ordinary functionality that one may
	// want to take away from someone later.
	FeatureDefaultAllow
)

// featureState is what a directive list says about one feature of one
// service.
type featureState int

const (
	featureUnset featureState = iota
	featureGranted
	featureExcluded
)

// FeatureAllowed reports whether a feature of a service may be used
// under the directive list. See ServiceAllowed for the grammar.
//
// NOTE — an EMPTY directive string is basic access to every service and
// nothing more. A token without the claim passes every service gate,
// and for a feature it is evaluated exactly like "+all": base access,
// feature state unset — allowed under FeatureDefaultAllow, DENIED under
// FeatureDefaultDeny. An empty "services" claim is what an
// authenticatoor without service grants (the grants config section)
// mints, so such an instance hands out no default-deny feature; grants
// are how those are given. An authenticatoor with grants never mints an
// empty claim.
//
// The walk over a directive list is left to right, tracking for the
// queried feature one of three states — unset, granted, excluded:
//
//   - "+svc:feat" and "+svc:all" (and "+all:…" for every service) set
//     granted;
//   - "-svc:feat", "-all:feat", "-svc:all" and a "-feat" / "-all"
//     segment inside a positive directive ("+svc:all:-feat",
//     "+svc:-feat") set excluded;
//   - a later directive overrides an earlier one, and inside one
//     directive the segments apply left to right;
//   - "-svc" (the service denied entirely) clears whatever was said
//     about its features, back to unset.
//
// The result is
//
//	ServiceAllowed(directives, service) AND
//	  (state == granted OR (state == unset AND def == FeatureDefaultAllow))
//
// so a feature is never allowed without base access to its service, in
// either mode:
//
//	basic access  state      FeatureDefaultDeny   FeatureDefaultAllow
//	denied        any        no                   no
//	allowed       unset      no                   yes
//	allowed       granted    yes                  yes
//	allowed       excluded   no                   no
//
// A token without the claim is the row "allowed, unset".
//
// Read the modes this way: with FeatureDefaultAllow a feature follows
// basic access unless it was excluded; with FeatureDefaultDeny it needs
// its own grant or ":all", so a token with the bare "+svc" has basic
// access and nothing default-deny.
//
// Arguments: the feature "basic" (FeatureBasic), like an empty feature,
// asks for the service itself and is equivalent to ServiceAllowed in
// both modes. An empty service is refused — unlike ServiceAllowed,
// which lets an empty service through, a feature check that cannot name
// its service is not answered with yes. The one exception is the service
// gate under the empty directive string, which is open whatever is
// asked ("basic" or an empty feature, any service). A feature that
// cannot be a feature name (the reserved word "all", or one containing
// ":", ",", "*" or a leading sign) is refused as well, under the empty
// directive string too: wildcards exist in directives only, never in
// queries.
func FeatureAllowed(directives, service, feature string, def FeatureDefault) bool {
	feature = strings.ToLower(strings.TrimSpace(feature))
	basic := feature == "" || feature == FeatureBasic
	if directives == "" && basic {
		// The service gate of a token without the claim: always open.
		// Any other feature takes the ordinary walk below, which over
		// no directives ends at base access with the feature unset.
		return true
	}
	service = strings.ToLower(strings.TrimSpace(service))
	if service == "" {
		return false
	}
	if basic {
		return ServiceAllowed(directives, service)
	}
	if !queryName(service) || !queryName(feature) || feature == grantAll {
		return false
	}

	base := true
	state := featureUnset
	for _, d := range parseDirectives(directives) {
		if !d.matches(service) {
			continue
		}
		if !d.targeted {
			// A bare directive decides base access. A denial also
			// forgets what was said about the service's features.
			base = d.allow
			if !d.allow {
				state = featureUnset
			}
			continue
		}
		if d.allow {
			base = true // a positive directive implies base access
		}
		for _, seg := range d.segments {
			if !seg.covers(feature) {
				continue
			}
			if seg.remove {
				state = featureExcluded
			} else {
				state = featureGranted
			}
		}
	}

	if !base {
		return false
	}
	return state == featureGranted || (state == featureUnset && def == FeatureDefaultAllow)
}

// HasFeature reports whether the token's "services" claim allows the
// named feature of a service; see FeatureAllowed, in particular for the
// meaning of a token without the claim (basic access to every service
// and nothing more: a feature is allowed under FeatureDefaultAllow and
// denied under FeatureDefaultDeny).
func (c *Claims) HasFeature(service, feature string, def FeatureDefault) bool {
	if c == nil {
		return false
	}
	return FeatureAllowed(c.Services, service, feature, def)
}

// queryName reports whether s can be the service or feature of a feature
// query: non-empty and free of the characters that structure a
// directive.
func queryName(s string) bool {
	return s != "" && !strings.ContainsAny(s, ":,*") && s[0] != '-' && s[0] != '+'
}

// directive is one parsed entry of a directive list.
type directive struct {
	// allow is true for "+", false for "-".
	allow bool
	// service is the lowercased service name, or "all".
	service string
	// targeted reports that the directive carried grant segments. For a
	// negative directive that makes it a removal of features rather
	// than a denial of the service.
	targeted bool
	// segments are the grant segments that take part in evaluation.
	segments []grantSegment
}

// grantSegment is one ":"-separated part of a directive after the
// service name.
type grantSegment struct {
	// name is the lowercased feature name, or "all"; for a prefix
	// segment it is the prefix without the trailing "*".
	name string
	// prefix reports that the segment was written with a trailing "*"
	// and covers every feature starting with name.
	prefix bool
	// remove reports whether the segment takes the grant away: a
	// "-"-signed segment of a positive directive, or any segment of a
	// negative one.
	remove bool
}

// covers reports whether the segment speaks about the queried feature.
// The query is a plain feature name; the reserved names never reach
// here (see FeatureAllowed).
func (s grantSegment) covers(feature string) bool {
	switch {
	case s.prefix:
		return strings.HasPrefix(feature, s.name)
	case s.name == grantAll:
		return true
	default:
		return s.name == feature
	}
}

// matches reports whether the directive applies to the queried service.
func (d directive) matches(service string) bool {
	return d.service == grantAll || d.service == service
}

// parseDirectives splits a directive list and drops malformed entries.
func parseDirectives(directives string) []directive {
	parts := strings.Split(directives, ",")
	out := make([]directive, 0, len(parts))
	for _, raw := range parts {
		if d, ok := parseDirective(raw); ok {
			out = append(out, d)
		}
	}
	return out
}

// parseDirective parses one entry; ok is false when it is malformed.
func parseDirective(raw string) (d directive, ok bool) {
	raw = strings.TrimSpace(raw)
	if len(raw) < 2 {
		return directive{}, false
	}
	op := raw[0]
	if op != '+' && op != '-' {
		return directive{}, false
	}
	fields := strings.Split(strings.ToLower(raw[1:]), ":")
	name := strings.TrimSpace(fields[0])
	if name == "" {
		return directive{}, false
	}

	if len(fields) > 1 && strings.Contains(name, "*") {
		// No wildcard in the service position. (A bare "+spam*" is left
		// as earlier versions read it: a literal name no service has.)
		return directive{}, false
	}

	// Check every segment before any of them takes effect: one malformed
	// segment makes the whole directive malformed, wherever it stands.
	allow := op == '+'
	type checkedSegment struct {
		name   string
		signed bool
		prefix bool
	}
	checked := make([]checkedSegment, 0, len(fields)-1)
	for _, field := range fields[1:] {
		seg := strings.TrimSpace(field)
		signed := strings.HasPrefix(seg, "-")
		if signed {
			seg = strings.TrimSpace(seg[1:])
		}
		if seg == "" {
			return directive{}, false // "+svc:", "+svc::f", "+svc:-"
		}
		if signed && !allow {
			return directive{}, false // "-svc:-x" has no meaning
		}
		prefix := false
		if i := strings.IndexByte(seg, '*'); i >= 0 {
			switch {
			case seg == "*":
				seg = grantAll
			case i == len(seg)-1:
				seg, prefix = seg[:i], true
			default:
				return directive{}, false // "us*er", "*admin", "u**"
			}
		}
		if seg == FeatureBasic && !prefix && signed {
			// "+svc:-basic": basic access cannot be excluded from a
			// directive that grants it.
			return directive{}, false
		}
		checked = append(checked, checkedSegment{name: seg, signed: signed, prefix: prefix})
	}

	d = directive{
		allow:    allow,
		service:  name,
		targeted: len(fields) > 1,
		segments: make([]grantSegment, 0, len(checked)),
	}
	for _, seg := range checked {
		if seg.name == FeatureBasic && !seg.prefix {
			if allow {
				// "+svc:basic": every positive directive grants it.
				continue
			}
			// "-svc:basic": without basic access nothing is left, so
			// this is the denial of the service.
			return directive{allow: false, service: name}, true
		}
		d.segments = append(d.segments, grantSegment{name: seg.name, prefix: seg.prefix, remove: seg.signed || !allow})
	}
	return d, true
}
