package auth

import "strings"

// ServiceAllowed reports whether the named service is permitted by a
// comma-separated directive list of the form "+name" / "-name". The
// pseudo-name "all" matches every service.
//
// Directives are processed left-to-right; later directives override
// earlier ones. The default verdict (no matching directive) is allow.
//
// Examples:
//
//	""                    → allow (no constraint)
//	"+all"                → allow
//	"-all"                → deny
//	"+all,-spamoor"       → allow except spamoor
//	"-all,+buildoor"      → deny except buildoor
//	"+spamoor,+buildoor"  → still allow others (no -all baseline);
//	                        to express "only X" use "-all,+X"
//
// Whitespace and case in directive names are ignored. Malformed entries
// (missing +/- prefix, empty name) are skipped.
func ServiceAllowed(directives, service string) bool {
	if directives == "" || service == "" {
		return true
	}
	service = strings.ToLower(strings.TrimSpace(service))
	if service == "" {
		return true
	}

	allowed := true
	for _, raw := range strings.Split(directives, ",") {
		raw = strings.TrimSpace(raw)
		if len(raw) < 2 {
			continue
		}
		op := raw[0]
		if op != '+' && op != '-' {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(raw[1:]))
		if name == "" {
			continue
		}
		if name != "all" && name != service {
			continue
		}
		allowed = op == '+'
	}
	return allowed
}
