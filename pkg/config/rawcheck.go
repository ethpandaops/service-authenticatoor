package config

import (
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/ethpandaops/service-authenticatoor/pkg/protection"
)

// checkRawDocument inspects the YAML document for mistakes that the
// loader would otherwise swallow, all of which fail open:
//
//   - Keys that differ only by case. The loader treats keys
//     case-insensitively and would merge "Panda" and "panda" — in an
//     order that changes from one start to the next. Any such pair, at
//     any depth, is an error naming both spellings.
//   - A key that looks like the service grants section but is not it:
//     "grant", "teamService", "team_services", or "grants" nested
//     under another key (looksLikeGrantsSection), and at the top level
//     also a misspelling of it such as "garnts" (misspelledGrants).
//     Ignoring it would leave every service open where the operator
//     meant to restrict them, so it is an error.
//   - Other unknown top-level keys, which are reported as a warning:
//     released versions ignored them, and a config that started then
//     has to start now.
func checkRawDocument(root *yaml.Node) (warnings []string, err error) {
	if root == nil {
		return nil, nil
	}
	if err := checkKeys(root, "", false); err != nil {
		return nil, err
	}

	known := knownTopLevelKeys()
	var unknown []string
	for i := 0; i+1 < len(root.Content); i += 2 {
		key := root.Content[i].Value
		if slices.ContainsFunc(known, func(k string) bool { return strings.EqualFold(k, key) }) {
			continue
		}
		if looksLikeGrantsSection(key) || misspelledGrants(key) {
			return nil, fmt.Errorf("unknown key %q: it looks like the service grants section, which is "+
				"spelled %q. Left like this it would be ignored and every service would stay open "+
				"(see docs/config.md, Service grants)", key, grantsKey)
		}
		unknown = append(unknown, key)
	}
	if len(unknown) > 0 {
		warnings = append(warnings, fmt.Sprintf(
			"unknown top-level config key(s) %s are ignored — check for typos", quoteKeys(unknown)))
	}
	return warnings, nil
}

// knownTopLevelKeys returns the top-level keys the loader understands:
// those of the Config struct, plus the sections read from the YAML
// document directly.
func knownTopLevelKeys() []string {
	t := reflect.TypeOf(Config{})
	keys := make([]string, 0, t.NumField()+2)
	for i := range t.NumField() {
		if tag := t.Field(i).Tag.Get("mapstructure"); tag != "" && tag != "-" {
			keys = append(keys, tag)
		}
	}
	// removedTeamServicesKey is "known" here so that loadGrants reports
	// it, with the message that says what replaced it.
	return append(keys, grantsKey, removedTeamServicesKey)
}

// grantsLookalikes are spellings (lower-cased, without "_", "-", "."
// and spaces) under which someone might write the grants section.
var grantsLookalikes = []string{
	"grant", "grants", "teamservice", "teamservices", "servicegrant", "servicegrants",
	"teamgrant", "teamgrants", "usergrant", "usergrants", "accessgrant", "accessgrants",
	"permission", "permissions", "serviceaccess", "teamaccess",
}

// grantsTypoDistance is how far a key may be from "grants" and still
// be taken for a misspelling of it.
const grantsTypoDistance = 2

// looksLikeGrantsSection reports whether a key that is not a known
// config key was probably meant to be the grants section: ignoring
// case and the separators "_", "-", "." and " ", it is one of
// grantsLookalikes, contains "grant" or starts with "teamserv".
func looksLikeGrantsSection(key string) bool {
	squeezed := squeezeKey(key)
	return slices.Contains(grantsLookalikes, squeezed) ||
		strings.Contains(squeezed, "grant") || strings.HasPrefix(squeezed, "teamserv")
}

// misspelledGrants reports whether an unknown top-level key is a
// misspelling of "grants": ignoring case and separators, it is at most
// grantsTypoDistance edits away from it, an edit being a dropped, added
// or replaced letter or two neighbouring letters swapped ("garnts",
// "grnts", "grabts", "gratns").
//
// Together with looksLikeGrantsSection this is everything that is
// recognised. A key that means the section in other words ("acl",
// "access") is an unknown key like any other, and only warned about.
func misspelledGrants(key string) bool {
	return editDistance(squeezeKey(key), grantsKey) <= grantsTypoDistance
}

// squeezeKey lower-cases a key and drops the separators people put into
// key names.
func squeezeKey(key string) string {
	return strings.NewReplacer("_", "", "-", "", ".", "", " ", "").Replace(strings.ToLower(key))
}

// editDistance is the Damerau-Levenshtein distance of two strings in
// its "optimal string alignment" form: the number of insertions,
// deletions, substitutions and swaps of two adjacent bytes that turn
// one into the other.
func editDistance(a, b string) int {
	prev2 := make([]int, len(b)+1)
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
			if i > 1 && j > 1 && a[i-1] == b[j-2] && a[i-2] == b[j-1] {
				cur[j] = min(cur[j], prev2[j-2]+1)
			}
		}
		prev2, prev, cur = prev, cur, prev2
	}
	return prev[len(b)]
}

// checkKeys walks the document. In every mapping it rejects keys that
// are the same but for case; outside of data maps it also rejects a
// grants-like key that is not at the top level. dataKeys marks mappings
// whose keys are data rather than settings — team names, user ids,
// group names — and may therefore be called anything.
func checkKeys(node *yaml.Node, path string, dataKeys bool) error {
	node = resolveNode(node)
	if node == nil {
		return nil
	}
	switch node.Kind {
	case yaml.SequenceNode:
		for i, item := range node.Content {
			if err := checkKeys(item, path+"["+strconv.Itoa(i)+"]", dataKeys); err != nil {
				return err
			}
		}
	case yaml.MappingNode:
		seen := make(map[string]string, len(node.Content)/2)
		for i := 0; i+1 < len(node.Content); i += 2 {
			key := node.Content[i].Value
			where := "at the top level"
			if path != "" {
				where = "in " + path
			}

			folded := strings.ToLower(key)
			if other, dup := seen[folded]; dup {
				if other == key {
					return fmt.Errorf("key %q is listed twice %s", key, where)
				}
				return fmt.Errorf("keys %q and %q %s are the same key (keys are case-insensitive); "+
					"keep one", other, key, where)
			}
			seen[folded] = key

			if path != "" && !dataKeys && looksLikeGrantsSection(key) {
				return fmt.Errorf("key %q %s: the service grants section is the top-level key %q; "+
					"nested here it would be ignored and every service would stay open", key, where, grantsKey)
			}

			child := key
			if path != "" {
				child = path + "." + key
			}
			// The map of a team rule holds data under its keys.
			childData := dataKeys || strings.EqualFold(key, "map")
			if err := checkKeys(node.Content[i+1], child, childData); err != nil {
				return err
			}
		}
	}
	return nil
}

// quoteKeys renders keys for a message.
func quoteKeys(keys []string) string {
	quoted := make([]string, 0, len(keys))
	for _, k := range keys {
		quoted = append(quoted, strconv.Quote(k))
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

// deprecatedKeys lists, per config struct, the keys that a released
// version documented or read and that mean nothing any more. A config
// that has one must still start: the key is reported in a deprecation
// warning and otherwise ignored, as released versions ignored it once
// it was gone. Keys are lower-cased.
//
// The list was made by comparing the config structs, the reference
// table in docs/config.md and the example files of every release with
// the current ones.
var deprecatedKeys = map[reflect.Type]map[string]string{
	reflect.TypeOf(AnyAuthConfig{}): {
		"loginpath": "the login form is always at /<name>/login (/anyauth/login for the legacy block)",
	},
	reflect.TypeOf(GitHubOAuthConfig{}): {
		"sessionsecret":     "the session key is derived from the JWT signing key",
		"sessionsecretfile": "the session key is derived from the JWT signing key",
	},
}

// checkProviderKeys rejects what the loader would silently drop or
// bend inside the provider configuration:
//
//   - unknown keys in a providers entry, in a provider type block (also
//     in the legacy top-level form) and in a team rule. A dropped key
//     there fails open — a rule written with "prefx:" instead of
//     "prefix:" would otherwise load as a rule without a prefix. Keys
//     that released versions knew (deprecatedKeys) are not errors; they
//     are returned as deprecation warnings;
//   - a map where a list belongs (providers, teamRules) and a list
//     where a map belongs (a type block, a providers entry). The loader
//     converts between the two without a word, and the result would
//     pass by every check made here on the document;
//   - rule keys that are present but empty, which must never count as
//     "not set".
func checkProviderKeys(root *yaml.Node) (deprecations []string, err error) {
	if root == nil {
		return nil, nil
	}
	entry := reflect.TypeOf(ProviderConfig{})

	// The legacy top-level blocks are the type blocks of an entry.
	for i := range entry.NumField() {
		field := entry.Field(i)
		if field.Type.Kind() != reflect.Struct {
			continue
		}
		key := field.Tag.Get("mapstructure")
		if node := rawChild(root, key); node != nil {
			if err := checkStructKeys(node, field.Type, key, &deprecations); err != nil {
				return nil, err
			}
		}
	}

	providers := rawChild(root, "providers")
	if err := requireList(providers, "providers", "one \"- name: …\" entry per provider"); err != nil {
		return nil, err
	}
	for i, item := range rawItems(providers) {
		where := fmt.Sprintf("providers[%d]", i)
		if item = resolveNode(item); item == nil || item.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("%s: must be a provider entry (a map with name, type and the type's block), "+
				"not %s", where, nodeKind(item))
		}
		if err := checkStructKeys(item, entry, where, &deprecations); err != nil {
			return nil, err
		}
	}
	return deprecations, nil
}

// requireList refuses a value that is neither a list nor absent where
// the config takes a list of entries. The loader would turn a single
// map into a list of one, and that entry would then be invisible to
// the checks that walk the document.
func requireList(node *yaml.Node, where, shape string) error {
	node = resolveNode(node)
	if node == nil || isNull(node) || node.Kind == yaml.SequenceNode {
		return nil
	}
	return fmt.Errorf("%s: must be a list (%s), not %s", where, shape, nodeKind(node))
}

// checkStructKeys checks that every key of a mapping node names a field
// of the config struct t (by its mapstructure tag, case-insensitively),
// and descends into struct fields and lists of structs. Maps hold data
// under their keys and are not descended into. Deprecated keys are
// appended to deprecations instead of being refused.
func checkStructKeys(node *yaml.Node, t reflect.Type, where string, deprecations *[]string) error {
	node = resolveNode(node)
	if node == nil || isNull(node) {
		return nil // "block:" without a value is an empty block
	}
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("%s: must be a map of settings, not %s", where, nodeKind(node))
	}

	fields := make(map[string]reflect.StructField, t.NumField())
	allowed := make([]string, 0, t.NumField())
	for i := range t.NumField() {
		if tag := t.Field(i).Tag.Get("mapstructure"); tag != "" && tag != "-" {
			fields[strings.ToLower(tag)] = t.Field(i)
			allowed = append(allowed, tag)
		}
	}
	slices.Sort(allowed)

	for i := 0; i+1 < len(node.Content); i += 2 {
		key, value := node.Content[i].Value, resolveNode(node.Content[i+1])
		field, known := fields[strings.ToLower(key)]
		if !known {
			if why, deprecated := deprecatedKeys[t][strings.ToLower(key)]; deprecated {
				*deprecations = append(*deprecations, fmt.Sprintf(
					"%s.%s is deprecated and ignored: %s. Remove the key", where, key, why))
				continue
			}
			return fmt.Errorf("%s: unknown key %q (the keys here are: %s). An unknown key would be "+
				"ignored, and a misspelled one silently changes what the config means",
				where, key, strings.Join(allowed, ", "))
		}
		child := where + "." + field.Tag.Get("mapstructure")
		switch {
		case field.Type.Kind() == reflect.Struct && field.Type != reflect.TypeOf(time.Time{}):
			if field.Type == reflect.TypeOf(OIDCBearerConfig{}) {
				if err := checkBearerBlock(value, child); err != nil {
					return err
				}
			}
			if err := checkStructKeys(value, field.Type, child, deprecations); err != nil {
				return err
			}
		case field.Type.Kind() == reflect.Slice && field.Type.Elem().Kind() == reflect.Struct:
			if err := requireList(value, child, "one \"- …\" entry each"); err != nil {
				return err
			}
			for j, item := range rawItems(value) {
				itemWhere := fmt.Sprintf("%s[%d]", child, j)
				if field.Type.Elem() == reflect.TypeOf(protection.TeamRule{}) {
					if err := checkTeamRuleValues(resolveNode(item), itemWhere); err != nil {
						return err
					}
				}
				if err := checkStructKeys(item, field.Type.Elem(), itemWhere, deprecations); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// checkBearerBlock checks the shape of an oidc.bearer block. Written
// down, the block is meant to switch bearer tokens on, so it has to
// say whose: a block that is empty, or whose audiences are missing,
// empty or not a list of non-empty strings, is refused instead of
// being read as "off" — or, for a single string where the list
// belongs, as a list of one.
func checkBearerBlock(block *yaml.Node, where string) error {
	if block == nil || isNull(block) {
		return fmt.Errorf("%s: is empty; leave the key out or list the accepted audiences", where)
	}
	if block.Kind != yaml.MappingNode {
		return nil // checkStructKeys says what it has to be
	}
	audiences := resolveNode(rawChild(block, "audiences"))
	if audiences == nil || audiences.Kind != yaml.SequenceNode || len(audiences.Content) == 0 {
		return fmt.Errorf("%s.audiences: must be a non-empty list of the client ids whose tokens are "+
			"accepted, not %s", where, nodeKind(audiences))
	}
	for i, item := range audiences.Content {
		if item = resolveNode(item); item == nil || item.Kind != yaml.ScalarNode || item.Value == "" {
			return fmt.Errorf("%s.audiences[%d]: must be a non-empty string", where, i)
		}
	}
	return nil
}

// checkTeamRuleValues rejects keys of a team rule that are present but
// empty. Written down, a key is meant: "prefix: ”", "map: {}", "map:"
// and "regex: ”" must not quietly turn the rule into another kind of
// rule.
func checkTeamRuleValues(rule *yaml.Node, where string) error {
	if rule == nil || rule.Kind != yaml.MappingNode {
		return fmt.Errorf("%s: a team rule must be a map with the key claim and one of prefix, map, regex, value", where)
	}
	for i := 0; i+1 < len(rule.Content); i += 2 {
		key, value := strings.ToLower(rule.Content[i].Value), resolveNode(rule.Content[i+1])
		empty := value == nil || isNull(value)
		switch key {
		case "claim", "prefix", "regex", "split":
			if empty || value.Kind != yaml.ScalarNode || value.Value == "" {
				return fmt.Errorf("%s.%s: is empty; leave the key out or give it a value", where, key)
			}
		case "map":
			if empty || value.Kind != yaml.MappingNode || len(value.Content) == 0 {
				return fmt.Errorf("%s.map: is empty; a map rule needs at least one \"value: [teams]\" entry", where)
			}
		case "value":
			if empty || value.Kind != yaml.ScalarNode || value.Tag != "!!bool" || !strings.EqualFold(value.Value, "true") {
				return fmt.Errorf("%s.value: must be true (\"value: true\" takes every value of the "+
					"attribute as a team); leave the key out otherwise", where)
			}
		}
	}
	return nil
}
