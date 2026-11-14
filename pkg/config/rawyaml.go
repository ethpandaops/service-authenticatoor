package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/ethpandaops/service-authenticatoor/pkg/protection"
)

// The config is loaded through viper, which lower-cases every key and
// splits keys at dots. That is fine for settings with fixed names; it
// is wrong for maps whose keys are data — group names, email
// addresses — where case and dots belong to the key. Those maps are
// therefore read from the YAML document itself, through the helpers in
// this file.

// rawFormats are the config file extensions whose content this reader
// can parse. viper picks its parser by the extension; JSON is a subset
// of YAML, so both go through the YAML reader here.
var rawFormats = []string{".yaml", ".yml", ".json"}

// loadRawDocument parses the config file into its node tree and returns
// the top-level mapping, with YAML merge keys ("<<") resolved the way
// the loader resolves them. It returns nil when there is no file or the
// file is empty.
//
// unchecked is non-empty when there is a file that viper has loaded but
// this reader cannot inspect — a format other than YAML or JSON. It
// says why. None of the strict checks can run on such a file, so the
// caller must refuse it as soon as the config uses anything those
// checks protect.
//
// A file holding more than one YAML document is an error. Only the
// first document is ever read, so whatever stands after a "---" — a
// grants section, say — would be ignored without a word.
func loadRawDocument(path string) (root *yaml.Node, unchecked string, err error) {
	if path == "" {
		return nil, "", nil
	}
	if ext := strings.ToLower(filepath.Ext(path)); !slices.Contains(rawFormats, ext) {
		return nil, fmt.Sprintf("%s is not a YAML or JSON file", path), nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Sprintf("%s cannot be read a second time (%v)", path, err), nil
	}
	defer func() { _ = file.Close() }()

	dec := yaml.NewDecoder(file)
	var doc yaml.Node
	switch err := dec.Decode(&doc); {
	case errors.Is(err, io.EOF):
		return nil, "", nil // an empty file configures nothing
	case err != nil:
		return nil, fmt.Sprintf("%s cannot be parsed as YAML (%v)", path, err), nil
	}
	for {
		var next yaml.Node
		err := dec.Decode(&next)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, "", fmt.Errorf("%s: after the first YAML document: %w", path, err)
		}
		// An empty document — a trailing "---" — holds nothing to lose.
		if content := resolveNode(&next); content != nil && !isNull(content) {
			return nil, "", fmt.Errorf("%s holds more than one YAML document (a \"---\" separator). Only the "+
				"first would be read and the rest ignored; put everything into one document", path)
		}
	}

	root = resolveNode(&doc)
	switch {
	case root == nil || isNull(root):
		return nil, "", nil
	case root.Kind != yaml.MappingNode:
		return nil, fmt.Sprintf("%s does not hold a map of settings at its top level", path), nil
	}
	if err := resolveMerges(root, make(map[*yaml.Node]struct{}, 64)); err != nil {
		return nil, "", fmt.Errorf("%s: %w", path, err)
	}
	return root, "", nil
}

// isMergeKey reports whether a mapping key is the YAML merge key: a
// plain "<<". A quoted "<<" is an ordinary key.
func isMergeKey(key *yaml.Node) bool {
	return key.Kind == yaml.ScalarNode && key.Value == "<<" &&
		(key.Tag == "" || key.Tag == "!" || key.Tag == "!!merge")
}

// resolveMerges rewrites every mapping that uses a merge key
// ("<<: *base", "<<: [*a, *b]") into the mapping it stands for, in
// place. The loader resolves merges while decoding; the checks in this
// package walk the node tree, and would otherwise not see the merged
// keys at all — a team rule or a grants group pulled in through an
// anchor would escape every one of them.
//
// The semantics are the loader's: a key written in the mapping wins
// over a merged one, and of several merged mappings the first that has
// a key wins. A mapping with more than one merge key is refused rather
// than guessed at.
func resolveMerges(node *yaml.Node, seen map[*yaml.Node]struct{}) error {
	node = resolveNode(node)
	if node == nil {
		return nil
	}
	if _, done := seen[node]; done {
		return nil
	}
	seen[node] = struct{}{}

	if node.Kind == yaml.MappingNode {
		var sources []*yaml.Node
		merges := 0
		kept := make([]*yaml.Node, 0, len(node.Content))
		for i := 0; i+1 < len(node.Content); i += 2 {
			key, value := node.Content[i], node.Content[i+1]
			if !isMergeKey(key) {
				kept = append(kept, key, value)
				continue
			}
			merges++
			if merges > 1 {
				return fmt.Errorf("line %d: a map has more than one merge key (\"<<\"); "+
					"merge several maps with one key: \"<<: [*a, *b]\"", key.Line)
			}
			source := resolveNode(value)
			switch {
			case source != nil && source.Kind == yaml.MappingNode:
				sources = append(sources, source)
			case source != nil && source.Kind == yaml.SequenceNode:
				for _, item := range source.Content {
					item = resolveNode(item)
					if item == nil || item.Kind != yaml.MappingNode {
						return fmt.Errorf("line %d: a merge key (\"<<\") takes a map or a list of maps", key.Line)
					}
					sources = append(sources, item)
				}
			default:
				return fmt.Errorf("line %d: a merge key (\"<<\") takes a map or a list of maps", key.Line)
			}
		}
		for _, source := range sources {
			// The source may use merge keys itself.
			if err := resolveMerges(source, seen); err != nil {
				return err
			}
			for i := 0; i+1 < len(source.Content); i += 2 {
				if !hasKey(kept, source.Content[i]) {
					kept = append(kept, source.Content[i], source.Content[i+1])
				}
			}
		}
		node.Content = kept
	}
	for _, child := range node.Content {
		if err := resolveMerges(child, seen); err != nil {
			return err
		}
	}
	return nil
}

// hasKey reports whether the key/value pairs already hold the key,
// compared the way YAML compares scalar keys: exactly.
func hasKey(pairs []*yaml.Node, key *yaml.Node) bool {
	for i := 0; i+1 < len(pairs); i += 2 {
		if pairs[i].Kind == key.Kind && pairs[i].Value == key.Value {
			return true
		}
	}
	return false
}

// resolveNode unwraps document and alias nodes.
func resolveNode(n *yaml.Node) *yaml.Node {
	for n != nil {
		switch {
		case n.Kind == yaml.DocumentNode && len(n.Content) == 1:
			n = n.Content[0]
		case n.Kind == yaml.AliasNode:
			n = n.Alias
		default:
			return n
		}
	}
	return nil
}

// rawChild returns the value of key in a mapping node, matching the key
// the way viper does: ASCII case-insensitively. It returns nil when the
// node is not a mapping or has no such key.
func rawChild(mapping *yaml.Node, key string) *yaml.Node {
	mapping = resolveNode(mapping)
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if strings.EqualFold(mapping.Content[i].Value, key) {
			return resolveNode(mapping.Content[i+1])
		}
	}
	return nil
}

// nodeKind names the kind of a node for an error message.
func nodeKind(n *yaml.Node) string {
	switch {
	case n == nil || isNull(n):
		return "nothing"
	case n.Kind == yaml.MappingNode:
		return "a map"
	case n.Kind == yaml.SequenceNode:
		return "a list"
	default:
		return "a single value"
	}
}

// rawItems returns the elements of a sequence node; nil otherwise.
func rawItems(seq *yaml.Node) []*yaml.Node {
	seq = resolveNode(seq)
	if seq == nil || seq.Kind != yaml.SequenceNode {
		return nil
	}
	return seq.Content
}

// isNull reports whether a node is YAML null (a key without a value).
func isNull(n *yaml.Node) bool {
	return n != nil && n.Kind == yaml.ScalarNode && n.Tag == "!!null"
}

// rawStringListMap reads a mapping of key → list of strings, keeping the
// keys exactly as written. A scalar value counts as a list of one. what
// names the mapping in error messages.
func rawStringListMap(mapping *yaml.Node, what string) (map[string][]string, error) {
	mapping = resolveNode(mapping)
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%s: must be a map", what)
	}
	out := make(map[string][]string, len(mapping.Content)/2)
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		keyNode, valueNode := mapping.Content[i], resolveNode(mapping.Content[i+1])
		if keyNode.Kind != yaml.ScalarNode {
			return nil, fmt.Errorf("%s: keys must be plain values", what)
		}
		key := keyNode.Value
		if _, dup := out[key]; dup {
			return nil, fmt.Errorf("%s: key %q is listed twice", what, key)
		}
		list, err := rawStringList(valueNode)
		if err != nil {
			return nil, fmt.Errorf("%s: %q: %w", what, key, err)
		}
		out[key] = list
	}
	return out, nil
}

// rawStringList reads a sequence of scalars, or a single scalar, as a
// list of strings.
func rawStringList(n *yaml.Node) ([]string, error) {
	switch {
	case n == nil || isNull(n):
		return nil, fmt.Errorf("must be a list (use [] for none)")
	case n.Kind == yaml.SequenceNode:
		out := make([]string, 0, len(n.Content))
		for _, item := range n.Content {
			item = resolveNode(item)
			if item == nil || item.Kind != yaml.ScalarNode || isNull(item) {
				return nil, fmt.Errorf("list entries must be plain values")
			}
			out = append(out, item.Value)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("must be a list (use [] for none)")
	}
}

// providerBlockKeys are the config keys of the per-type provider
// blocks, as they appear at the top level (legacy form) and inside a
// providers entry.
var providerBlockKeys = []string{"cloudflareAccess", "basicAuth", "anyAuth", "githubOAuth", "oidc"}

// teamRulesOf returns the team rule list of the named provider block.
func (p *ProviderConfig) teamRulesOf(block string) []protection.TeamRule {
	switch block {
	case "cloudflareAccess":
		return p.CloudflareAccess.TeamRules
	case "basicAuth":
		return p.BasicAuth.TeamRules
	case "anyAuth":
		return p.AnyAuth.TeamRules
	case "githubOAuth":
		return p.GitHubOAuth.TeamRules
	case "oidc":
		return p.OIDC.TeamRules
	default:
		return nil
	}
}

// teamsOf returns the static team list of the named provider block.
func (p *ProviderConfig) teamsOf(block string) []string {
	switch block {
	case "cloudflareAccess":
		return p.CloudflareAccess.Teams
	case "basicAuth":
		return p.BasicAuth.Teams
	case "anyAuth":
		return p.AnyAuth.Teams
	case "githubOAuth":
		return p.GitHubOAuth.Teams
	case "oidc":
		return p.OIDC.Teams
	default:
		return nil
	}
}

// restoreRuleMaps replaces the `map` of every team rule by what the
// YAML document says. viper's view of those maps has lower-cased keys
// and breaks keys at dots; the keys are group names and email
// addresses, so they are taken as written. Runs before the legacy
// blocks are converted into provider entries.
func (c *Config) restoreRuleMaps(root *yaml.Node) error {
	if root == nil {
		return nil
	}

	// The legacy top-level blocks share their shape with a providers
	// entry, so view them as one.
	legacy := &ProviderConfig{
		CloudflareAccess: c.CloudflareAccess,
		BasicAuth:        c.BasicAuth,
		AnyAuth:          c.AnyAuth,
		GitHubOAuth:      c.GitHubOAuth,
		OIDC:             c.OIDC,
	}
	if err := legacy.restoreRuleMaps(root, ""); err != nil {
		return err
	}

	entries := rawItems(rawChild(root, "providers"))
	for i := range c.Providers {
		if i >= len(entries) {
			break
		}
		if err := c.Providers[i].restoreRuleMaps(entries[i], fmt.Sprintf("providers[%d].", i)); err != nil {
			return err
		}
	}
	return nil
}

// restoreRuleMaps does the work of Config.restoreRuleMaps for the blocks
// found under one mapping node. The rule slices are shared with the
// config the ProviderConfig was built from, so writing the maps here
// updates it.
func (p *ProviderConfig) restoreRuleMaps(node *yaml.Node, where string) error {
	for _, block := range providerBlockKeys {
		rules := p.teamRulesOf(block)
		rawRules := rawItems(rawChild(rawChild(node, block), "teamRules"))
		for j := range rules {
			if j >= len(rawRules) {
				break
			}
			rawMap := rawChild(rawRules[j], "map")
			if rawMap == nil || isNull(rawMap) {
				continue
			}
			what := fmt.Sprintf("%s%s.teamRules[%d].map", where, block, j)
			mapping, err := rawStringListMap(rawMap, what)
			if err != nil {
				return err
			}
			rules[j].Map = mapping
		}
	}
	return nil
}
