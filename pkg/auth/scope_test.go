package auth

import (
	"testing"
)

func TestMatchHost(t *testing.T) {
	tests := []struct {
		pattern string
		host    string
		want    bool
	}{
		{"foo.bar", "foo.bar", true},
		{"foo.bar", "FOO.BAR", true},
		{"foo.bar", "foo.bar.", false},
		{"foo.bar", "foo.baz", false},
		{"foo.bar", "x.foo.bar", false},

		{"*.foo.bar", "x.foo.bar", true},
		{"*.foo.bar", "x.y.foo.bar", true},
		{"*.foo.bar", "foo.bar", false},
		{"*.foo.bar", "evil-foo.bar", false},
		{"*", "anything", true},
		{"*", "anything.at.all", true},

		// suffix-spoof attempts: must NOT match a "*.<base>" pattern
		{"*.base.example", "app.base.example", true},
		{"*.base.example", "a.b.c.base.example", true},
		{"*.base.example", "attacker.com", false},
		{"*.base.example", "base.example.attacker.com", false},
		{"*.base.example", "attacker-base.example", false},
		{"*.base.example", "base.example", false},

		// partial wildcards are not supported
		{"foo*.bar", "foox.bar", false},
		{"*foo.bar", "xfoo.bar", false},

		// wildcards only allowed at leftmost position
		{"a.*.b", "a.x.b", false},
		{"a.b.*", "a.b.c", false},

		{"", "foo", false},
		{"foo", "", false},
		{"", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+" vs "+tt.host, func(t *testing.T) {
			got := MatchHost(tt.pattern, tt.host)
			if got != tt.want {
				t.Errorf("MatchHost(%q, %q) = %v, want %v", tt.pattern, tt.host, got, tt.want)
			}
		})
	}
}

func TestMatchAnyHost(t *testing.T) {
	patterns := []string{"a.example.com", "*.example.org"}

	if !MatchAnyHost(patterns, "a.example.com") {
		t.Error("expected a.example.com to match")
	}
	if !MatchAnyHost(patterns, "x.example.org") {
		t.Error("expected x.example.org to match")
	}
	if MatchAnyHost(patterns, "b.example.com") {
		t.Error("did not expect b.example.com to match")
	}
	if MatchAnyHost(nil, "anything") {
		t.Error("nil pattern list should not match anything")
	}
}
