package protection

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
)

func TestMembers_Match(t *testing.T) {
	attrs := jsonAttributes(t, sampleClaims)

	tests := []struct {
		name    string
		members []AttributeMember
		want    []string
	}{
		{"none", nil, nil},
		{"a list contains the value", []AttributeMember{{"groups", "ethpandaops"}}, []string{"groups:ethpandaops"}},
		{"a value with a colon", []AttributeMember{{"groups", "sigp:core"}}, []string{"groups:sigp:core"}},
		{"ASCII case is ignored, both ways", []AttributeMember{{"groups", "TEAM:UPPER"}, {"groups", "EthPandaOps"}}, []string{"groups:ethpandaops", "groups:team:upper"}},
		{"a string claim", []AttributeMember{{"department", "eng-consensus"}}, []string{"department:eng-consensus"}},
		{"the whole value, not a part", []AttributeMember{{"department", "eng"}, {"groups", "ethpanda"}, {"groups", "ethpandaops-evil"}}, nil},
		{"a string is not split", []AttributeMember{{"scope", "openid"}}, nil},
		{"a nested path", []AttributeMember{{"realm_access.roles", "ops"}}, []string{"realm_access.roles:ops"}},
		{"a deeper path", []AttributeMember{{"resource_access.myapp.roles", "myapp-admin"}}, []string{"resource_access.myapp.roles:myapp-admin"}},
		{"a number", []AttributeMember{{"level", "3"}}, []string{"level:3"}},
		{"a bool", []AttributeMember{{"admin", "true"}}, []string{"admin:true"}},
		{"email", []AttributeMember{{"email", "alice@example.org"}}, []string{"email:alice@example.org"}},
		{"a missing attribute", []AttributeMember{{"missing", "x"}, {"realm_access.groups", "ops"}}, nil},
		{"an object is never a value", []AttributeMember{{"object", "map[x:y]"}, {"object", "{\"x\":\"y\"}"}, {"object.x", "y"}}, []string{"object.x:y"}},
		{"null is never a value", []AttributeMember{{"nothing", "null"}, {"nothing", "<nil>"}}, nil},
		{"attribute names are case-sensitive", []AttributeMember{{"Groups", "ethpandaops"}}, nil},
		{"a Kelvin sign is not a k", []AttributeMember{{"groups", "Kthpandaops"}, {"groups", "other "}}, nil},
		{"several members, sorted and de-duplicated", []AttributeMember{{"groups", "other"}, {"groups", "ethpandaops"}, {"groups", "OTHER"}}, []string{"groups:ethpandaops", "groups:other"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := NewMembers(tc.members)
			if got := m.ForRequest(attrs); !slices.Equal(got, tc.want) {
				t.Errorf("per request: got %v, want %v", got, tc.want)
			}
			log, hook := test.NewNullLogger()
			if got := m.Capture(log, attrs, nil); !slices.Equal(got, tc.want) {
				t.Errorf("capture: got %v, want %v", got, tc.want)
			}
			if n := len(hook.AllEntries()); n != 0 {
				t.Errorf("capture logged %d entries", n)
			}
			if got := m.ForRequest(nil); got != nil {
				t.Errorf("without attributes: %v", got)
			}
		})
	}
}

// TestMembers_Bounds: an identity never carries more matches than a
// session can hold — in number and, together with its teams, in bytes.
// What is dropped is the tail of the sorted list, reported once at
// login.
func TestMembers_Bounds(t *testing.T) {
	// 200 members, all satisfied.
	values := make([]any, 0, 200)
	members := make([]AttributeMember, 0, 200)
	for i := range 200 {
		v := fmt.Sprintf("group-%03d", i)
		values = append(values, v)
		members = append(members, AttributeMember{Attribute: "groups", Value: v})
	}
	attrs := Attributes{"groups": values}
	m := NewMembers(members)

	log, hook := test.NewNullLogger()
	got := m.Capture(log, attrs, nil)
	if len(got) != MaxMatches {
		t.Fatalf("matches: %d, want %d", len(got), MaxMatches)
	}
	if got[0] != "groups:group-000" || got[MaxMatches-1] != fmt.Sprintf("groups:group-%03d", MaxMatches-1) {
		t.Errorf("not the head of the sorted list: %v … %v", got[0], got[MaxMatches-1])
	}
	entries := hook.AllEntries()
	if len(entries) != 1 || entries[0].Level != logrus.WarnLevel || entries[0].Data["dropped"] != 200-MaxMatches {
		t.Fatalf("login log: %+v", entries)
	}
	if again := m.Capture(log, attrs, nil); !slices.Equal(again, got) {
		t.Error("truncation is not deterministic")
	}
	// The per-request path stores nothing in a cookie, so the cookie's
	// budget does not apply to it: every satisfied member counts, and
	// nothing is logged because nothing is dropped.
	hook.Reset()
	if perRequest := m.ForRequest(attrs); len(perRequest) != 200 || !slices.IsSorted(perRequest) {
		t.Errorf("the per-request path cut the matches to %d", len(perRequest))
	}
	if len(hook.AllEntries()) != 0 {
		t.Errorf("the per-request path logged: %+v", hook.AllEntries())
	}

	// Long keys: the byte budget bites before the count does, and the
	// teams' share is taken off first.
	long := make([]AttributeMember, 0, 40)
	longValues := make([]any, 0, 40)
	for i := range 40 {
		v := fmt.Sprintf("%02d", i) + strings.Repeat("x", 240)
		longValues = append(longValues, v)
		long = append(long, AttributeMember{Attribute: "groups", Value: v})
	}
	teams := make([]string, 0, 32)
	for i := range 32 {
		teams = append(teams, fmt.Sprintf("%02d", i)+strings.Repeat("t", 61))
	}
	lm := NewMembers(long)
	withoutTeams := lm.Capture(log, Attributes{"groups": longValues}, nil)
	withTeams := lm.Capture(log, Attributes{"groups": longValues}, teams)
	if len(withoutTeams) >= 40 || len(withTeams) >= len(withoutTeams) || len(withTeams) == 0 {
		t.Errorf("byte budget: %d matches without teams, %d with 32 long teams", len(withoutTeams), len(withTeams))
	}
	total := 0
	for _, s := range append(slices.Clone(teams), withTeams...) {
		total += len(s) + 3
	}
	if total > maxCapturedBytes {
		t.Errorf("teams and matches take %d bytes, budget is %d", total, maxCapturedBytes)
	}

	// BoundMatches refuses oversized and empty entries outright.
	kept, dropped := BoundMatches([]string{"a:b", "", strings.Repeat("k", MaxMatchLen+1), "a:b", "c:d"}, nil)
	if !slices.Equal(kept, []string{"a:b", "c:d"}) || dropped != 2 {
		t.Errorf("BoundMatches: kept %v, dropped %d", kept, dropped)
	}
}
