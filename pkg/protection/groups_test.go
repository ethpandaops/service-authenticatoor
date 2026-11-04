package protection

import "testing"

func TestGroupSetAllows(t *testing.T) {
	tests := []struct {
		name    string
		allowed []string
		groups  []string
		want    bool
	}{
		{"empty allow-list permits all", nil, nil, true},
		{"exact team match", []string{"ethpandaops:Core"}, []string{"ethpandaops:core"}, true},
		{"team entry does not match bare org", []string{"ethpandaops:Core"}, []string{"ethpandaops"}, false},
		{"team entry does not match another team", []string{"ethpandaops:Core"}, []string{"ethpandaops:Interns"}, false},
		{"org entry matches its teams", []string{"EthPandaOps"}, []string{"ethpandaops:Core"}, true},
		{"org entry matches the bare org", []string{"ethpandaops"}, []string{"ethpandaops"}, true},
		{"no overlap", []string{"ethpandaops"}, []string{"ethereum", "sigp:lighthouse"}, false},
		{"no groups claim", []string{"ethpandaops"}, nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := NewGroupSet(tc.allowed).Allows(tc.groups); got != tc.want {
				t.Fatalf("Allows(%v) with %v: got %v, want %v", tc.groups, tc.allowed, got, tc.want)
			}
		})
	}
}
