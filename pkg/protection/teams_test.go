package protection

import (
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"

	"github.com/ethpandaops/service-authenticatoor/pkg/auth"
)

// numbered returns n distinct valid team names "<prefix>-00", "<prefix>-01", …
func numbered(prefix string, n int) []string {
	out := make([]string, 0, n)
	for i := range n {
		out = append(out, fmt.Sprintf("%s-%02d", prefix, i))
	}
	return out
}

func TestValidateTeams(t *testing.T) {
	tests := []struct {
		name    string
		in      []string
		want    []string
		wantErr string
	}{
		{"nil", nil, nil, ""},
		{"sorted", []string{"panda", "geth"}, []string{"geth", "panda"}, ""},
		{"duplicates collapse", []string{"panda", "panda"}, []string{"panda"}, ""},
		{"uppercase is an error, not another spelling", []string{"panda", "Panda"}, nil, `invalid team name(s) ["Panda"]`},
		{"the error says how to fix it", []string{"PANDA"}, nil, "write them lowercase"},
		{"padding is an error", []string{" geth "}, nil, `invalid team name(s) [" geth "]`},
		{"a no-break space is an error", []string{"geth\u00a0"}, nil, "invalid team name(s)"},
		{"invalid name", []string{"panda", "core devs"}, nil, `invalid team name(s) ["core devs"]`},
		{"empty name", []string{""}, nil, `invalid team name(s) [""]`},
		{"prefixed name", []string{"team:panda"}, nil, `invalid team name(s) ["team:panda"]`},
		{"exactly the bound", numbered("t", auth.MaxTeams), numbered("t", auth.MaxTeams), ""},
		{"over the bound", numbered("t", auth.MaxTeams+1), nil, "too many teams: 33 (at most 32)"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ValidateTeams(tc.in)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error: got %v, want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestStaticTeams_With(t *testing.T) {
	// 40 names sorting before "panda", to prove a flood of captured
	// teams cannot push a configured team out.
	flood := numbered("a", 40)

	tests := []struct {
		name     string
		static   []string
		captured []string
		want     []string
	}{
		{"none", nil, nil, nil},
		{"static only", []string{"panda"}, nil, []string{"panda"}},
		{"captured only", nil, []string{"lighthouse"}, []string{"lighthouse"}},
		{"union is sorted", []string{"panda"}, []string{"lighthouse", "geth"}, []string{"geth", "lighthouse", "panda"}},
		{"overlap is de-duplicated", []string{"panda"}, []string{"panda", "geth"}, []string{"geth", "panda"}},
		{"captured names are taken only in normal form", nil, []string{" geth ", "Geth", "bad name", "geth"}, []string{"geth"}},
		{
			"bound keeps the static teams first",
			[]string{"panda", "zeta"},
			flood,
			append(slices.Clone(flood[:auth.MaxTeams-2]), "panda", "zeta"),
		},
		{"captured alone is bounded", nil, flood, flood[:auth.MaxTeams]},
		{
			"an overlapping captured team takes no room",
			[]string{"panda"},
			append(slices.Clone(flood), "panda"),
			append(slices.Clone(flood[:auth.MaxTeams-1]), "panda"),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := NewStaticTeams(tc.static)
			if s.Err() != nil {
				t.Fatalf("static: %v", s.Err())
			}
			got := s.With(tc.captured)
			if !slices.Equal(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
			if len(got) > auth.MaxTeams {
				t.Errorf("result holds %d teams, bound is %d", len(got), auth.MaxTeams)
			}
			if tc.want == nil && got != nil {
				t.Errorf("want nil for no teams, got %#v", got)
			}
			// Deterministic: the same input in another order gives the
			// same result.
			reversed := slices.Clone(tc.captured)
			slices.Reverse(reversed)
			if again := s.With(reversed); !slices.Equal(again, got) {
				t.Errorf("order-dependent result: %v vs %v", again, got)
			}
		})
	}
}

func TestStaticTeams_Capture(t *testing.T) {
	tests := []struct {
		name      string
		static    []string
		derived   []string
		want      []string
		wantWarns []string
	}{
		{"nothing derived", []string{"panda"}, nil, nil, nil},
		{"valid names pass silently", nil, []string{"lighthouse", "geth", "geth"}, []string{"geth", "lighthouse"}, nil},
		{
			"nothing is folded: case and whitespace variants are dropped",
			nil,
			[]string{"Lighthouse", " geth", "geth\u00a0", "\u212aurtosis", "geth"},
			[]string{"geth"},
			[]string{"dropping invalid team names"},
		},
		{
			"invalid names are dropped with a warning",
			nil,
			[]string{"geth", "core devs", ""},
			[]string{"geth"},
			[]string{"dropping invalid team names"},
		},
		{
			"surplus is dropped with a warning",
			[]string{"panda"},
			numbered("a", 40),
			numbered("a", auth.MaxTeams-1),
			[]string{"too many teams"},
		},
		{
			"both problems, both warnings",
			nil,
			append(numbered("a", 40), "not valid"),
			numbered("a", auth.MaxTeams),
			[]string{"dropping invalid team names", "too many teams"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			log, hook := test.NewNullLogger()
			s := NewStaticTeams(tc.static)

			got := s.Capture(log, tc.derived)
			if !slices.Equal(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}

			entries := hook.AllEntries()
			if len(entries) != len(tc.wantWarns) {
				t.Fatalf("log entries: got %d, want %d", len(entries), len(tc.wantWarns))
			}
			for i, want := range tc.wantWarns {
				if entries[i].Level != logrus.WarnLevel || !strings.Contains(entries[i].Message, want) {
					t.Errorf("entry %d: got %s %q, want a warning containing %q",
						i, entries[i].Level, entries[i].Message, want)
				}
			}

			// What was captured always fits next to the static teams.
			if merged := s.With(got); len(merged) > auth.MaxTeams {
				t.Errorf("merged result holds %d teams", len(merged))
			}
		})
	}
}

// TestStaticTeams_CaptureLogIsBounded makes sure a hostile identity
// source cannot flood the log through the invalid-name warning.
func TestStaticTeams_CaptureLogIsBounded(t *testing.T) {
	log, hook := test.NewNullLogger()
	derived := make([]string, 0, 500)
	for range 500 {
		derived = append(derived, strings.Repeat("X ", 2000))
	}

	NewStaticTeams(nil).Capture(log, derived)

	entries := hook.AllEntries()
	if len(entries) != 1 {
		t.Fatalf("log entries: got %d, want 1", len(entries))
	}
	line, err := entries[0].String()
	if err != nil {
		t.Fatalf("format: %v", err)
	}
	if len(line) > 4096 {
		t.Errorf("warning is %d bytes long", len(line))
	}
}

func TestStaticTeams_InvalidConfig(t *testing.T) {
	log := logrus.New()
	log.SetOutput(io.Discard)

	tests := []struct {
		name   string
		static []string
	}{
		{"invalid name", []string{"panda", "not valid"}},
		{"too many", numbered("t", auth.MaxTeams+1)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := NewStaticTeams(tc.static)
			if s.Err() == nil {
				t.Fatal("expected a configuration error")
			}
			// A provider that ignored Err still hands out nothing from the
			// rejected list.
			if got := s.With(nil); got != nil {
				t.Errorf("rejected config yields teams: %v", got)
			}
			if got := s.Capture(log, []string{"geth"}); !slices.Equal(got, []string{"geth"}) {
				t.Errorf("capture: %v", got)
			}
		})
	}
}
