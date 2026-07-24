package protection

import "testing"

func TestSafeReturnTo(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", "/"},
		{"/", "/"},
		{"/auth/login", "/auth/login"},
		{"/auth/login?x=1", "/auth/login?x=1"},
		{"//evil.example/", "/"},
		{`/\evil.example/`, "/"},
		{"https://evil.example/", "/"},
		{"javascript:alert(1)", "/"},
		{"./relative", "/"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := SafeReturnTo(tc.in); got != tc.want {
				t.Errorf("SafeReturnTo(%q): got %q want %q", tc.in, got, tc.want)
			}
		})
	}
}
