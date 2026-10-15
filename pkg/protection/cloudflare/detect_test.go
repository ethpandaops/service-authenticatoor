package cloudflare

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/ethpandaops/service-authenticatoor/pkg/cfaccess"
)

const testTeam = "team.example"

// stubMetaVerifier returns fixed meta claims without a real JWKS.
type stubMetaVerifier struct {
	hostname string
	aud      string
	err      error
}

func (s stubMetaVerifier) VerifyMeta(_ context.Context, _ string) (*cfaccess.MetaClaims, error) {
	if s.err != nil {
		return nil, s.err
	}
	c := &cfaccess.MetaClaims{Type: "meta", Hostname: s.hostname}
	c.Audience = []string{s.aud}
	return c, nil
}

// accessLoginRedirect builds a Cloudflare Access login redirect URL.
func accessLoginRedirect(team, host, meta string) string {
	v := url.Values{}
	v.Set("kid", "aud-from-kid")
	if meta != "" {
		v.Set("meta", meta)
	}
	return "https://" + team + cfLoginPathPrefix + host + "?" + v.Encode()
}

// newEdge stands in for the CF Access edge in front of the public URL:
// it answers every request with the given status and Location.
func newEdge(t *testing.T, status int, location string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if location != "" {
			w.Header().Set("Location", location)
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newDetectingProvider(t *testing.T, publicURL string, meta cfaccess.MetaVerifier) *Provider {
	t.Helper()
	p := newTestProvider(t, Config{VerifyJWT: true, TeamDomain: testTeam, PublicURL: publicURL})
	p.SetMetaVerifier(meta)
	return p
}

func TestDetectAud(t *testing.T) {
	okMeta := stubMetaVerifier{hostname: "127.0.0.1", aud: "aud-1"}
	tests := []struct {
		name     string
		status   int
		location string
		meta     cfaccess.MetaVerifier
		want     string
	}{
		{"cf login redirect", http.StatusFound,
			accessLoginRedirect(testTeam, "127.0.0.1", "tok"), okMeta, "aud-1"},
		{"not covered by edge", http.StatusForbidden, "", okMeta, ""},
		{"redirect to other host", http.StatusFound,
			accessLoginRedirect("evil.example", "127.0.0.1", "tok"), okMeta, ""},
		{"redirect to other path", http.StatusFound,
			"https://" + testTeam + "/somewhere?meta=tok", okMeta, ""},
		{"missing meta token", http.StatusFound,
			accessLoginRedirect(testTeam, "127.0.0.1", ""), okMeta, ""},
		{"meta token for other host", http.StatusFound,
			accessLoginRedirect(testTeam, "127.0.0.1", "tok"),
			stubMetaVerifier{hostname: "other.example", aud: "aud-1"}, ""},
		{"meta token invalid", http.StatusFound,
			accessLoginRedirect(testTeam, "127.0.0.1", "tok"),
			stubMetaVerifier{err: errors.New("bad signature")}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			edge := newEdge(t, tc.status, tc.location)
			p := newDetectingProvider(t, edge.URL, tc.meta)

			got, err := p.detectAud(context.Background())
			if tc.want == "" {
				if err == nil {
					t.Fatalf("expected error, got aud %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("detect: %v", err)
			}
			if got != tc.want {
				t.Errorf("aud: got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDetecting_OnlyWithoutConfiguredAudTag(t *testing.T) {
	p := newTestProvider(t, Config{VerifyJWT: true, TeamDomain: testTeam,
		AudTag: "configured", PublicURL: "https://auth.example"})
	if p.detecting() {
		t.Error("configured audTag must disable detection")
	}
	p = newTestProvider(t, Config{VerifyJWT: false, PublicURL: "https://auth.example"})
	if p.detecting() {
		t.Error("verifyJWT=false must disable detection")
	}
}

// TestDetectedAud_EnforcedOnOwnPrefixOnly checks that a detected tag
// gates the login entry / token alias, while /auth/* (Authenticate)
// keeps accepting any team assertion.
func TestDetectedAud_EnforcedOnOwnPrefixOnly(t *testing.T) {
	p := newDetectingProvider(t, "https://auth.example", stubMetaVerifier{})
	aud := "aud-1"
	p.detectedAud.Store(&aud)

	assertion := func() *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set(cfaccess.DefaultJWTHeader, "non-empty")
		return r
	}

	p.SetVerifier(stubVerifier{email: "alice@example.com", aud: []string{"aud-1"}})
	out, _ := p.AuthenticateAmbient(context.Background(), assertion())
	if out.Identity == nil {
		t.Fatalf("matching aud on own prefix: got %+v", out)
	}

	p.SetVerifier(stubVerifier{email: "alice@example.com", aud: []string{"other-app"}})
	out, _ = p.AuthenticateAmbient(context.Background(), assertion())
	if out.Identity != nil || out.Status != http.StatusUnauthorized {
		t.Errorf("foreign aud on own prefix: got %+v, want 401", out)
	}

	out, _ = p.Authenticate(context.Background(), assertion())
	if out.Identity == nil {
		t.Errorf("foreign aud on /auth/*: got %+v, want identity", out)
	}
}

func TestLogin_UnavailableUntilAudDetected(t *testing.T) {
	edge := newEdge(t, http.StatusForbidden, "")
	p := newDetectingProvider(t, edge.URL, stubMetaVerifier{})
	p.SetVerifier(stubVerifier{email: "alice@example.com", aud: []string{"aud-1"}})

	r := httptest.NewRequest(http.MethodGet, "/cfaccess/login?return_to=/x", nil)
	r.Header.Set(cfaccess.DefaultJWTHeader, "non-empty")
	rr := httptest.NewRecorder()
	p.handleLogin(rr, r)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status: got %d, want 503", rr.Code)
	}
	if len(rr.Result().Cookies()) != 0 {
		t.Error("no session cookie may be minted before detection")
	}
}

func TestLogin_DetectsAudOnDemand(t *testing.T) {
	edge := newEdge(t, http.StatusFound, accessLoginRedirect(testTeam, "127.0.0.1", "tok"))
	p := newDetectingProvider(t, edge.URL, stubMetaVerifier{hostname: "127.0.0.1", aud: "aud-1"})
	p.SetVerifier(stubVerifier{email: "alice@example.com", aud: []string{"aud-1"}})

	r := httptest.NewRequest(http.MethodGet, "/cfaccess/login?return_to=/x", nil)
	r.Header.Set(cfaccess.DefaultJWTHeader, "non-empty")
	rr := httptest.NewRecorder()
	p.handleLogin(rr, r)

	if rr.Code != http.StatusFound {
		t.Fatalf("status: got %d, want 302 (body %q)", rr.Code, rr.Body.String())
	}
	if got := p.detectedAudTag(); got != "aud-1" {
		t.Errorf("detected aud: got %q", got)
	}
}
