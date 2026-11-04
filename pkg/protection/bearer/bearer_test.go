package bearer

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"

	"github.com/ethpandaops/service-authenticatoor/pkg/issuer"
	"github.com/ethpandaops/service-authenticatoor/pkg/protection"
)

const testAudience = "devnet-authenticatoor"

// fakeIdP serves an OIDC discovery document and JWKS. The advertised
// issuer carries a trailing slash, as Authentik's per-application issuers do.
type fakeIdP struct {
	srv     *httptest.Server
	key     *rsa.PrivateKey
	issuer  string
	jwksURI string // overrides the advertised jwks_uri when set
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, err := issuer.GenerateRSAKey()
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	idp := &fakeIdP{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/app/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		jwks := idp.jwksURI
		if jwks == "" {
			jwks = idp.srv.URL + "/app/jwks/"
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": idp.issuer, "jwks_uri": jwks})
	})
	mux.HandleFunc("/app/jwks/", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(issuer.JWKS{Keys: []issuer.JWK{issuer.PublicKeyToJWK(&key.PublicKey, "k1")}})
	})
	idp.srv = httptest.NewServer(mux)
	idp.issuer = idp.srv.URL + "/app/"
	t.Cleanup(idp.srv.Close)
	return idp
}

func (idp *fakeIdP) sign(t *testing.T, c jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	tok.Header["kid"] = "k1"
	s, err := tok.SignedString(idp.key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

func (idp *fakeIdP) claims(mutate func(jwt.MapClaims)) jwt.MapClaims {
	c := jwt.MapClaims{
		"iss":    idp.issuer,
		"aud":    testAudience,
		"sub":    "alice",
		"email":  "alice@example.com",
		"groups": []string{"ethpandaops", "ethpandaops:Core"},
		"exp":    time.Now().Add(5 * time.Minute).Unix(),
	}
	if mutate != nil {
		mutate(c)
	}
	return c
}

func startProvider(t *testing.T, cfg Config) *Provider {
	t.Helper()
	log := logrus.New()
	log.SetOutput(io.Discard)
	p := New(log, cfg)
	if err := p.Start(t.Context()); err != nil {
		t.Fatalf("start: %v", err)
	}
	return p
}

func requestWith(authz string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/bearer/token", nil)
	if authz != "" {
		r.Header.Set("Authorization", authz)
	}
	return r
}

func TestAuthenticate(t *testing.T) {
	idp := newFakeIdP(t)
	p := startProvider(t, Config{
		IssuerURL:     strings.TrimSuffix(idp.issuer, "/"),
		Audiences:     []string{"other", testAudience},
		AllowedGroups: []string{"ethpandaops:Core"},
	})

	otherKey, err := issuer.GenerateRSAKey()
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	foreign := jwt.NewWithClaims(jwt.SigningMethodRS256, idp.claims(nil))
	foreign.Header["kid"] = "k1"
	foreignSigned, err := foreign.SignedString(otherKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	hmacSigned, err := jwt.NewWithClaims(jwt.SigningMethodHS256, idp.claims(nil)).SignedString([]byte("secret"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	tests := []struct {
		name        string
		authz       string
		wantSubject string
		wantStatus  int
	}{
		{"valid token", "Bearer " + idp.sign(t, idp.claims(nil)), "alice@example.com", 0},
		{"scheme is case-insensitive", "bearer " + idp.sign(t, idp.claims(nil)), "alice@example.com", 0},
		{"subject falls back to preferred_username", "Bearer " + idp.sign(t, idp.claims(func(c jwt.MapClaims) {
			delete(c, "email")
			c["preferred_username"] = "alice-gh"
		})), "alice-gh", 0},
		{"subject falls back to sub", "Bearer " + idp.sign(t, idp.claims(func(c jwt.MapClaims) {
			delete(c, "email")
		})), "alice", 0},
		{"missing header", "", "", http.StatusUnauthorized},
		{"basic credentials are not ours", "Basic YWxpY2U6cHc=", "", http.StatusUnauthorized},
		{"wrong audience", "Bearer " + idp.sign(t, idp.claims(func(c jwt.MapClaims) {
			c["aud"] = "panda-proxy"
		})), "", http.StatusUnauthorized},
		{"wrong issuer", "Bearer " + idp.sign(t, idp.claims(func(c jwt.MapClaims) {
			c["iss"] = "https://idp.example/other/"
		})), "", http.StatusUnauthorized},
		{"expired", "Bearer " + idp.sign(t, idp.claims(func(c jwt.MapClaims) {
			c["exp"] = time.Now().Add(-time.Minute).Unix()
		})), "", http.StatusUnauthorized},
		{"no expiry", "Bearer " + idp.sign(t, idp.claims(func(c jwt.MapClaims) {
			delete(c, "exp")
		})), "", http.StatusUnauthorized},
		{"no subject", "Bearer " + idp.sign(t, idp.claims(func(c jwt.MapClaims) {
			delete(c, "sub")
		})), "", http.StatusUnauthorized},
		{"signed by another key", "Bearer " + foreignSigned, "", http.StatusUnauthorized},
		{"hmac algorithm", "Bearer " + hmacSigned, "", http.StatusUnauthorized},
		{"group not allowed", "Bearer " + idp.sign(t, idp.claims(func(c jwt.MapClaims) {
			c["groups"] = []string{"ethpandaops"}
		})), "", http.StatusForbidden},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for _, authenticate := range []func(context.Context, *http.Request) (protection.Outcome, error){
				p.Authenticate, p.AuthenticateAmbient,
			} {
				out, err := authenticate(t.Context(), requestWith(tc.authz))
				if err != nil {
					t.Fatalf("authenticate: %v", err)
				}
				if tc.wantSubject != "" {
					if out.Identity == nil || out.Identity.Subject != tc.wantSubject {
						t.Fatalf("identity: got %+v, want subject %q (status %d)", out.Identity, tc.wantSubject, out.Status)
					}
					continue
				}
				if out.Identity != nil {
					t.Fatalf("authenticated as %q, want status %d", out.Identity.Subject, tc.wantStatus)
				}
				if out.Status != tc.wantStatus {
					t.Fatalf("status: got %d, want %d", out.Status, tc.wantStatus)
				}
				if c := out.Challenge.Get("WWW-Authenticate"); !strings.HasPrefix(c, "Bearer ") {
					t.Fatalf("challenge: got %q", c)
				}
			}
		})
	}
}

func TestAuthenticate_EmptyAllowListTrustsIssuer(t *testing.T) {
	idp := newFakeIdP(t)
	p := startProvider(t, Config{IssuerURL: idp.issuer, Audiences: []string{testAudience}})

	out, err := p.Authenticate(t.Context(), requestWith("Bearer "+idp.sign(t, idp.claims(func(c jwt.MapClaims) {
		delete(c, "groups")
	}))))
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if out.Identity == nil || out.Identity.Email != "alice@example.com" {
		t.Fatalf("identity: got %+v", out.Identity)
	}
}

func TestStart_RejectsIssuerMismatch(t *testing.T) {
	idp := newFakeIdP(t)
	log := logrus.New()
	log.SetOutput(io.Discard)

	idp.issuer = "https://elsewhere.example/app/"
	p := New(log, Config{IssuerURL: idp.srv.URL + "/app/", Audiences: []string{testAudience}})
	if err := p.Start(t.Context()); err == nil || !strings.Contains(err.Error(), "issuer mismatch") {
		t.Fatalf("start: got %v, want issuer mismatch", err)
	}
}

func TestStart_RejectsPlainHTTPJWKS(t *testing.T) {
	idp := newFakeIdP(t)
	idp.jwksURI = "http://idp.example/app/jwks/"
	log := logrus.New()
	log.SetOutput(io.Discard)

	p := New(log, Config{IssuerURL: idp.issuer, Audiences: []string{testAudience}})
	if err := p.Start(t.Context()); err == nil || !strings.Contains(err.Error(), "must use https") {
		t.Fatalf("start: got %v, want https requirement on jwks_uri", err)
	}
}

func TestProviderHasNoInteractiveLogin(t *testing.T) {
	p := New(logrus.New(), Config{})
	if got := p.LoginURL("/auth/token"); got != "" {
		t.Fatalf("LoginURL: got %q, want empty", got)
	}
}
