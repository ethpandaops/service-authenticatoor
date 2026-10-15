package cfaccess

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"
)

// newTestVerifier builds a JWKSVerifier over an in-memory JWKS holding
// the public half of key.
func newTestVerifier(t *testing.T, key *rsa.PrivateKey) *JWKSVerifier {
	t.Helper()
	b64 := base64.RawURLEncoding.EncodeToString
	jwks, err := json.Marshal(map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig",
		"n": b64(key.N.Bytes()),
		"e": b64(big.NewInt(int64(key.E)).Bytes()),
	}}})
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	kf, err := keyfunc.NewJWKSetJSON(jwks)
	if err != nil {
		t.Fatalf("keyfunc: %v", err)
	}
	return &JWKSVerifier{
		cfg: Config{TeamDomain: "team.example", Now: time.Now},
		kf:  kf,
		log: logrus.New(),
	}
}

func signMeta(t *testing.T, key *rsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "k1"
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

func TestVerifyMeta(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	v := newTestVerifier(t, key)
	exp := time.Now().Add(5 * time.Minute).Unix()
	valid := jwt.MapClaims{"type": "meta", "aud": "aud-1", "hostname": "auth.example", "exp": exp}

	claims, err := v.VerifyMeta(context.Background(), signMeta(t, key, valid))
	if err != nil {
		t.Fatalf("valid meta: %v", err)
	}
	if claims.Hostname != "auth.example" || claims.Audience[0] != "aud-1" {
		t.Errorf("claims: %+v", claims)
	}

	tests := []struct {
		name   string
		key    *rsa.PrivateKey
		claims jwt.MapClaims
	}{
		{"foreign key", other, valid},
		{"wrong type", key, jwt.MapClaims{"type": "app", "aud": "aud-1", "hostname": "auth.example", "exp": exp}},
		{"expired", key, jwt.MapClaims{"type": "meta", "aud": "aud-1", "hostname": "auth.example",
			"exp": time.Now().Add(-time.Minute).Unix()}},
		{"no audience", key, jwt.MapClaims{"type": "meta", "hostname": "auth.example", "exp": exp}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := v.VerifyMeta(context.Background(), signMeta(t, tc.key, tc.claims)); err == nil {
				t.Error("expected error")
			}
		})
	}
}
