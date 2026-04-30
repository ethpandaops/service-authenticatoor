package issuer

import (
	"encoding/json"
	"testing"
)

func TestRSAKeyRoundtrip(t *testing.T) {
	key, err := GenerateRSAKey()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	pem, err := MarshalRSAPrivateKeyPEM(key)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	parsed, err := ParseRSAPrivateKeyPEM(pem)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if key.N.Cmp(parsed.N) != 0 || key.E != parsed.E {
		t.Errorf("roundtrip mismatch")
	}
}

func TestDeriveKeyIDStable(t *testing.T) {
	key, err := GenerateRSAKey()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	a := DeriveKeyID(&key.PublicKey)
	b := DeriveKeyID(&key.PublicKey)
	if a != b {
		t.Errorf("kid not stable: %q vs %q", a, b)
	}
	if a == "" {
		t.Error("kid empty")
	}
}

func TestDeriveKeyIDDistinct(t *testing.T) {
	k1, err := GenerateRSAKey()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	k2, err := GenerateRSAKey()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if DeriveKeyID(&k1.PublicKey) == DeriveKeyID(&k2.PublicKey) {
		t.Error("two distinct keys produced the same kid")
	}
}

func TestPublicKeyToJWK(t *testing.T) {
	key, err := GenerateRSAKey()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	jwk := PublicKeyToJWK(&key.PublicKey, "")

	if jwk.Kty != "RSA" || jwk.Alg != "RS256" || jwk.Use != "sig" {
		t.Errorf("wrong header fields: %+v", jwk)
	}
	if jwk.Kid == "" || jwk.N == "" || jwk.E == "" {
		t.Errorf("missing JWK fields: %+v", jwk)
	}

	if _, err := json.Marshal(JWKS{Keys: []JWK{jwk}}); err != nil {
		t.Errorf("marshal: %v", err)
	}
}

func TestPublicKeyToJWK_ExplicitKid(t *testing.T) {
	key, err := GenerateRSAKey()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	jwk := PublicKeyToJWK(&key.PublicKey, "explicit-kid")
	if jwk.Kid != "explicit-kid" {
		t.Errorf("explicit kid not honored: got %q", jwk.Kid)
	}
}
