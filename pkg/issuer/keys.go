package issuer

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
)

// MinRSAKeyBits is the smallest acceptable RSA key size for RS256 signing
// (per RFC 7518) and matches modern industry guidance.
const MinRSAKeyBits = 2048

// JWK is a JSON Web Key for an RSA public key. RS256 only.
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKS is a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// LoadRSAPrivateKeyPEM reads an RSA private key from a PEM file. Both
// PKCS#1 ("BEGIN RSA PRIVATE KEY") and PKCS#8 ("BEGIN PRIVATE KEY")
// encodings are accepted.
func LoadRSAPrivateKeyPEM(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key file: %w", err)
	}
	return ParseRSAPrivateKeyPEM(data)
}

// ParseRSAPrivateKeyPEM parses an RSA private key from PEM bytes.
func ParseRSAPrivateKeyPEM(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS#1 private key: %w", err)
		}
		if key.N.BitLen() < MinRSAKeyBits {
			return nil, fmt.Errorf("RSA key too small: %d bits, need at least %d", key.N.BitLen(), MinRSAKeyBits)
		}
		return key, nil
	case "PRIVATE KEY":
		anyKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS#8 private key: %w", err)
		}
		key, ok := anyKey.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS#8 key is not RSA: %T", anyKey)
		}
		if key.N.BitLen() < MinRSAKeyBits {
			return nil, fmt.Errorf("RSA key too small: %d bits, need at least %d", key.N.BitLen(), MinRSAKeyBits)
		}
		return key, nil
	default:
		return nil, fmt.Errorf("unsupported PEM block type: %s", block.Type)
	}
}

// LoadRSAPublicKeyPEM reads an RSA public key from a PEM file. Accepts
// either SPKI ("BEGIN PUBLIC KEY") or PKCS#1 ("BEGIN RSA PUBLIC KEY").
func LoadRSAPublicKeyPEM(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key file: %w", err)
	}
	return ParseRSAPublicKeyPEM(data)
}

// ParseRSAPublicKeyPEM parses an RSA public key from PEM bytes.
func ParseRSAPublicKeyPEM(data []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	switch block.Type {
	case "PUBLIC KEY":
		anyKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKIX public key: %w", err)
		}
		key, ok := anyKey.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("PKIX key is not RSA: %T", anyKey)
		}
		return key, nil
	case "RSA PUBLIC KEY":
		key, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS#1 public key: %w", err)
		}
		return key, nil
	default:
		return nil, fmt.Errorf("unsupported PEM block type: %s", block.Type)
	}
}

// MarshalRSAPrivateKeyPEM encodes a private key as PKCS#8 PEM.
func MarshalRSAPrivateKeyPEM(key *rsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal PKCS#8: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// GenerateRSAKey returns a fresh RSA-2048 keypair.
func GenerateRSAKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, MinRSAKeyBits)
}

// DeriveKeyID returns a deterministic kid for an RSA public key: the first
// 16 bytes of SHA-256 over its SPKI-DER encoding, base64-url-encoded.
func DeriveKeyID(pub *rsa.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "unknown"
	}
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}

// PublicKeyToJWK builds a JWK for an RSA public key. If kid is empty, one
// is derived via DeriveKeyID.
func PublicKeyToJWK(pub *rsa.PublicKey, kid string) JWK {
	if kid == "" {
		kid = DeriveKeyID(pub)
	}
	return JWK{
		Kty: "RSA",
		Use: "sig",
		Alg: "RS256",
		Kid: kid,
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}
