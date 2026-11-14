// Package oidctest provides a minimal in-process OpenID Connect identity
// provider for tests: discovery document, JWKS, an authorize endpoint
// that immediately redirects back with a code, and a token endpoint that
// answers with a signed id_token for the configured user.
package oidctest

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const keyID = "oidctest"

// User is the identity the IdP asserts in the next id_token it issues.
type User struct {
	Subject string
	Email   string
	// Groups becomes the id_token `groups` claim.
	Groups []string
	// Claims are further id_token claims, by name. They cannot replace
	// the claims the IdP sets itself (iss, aud, sub, nonce, iat, exp).
	//
	// The IdP marks the email as verified ("email_verified": true)
	// unless Claims says otherwise: set "email_verified" to another
	// value, or to nil to leave the claim out.
	Claims map[string]any
}

// IdP is a fake OpenID Connect provider backed by an httptest.Server.
type IdP struct {
	// URL is the issuer URL (also the base of every endpoint).
	URL string

	server *httptest.Server
	key    *rsa.PrivateKey

	mu     sync.Mutex
	user   User
	nonces map[string]string // authorization code → nonce
	seq    int
}

// New starts a fake IdP that asserts user. It is shut down when the test
// ends.
func New(t *testing.T, user User) *IdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("oidctest: generate key: %v", err)
	}
	idp := &IdP{key: key, user: user, nonces: make(map[string]string, 4)}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", idp.handleDiscovery)
	mux.HandleFunc("/keys", idp.handleKeys)
	mux.HandleFunc("/auth", idp.handleAuthorize)
	mux.HandleFunc("/token", idp.handleToken)
	idp.server = httptest.NewServer(mux)
	idp.URL = idp.server.URL
	t.Cleanup(idp.server.Close)
	return idp
}

// SetUser changes the identity asserted by subsequently issued id_tokens.
func (i *IdP) SetUser(user User) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.user = user
}

// Authorize plays the browser's visit to the authorize URL the relying
// party redirected to and returns the callback query (code + state) the
// IdP sends the browser back with.
func (i *IdP) Authorize(t *testing.T, authorizeURL string) url.Values {
	t.Helper()
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(authorizeURL)
	if err != nil {
		t.Fatalf("oidctest: authorize: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("oidctest: authorize status %d", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("oidctest: authorize redirect: %v", err)
	}
	return loc.Query()
}

func (i *IdP) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]string{
		"issuer":                 i.URL,
		"authorization_endpoint": i.URL + "/auth",
		"token_endpoint":         i.URL + "/token",
		"jwks_uri":               i.URL + "/keys",
	})
}

func (i *IdP) handleKeys(w http.ResponseWriter, _ *http.Request) {
	pub := &i.key.PublicKey
	writeJSON(w, map[string]any{"keys": []map[string]string{{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": keyID,
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}})
}

func (i *IdP) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	redirect, err := url.Parse(q.Get("redirect_uri"))
	if err != nil || q.Get("redirect_uri") == "" {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}

	i.mu.Lock()
	i.seq++
	code := "code-" + base64.RawURLEncoding.EncodeToString(big.NewInt(int64(i.seq)).Bytes())
	i.nonces[code] = q.Get("nonce")
	i.mu.Unlock()

	back := url.Values{}
	back.Set("code", code)
	back.Set("state", q.Get("state"))
	redirect.RawQuery = back.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

func (i *IdP) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	i.mu.Lock()
	nonce, known := i.nonces[r.Form.Get("code")]
	delete(i.nonces, r.Form.Get("code"))
	user := i.user
	i.mu.Unlock()

	if !known {
		writeJSON(w, map[string]string{"error": "invalid_grant", "error_description": "unknown code"})
		return
	}

	now := time.Now()
	claims := jwt.MapClaims{}
	for name, value := range user.Claims {
		claims[name] = value
	}
	claims["iss"] = i.URL
	claims["aud"] = r.Form.Get("client_id")
	claims["sub"] = user.Subject
	claims["nonce"] = nonce
	claims["iat"] = now.Unix()
	claims["exp"] = now.Add(5 * time.Minute).Unix()
	if user.Email != "" {
		claims["email"] = user.Email
		switch value, set := user.Claims["email_verified"]; {
		case !set:
			claims["email_verified"] = true
		case value == nil:
			delete(claims, "email_verified")
		}
	}
	if user.Groups != nil {
		claims["groups"] = user.Groups
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = keyID
	signed, err := tok.SignedString(i.key)
	if err != nil {
		http.Error(w, "sign", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"id_token": signed, "token_type": "bearer", "access_token": "unused"})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
