package basic

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
)

// htpasswdSHA returns a one-entry htpasswd body using the {SHA} format
// that go-htpasswd parses without external tooling.
func htpasswdSHA(user, pass string) string {
	sum := sha1.Sum([]byte(pass))
	return user + ":{SHA}" + base64.StdEncoding.EncodeToString(sum[:]) + "\n"
}

func writeHtpasswd(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "htpasswd")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

func newTestProvider(t *testing.T, htpasswdBody string) *Provider {
	t.Helper()
	log := logrus.New()
	log.SetOutput(io.Discard)
	p := New(log, Config{
		HtpasswdFile: writeHtpasswd(t, htpasswdBody),
		Realm:        "test-realm",
	})
	if err := p.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	return p
}

// alice / hunter2 in {SHA} form.
var aliceHtpasswd = htpasswdSHA("alice", "hunter2")

func TestBasic_AcceptsCorrectCredentials(t *testing.T) {
	p := newTestProvider(t, aliceHtpasswd)

	r := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
	r.SetBasicAuth("alice", "hunter2")
	out, err := p.Authenticate(context.Background(), r)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	if out.Identity == nil {
		t.Fatalf("expected identity, got status %d", out.Status)
	}
	if out.Identity.Subject != "alice" {
		t.Errorf("subject: %q", out.Identity.Subject)
	}
}

func TestBasic_RejectsWrongPassword(t *testing.T) {
	p := newTestProvider(t, aliceHtpasswd)

	r := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
	r.SetBasicAuth("alice", "wrong")
	out, err := p.Authenticate(context.Background(), r)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	if out.Identity != nil {
		t.Fatal("expected no identity")
	}
	if out.Status != http.StatusUnauthorized {
		t.Errorf("status: got %d", out.Status)
	}
	chall := out.Challenge.Get("WWW-Authenticate")
	if !strings.Contains(chall, `realm="test-realm"`) {
		t.Errorf("challenge: %q", chall)
	}
}

func TestBasic_RejectsUnknownUser(t *testing.T) {
	p := newTestProvider(t, aliceHtpasswd)

	r := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
	r.SetBasicAuth("bob", "anything")
	out, err := p.Authenticate(context.Background(), r)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	if out.Identity != nil {
		t.Fatal("expected no identity for unknown user")
	}
}

func TestBasic_RejectsMissingHeader(t *testing.T) {
	p := newTestProvider(t, aliceHtpasswd)

	r := httptest.NewRequest(http.MethodGet, "/auth/token", nil)
	out, err := p.Authenticate(context.Background(), r)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	if out.Identity != nil {
		t.Fatal("expected no identity")
	}
	if out.Status != http.StatusUnauthorized {
		t.Errorf("status: got %d", out.Status)
	}
}

func TestBasic_Start_RejectsMissingFile(t *testing.T) {
	log := logrus.New()
	log.SetOutput(io.Discard)
	p := New(log, Config{HtpasswdFile: ""})
	if err := p.Start(context.Background()); err == nil {
		t.Error("expected error for empty HtpasswdFile")
	}
}
