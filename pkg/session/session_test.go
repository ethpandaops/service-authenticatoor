package session

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/ethpandaops/service-authenticatoor/pkg/auth"
	"github.com/ethpandaops/service-authenticatoor/pkg/protection"
)

var (
	testDoor   = NewDoor("oidc", "https://idp.example", "client")
	testSecret = []byte("0123456789abcdef0123456789abcdef")
	testNow    = time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)
)

func TestSession_RoundTrip(t *testing.T) {
	many := make([]string, 0, 40)
	for i := range 40 {
		many = append(many, fmt.Sprintf("team-%02d", i))
	}

	tests := []struct {
		name      string
		in        Payload
		wantTeams []string
	}{
		{"no teams", Payload{Subject: "alice", Email: "alice@example.com"}, nil},
		{"no email", Payload{Subject: "svc-token-id"}, nil},
		{
			"teams",
			Payload{Subject: "alice", Email: "alice@example.com", Teams: []string{"geth", "lighthouse"}},
			[]string{"geth", "lighthouse"},
		},
		{
			"teams are stored in normal form",
			Payload{Subject: "alice", Teams: []string{"Panda", "geth", "panda", "not valid"}},
			[]string{"geth", "panda"},
		},
		{"teams are capped", Payload{Subject: "alice", Teams: many}, many[:auth.MaxTeams]},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			signed, err := Sign(testSecret, testDoor, tc.in, time.Hour, testNow)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			got, err := Parse(testSecret, testDoor, signed, testNow.Add(time.Minute))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if got.Subject != tc.in.Subject || got.Email != tc.in.Email {
				t.Errorf("identity: got %q/%q, want %q/%q", got.Subject, got.Email, tc.in.Subject, tc.in.Email)
			}
			if !slices.Equal(got.Teams, tc.wantTeams) {
				t.Errorf("teams: got %v, want %v", got.Teams, tc.wantTeams)
			}
		})
	}
}

// TestSession_OldFormatCookie feeds Parse a cookie exactly as released
// versions signed it (sub, email, iat, exp — no door). It is rejected:
// nothing in it says which door it was opened at, so it could count at
// whatever its provider entry has become. Users log in again once
// after the upgrade.
func TestSession_OldFormatCookie(t *testing.T) {
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":   "alice",
		"email": "alice@example.com",
		"iat":   testNow.Unix(),
		"exp":   testNow.Add(time.Hour).Unix(),
	})
	old, err := tok.SignedString(testSecret)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	for _, door := range []Door{testDoor, NewDoor("basic"), NewDoor("cloudflare", "x", "true"), NewDoor("github", "")} {
		got, err := Parse(testSecret, door, old, testNow.Add(time.Minute))
		if err == nil || !strings.Contains(err.Error(), "without a door") {
			t.Errorf("door %s: a cookie without a door was accepted: %+v (err %v)", door, got, err)
		}
		if got.Subject != "" || got.Email != "" || got.Teams != nil {
			t.Errorf("a rejected cookie yielded a payload: %+v", got)
		}
	}
}

// TestSession_NoTeamsKeepsOldPayload: a session without teams has no
// "teams" key; a binary rolled back to a version without teams reads
// it (the door is an extra claim such a version ignores).
func TestSession_NoTeamsKeepsOldPayload(t *testing.T) {
	signed, err := Sign(testSecret, testDoor, Payload{Subject: "alice", Email: "alice@example.com"}, time.Hour, testNow)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(signed, claims); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, present := claims["teams"]; present {
		t.Errorf("payload carries a teams key without teams: %v", claims)
	}
}

func TestSession_RejectsUnverifiableCookies(t *testing.T) {
	valid, err := Sign(testSecret, testDoor, Payload{Subject: "alice", Teams: []string{"geth"}}, time.Hour, testNow)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	parts := strings.Split(valid, ".")

	// A forged payload granting "panda", glued onto the genuine signature.
	forgedTok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":   "alice",
		"teams": []string{"panda"},
		"iat":   testNow.Unix(),
		"exp":   testNow.Add(time.Hour).Unix(),
	})
	forgedSigned, err := forgedTok.SignedString([]byte("some-other-secret-of-enough-size"))
	if err != nil {
		t.Fatalf("sign forged: %v", err)
	}
	forgedParts := strings.Split(forgedSigned, ".")

	unsigned := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"sub":   "alice",
		"teams": []string{"panda"},
		"exp":   testNow.Add(time.Hour).Unix(),
	})
	algNone, err := unsigned.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign none: %v", err)
	}

	tests := []struct {
		name string
		raw  string
		now  time.Time
	}{
		{"empty", "", testNow},
		{"garbage", "not-a-jwt", testNow},
		{"payload swapped under the genuine signature", parts[0] + "." + forgedParts[1] + "." + parts[2], testNow},
		{"signed with another key", forgedSigned, testNow},
		{"alg none", algNone, testNow},
		{"signature stripped", parts[0] + "." + parts[1] + ".", testNow},
		{"expired", valid, testNow.Add(2 * time.Hour)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Parse(testSecret, testDoor, tc.raw, tc.now)
			if err == nil {
				t.Fatal("expected an error")
			}
			if got.Subject != "" || got.Email != "" || got.Teams != nil {
				t.Errorf("a rejected cookie must yield no payload, got %+v", got)
			}
		})
	}
}

// TestSession_WorstCaseCookieFitsBrowserLimit pins the size reasoning
// behind auth.MaxTeams: a session holding the maximum number of
// maximum-length team names, set the way the providers set it, stays
// under the 4096-byte per-cookie limit browsers enforce.
func TestSession_WorstCaseCookieFitsBrowserLimit(t *testing.T) {
	teams := make([]string, 0, auth.MaxTeams)
	for i := range auth.MaxTeams {
		teams = append(teams, fmt.Sprintf("%02d", i)+strings.Repeat("x", 61)) // 63 chars each
	}
	email := strings.Repeat("a", 88) + "@example.com" // 100 chars

	signed, err := Sign(testSecret, testDoor, Payload{Subject: email, Email: email, Teams: teams}, 12*time.Hour, testNow)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	got, err := Parse(testSecret, testDoor, signed, testNow)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got.Teams) != auth.MaxTeams {
		t.Fatalf("teams: got %d, want %d", len(got.Teams), auth.MaxTeams)
	}

	cookie := &http.Cookie{
		Name:     "authenticatoor_a-provider-name-of-32-characters_session",
		Value:    signed,
		Path:     "/",
		MaxAge:   43200,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	}
	if size := len(cookie.String()); size >= 4096 {
		t.Errorf("worst-case session cookie is %d bytes, over the 4096-byte browser limit", size)
	} else {
		t.Logf("worst-case session cookie: %d bytes", size)
	}
}

// TestSession_Door: a session counts only for the door it was opened
// at. The signing key is the same in every case here — as it is when a
// provider entry keeps its name while its type or identity source
// changes.
func TestSession_Door(t *testing.T) {
	oidcDoor := NewDoor("oidc", "https://idp.example", "client")
	payload := Payload{Subject: "alice", Email: "alice@example.com", Teams: []string{"lighthouse", "panda"}}
	signed, err := Sign(testSecret, oidcDoor, payload, time.Hour, testNow)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	tests := []struct {
		name    string
		door    Door
		wantErr bool
	}{
		{"the same door", NewDoor("oidc", "https://idp.example", "client"), false},
		{"type changed to basic", NewDoor("basic"), true},
		{"type changed to cloudflare", NewDoor("cloudflare", "team.cloudflareaccess.com", "true"), true},
		{"type changed to github", NewDoor("github", "https://api.github.com"), true},
		{"the same type, another IdP", NewDoor("oidc", "https://other-idp.example", "client"), true},
		{"the same IdP, another client", NewDoor("oidc", "https://idp.example", "other-client"), true},
		{"details are not concatenated", NewDoor("oidc", "https://idp.exampleclient"), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Parse(testSecret, tc.door, signed, testNow)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("a session of another door was accepted: %+v", got)
				}
				if got.Subject != "" || got.Teams != nil {
					t.Errorf("a rejected session yielded a payload: %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if !slices.Equal(got.Teams, payload.Teams) {
				t.Errorf("teams: %v", got.Teams)
			}
		})
	}
}

// TestSession_ZeroDoorIsUnusable: the zero Door is not a door. Nothing
// can be signed for it and nothing parses under it — not a doorless
// cookie, not one signed for a real door — so "no door" can never mean
// "any door".
func TestSession_ZeroDoorIsUnusable(t *testing.T) {
	var zero Door
	if NewDoor("") != zero || NewDoor("", "detail") != zero {
		t.Error("NewDoor with an empty kind must give the zero Door")
	}
	if NewDoor("basic") == zero {
		t.Error("a real door equals the zero Door")
	}

	if signed, err := Sign(testSecret, zero, Payload{Subject: "alice"}, time.Hour, testNow); err == nil {
		t.Errorf("Sign with the zero Door minted %q", signed)
	}

	real, err := Sign(testSecret, testDoor, Payload{Subject: "alice", Teams: []string{"panda"}}, time.Hour, testNow)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	doorless, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "alice", "teams": []string{"panda"}, "exp": testNow.Add(time.Hour).Unix(),
	}).SignedString(testSecret)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	emptyDoor, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "alice", "door": "", "teams": []string{"panda"}, "exp": testNow.Add(time.Hour).Unix(),
	}).SignedString(testSecret)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	for name, raw := range map[string]string{"a real session": real, "a doorless cookie": doorless, "a cookie with an empty door": emptyDoor} {
		if got, err := Parse(testSecret, zero, raw, testNow); err == nil {
			t.Errorf("Parse with the zero Door accepted %s: %+v", name, got)
		}
	}
	for name, raw := range map[string]string{"a doorless cookie": doorless, "a cookie with an empty door": emptyDoor} {
		if got, err := Parse(testSecret, testDoor, raw, testNow); err == nil {
			t.Errorf("Parse accepted %s: %+v", name, got)
		}
	}
}

// TestSession_StateCookieIsNotASession: the OAuth state cookie is
// signed with the same key as the session cookie. It must not parse as
// a session — and a session must not parse as a state.
func TestSession_StateCookieIsNotASession(t *testing.T) {
	state, err := SignState(testSecret, "nonce-value", "/auth/token", testNow, time.Hour)
	if err != nil {
		t.Fatalf("sign state: %v", err)
	}
	if got, err := Parse(testSecret, testDoor, state, testNow); err == nil {
		t.Errorf("a state cookie parsed as a session: %+v", got)
	}

	sess, err := Sign(testSecret, testDoor, Payload{Subject: "alice", Teams: []string{"panda"}}, time.Hour, testNow)
	if err != nil {
		t.Fatalf("sign session: %v", err)
	}
	if nonce, _, err := ParseState(testSecret, sess, testNow); err == nil {
		t.Errorf("a session cookie parsed as a state (nonce %q)", nonce)
	}
}

// TestSession_Matches: the grant-member matches captured at login make
// the round trip next to the teams, bounded, and — like teams — are not
// read from a session of another door.
func TestSession_Matches(t *testing.T) {
	payload := Payload{
		Subject: "alice",
		Teams:   []string{"lighthouse"},
		Matches: []string{"groups:panda-access", "groups:sigp:core", "groups:panda-access", ""},
	}
	signed, err := Sign(testSecret, testDoor, payload, time.Hour, testNow)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	got, err := Parse(testSecret, testDoor, signed, testNow)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if want := []string{"groups:panda-access", "groups:sigp:core"}; !slices.Equal(got.Matches, want) {
		t.Errorf("matches: got %v, want %v", got.Matches, want)
	}

	if other, err := Parse(testSecret, NewDoor("basic"), signed, testNow); err == nil {
		t.Errorf("a session of another door yielded %+v", other)
	}

	// A session without matches has no "match" key at all.
	plain, err := Sign(testSecret, testDoor, Payload{Subject: "alice"}, time.Hour, testNow)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(plain, claims); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, present := claims["match"]; present {
		t.Errorf("payload carries a match key without matches: %v", claims)
	}
}

// TestSession_WorstCaseWithMatchesFitsBrowserLimit: teams at their
// bound AND as many grant-member matches as an attacker-friendly IdP
// could make an identity satisfy still give a cookie under 4096 bytes.
// The count bound alone (64 matches of up to 300 bytes) could not
// guarantee that; the byte budget shared with the teams does.
func TestSession_WorstCaseWithMatchesFitsBrowserLimit(t *testing.T) {
	teams := make([]string, 0, auth.MaxTeams)
	for i := range auth.MaxTeams {
		teams = append(teams, fmt.Sprintf("%02d", i)+strings.Repeat("x", 61))
	}
	email := strings.Repeat("a", 88) + "@example.com"

	cases := map[string][]string{}
	long := make([]string, 0, protection.MaxMatches)
	short := make([]string, 0, 500)
	for i := range protection.MaxMatches {
		long = append(long, fmt.Sprintf("groups:%02d", i)+strings.Repeat("y", protection.MaxMatchLen-9))
	}
	for i := range 500 {
		short = append(short, fmt.Sprintf("g:%03d", i))
	}
	cases["64 matches of 300 bytes"] = long
	cases["500 short matches"] = short

	for name, matches := range cases {
		for _, withTeams := range []bool{true, false} {
			p := Payload{Subject: email, Email: email, Matches: matches}
			if withTeams {
				p.Teams = teams
			}
			signed, err := Sign(testSecret, testDoor, p, 12*time.Hour, testNow)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			got, err := Parse(testSecret, testDoor, signed, testNow)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if withTeams && len(got.Teams) != auth.MaxTeams {
				t.Errorf("%s: teams were cut to make room: %d", name, len(got.Teams))
			}
			if len(got.Matches) > protection.MaxMatches {
				t.Errorf("%s: %d matches", name, len(got.Matches))
			}
			if !withTeams && len(got.Matches) == 0 {
				t.Errorf("%s: no match kept although there was room", name)
			}
			cookie := &http.Cookie{
				Name:  "authenticatoor_a-provider-name-of-32-characters_session",
				Value: signed, Path: "/", MaxAge: 43200, HttpOnly: true, Secure: true, SameSite: http.SameSiteNoneMode,
			}
			if size := len(cookie.String()); size >= 4096 {
				t.Errorf("%s (teams: %t): cookie is %d bytes", name, withTeams, size)
			} else {
				t.Logf("%s (teams: %t): %d matches kept, cookie %d bytes", name, withTeams, len(got.Matches), size)
			}
		}
	}
}

// TestSession_DoorIsInsideTheMAC: the door is part of the signed
// payload. Rewriting it — to move a session to another door — breaks
// the signature like any other edit.
func TestSession_DoorIsInsideTheMAC(t *testing.T) {
	oidcDoor := NewDoor("oidc", "https://idp.example", "client")
	basicDoor := NewDoor("basic")
	signed, err := Sign(testSecret, oidcDoor, Payload{Subject: "alice", Teams: []string{"panda"}, Matches: []string{"groups:staff"}}, time.Hour, testNow)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	parts := strings.Split(signed, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(string(payload), `"door":"`+oidcDoor.String()+`"`) {
		t.Fatalf("the payload does not carry the door: %s", payload)
	}

	edits := map[string]string{
		"door rewritten to the basic door": strings.Replace(string(payload), oidcDoor.String(), basicDoor.String(), 1),
		"door removed":                     strings.Replace(string(payload), `,"door":"`+oidcDoor.String()+`"`, "", 1),
		"door emptied":                     strings.Replace(string(payload), oidcDoor.String(), "", 1),
		"a team added":                     strings.Replace(string(payload), `"panda"`, `"panda","root"`, 1),
		"a match added":                    strings.Replace(string(payload), `"groups:staff"`, `"groups:staff","groups:admin"`, 1),
	}
	for name, edited := range edits {
		if edited == string(payload) {
			t.Fatalf("%s: the edit changed nothing", name)
		}
		tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(edited)) + "." + parts[2]
		for _, door := range []Door{oidcDoor, basicDoor} {
			if got, err := Parse(testSecret, door, tampered, testNow); err == nil {
				t.Errorf("%s: accepted at door %s: %+v", name, door, got)
			}
		}
	}
	if _, err := Parse(testSecret, oidcDoor, signed, testNow); err != nil {
		t.Errorf("the genuine session: %v", err)
	}
}

// TestNewDoor_PartsAreNotAmbiguous: a door is made from a list of
// parts. No two different lists give the same door — not by moving a
// boundary, and not by putting the separator a naive encoding would
// use into a part.
func TestNewDoor_PartsAreNotAmbiguous(t *testing.T) {
	doors := map[string]Door{
		`("oidc", "a\x00b")`:     NewDoor("oidc", "a\x00b"),
		`("oidc", "a", "b")`:     NewDoor("oidc", "a", "b"),
		`("oidc", "ab")`:         NewDoor("oidc", "ab"),
		`("oidc", "a", "b", "")`: NewDoor("oidc", "a", "b", ""),
		`("oidc", "", "a", "b")`: NewDoor("oidc", "", "a", "b"),
		`("oidc\x00a", "b")`:     NewDoor("oidc\x00a", "b"),
		`("oidca", "b")`:         NewDoor("oidca", "b"),
		`("oidc")`:               NewDoor("oidc"),
		`("oidc", "")`:           NewDoor("oidc", ""),
		`("oidc", "\x00")`:       NewDoor("oidc", "\x00"),
		`("oidc", "", "")`:       NewDoor("oidc", "", ""),
	}
	seen := make(map[Door]string, len(doors))
	for parts, door := range doors {
		if door == (Door{}) {
			t.Errorf("NewDoor%s is the zero door", parts)
		}
		if other, dup := seen[door]; dup {
			t.Errorf("NewDoor%s and NewDoor%s are the same door", parts, other)
		}
		seen[door] = parts
	}
	again := NewDoor("oidc", "a", "b")
	if doors[`("oidc", "a", "b")`] != again {
		t.Error("the same parts give two doors")
	}
}

// TestSession_SubjectKind: whether the subject is a verified email is
// part of the signed session, and reads back as it was written. A
// session that does not say so has a raw subject.
func TestSession_SubjectKind(t *testing.T) {
	for _, isEmail := range []bool{true, false} {
		signed, err := Sign(testSecret, testDoor,
			Payload{Subject: "alice@example.org", Email: "alice@example.org", SubjectIsEmail: isEmail}, time.Hour, testNow)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		got, err := Parse(testSecret, testDoor, signed, testNow)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if got.SubjectIsEmail != isEmail {
			t.Errorf("SubjectIsEmail: wrote %t, read %t", isEmail, got.SubjectIsEmail)
		}
		claims := jwt.MapClaims{}
		if _, _, err := jwt.NewParser().ParseUnverified(signed, claims); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if _, present := claims["sem"]; present != isEmail {
			t.Errorf("payload for SubjectIsEmail=%t: %v", isEmail, claims)
		}
	}
}

// TestSession_TooLargeForACookie: a session is never larger than a
// cookie can be. Teams and matches are bounded on their own; a subject
// or an email of any length is not, so the result is checked — and a
// session that would not fit is refused instead of handed to a browser
// that drops it.
func TestSession_TooLargeForACookie(t *testing.T) {
	const name = "authenticatoor_a-provider-name-of-32-characters_session"
	teams := make([]string, 0, auth.MaxTeams)
	for i := range auth.MaxTeams {
		teams = append(teams, fmt.Sprintf("%02d", i)+strings.Repeat("x", 61))
	}
	matches := make([]string, 0, protection.MaxMatches)
	for i := range protection.MaxMatches {
		matches = append(matches, fmt.Sprintf("groups:%02d", i)+strings.Repeat("y", 40))
	}
	payload := func(subject, email int) Payload {
		p := Payload{Subject: strings.Repeat("s", subject), Teams: teams, Matches: matches, SubjectIsEmail: email > 0}
		if email > 0 {
			p.Email = strings.Repeat("e", email-12) + "@example.com"
		}
		return p
	}

	// What always fits, whatever the teams and matches: subject and
	// email of 200 bytes each. This is the statement the docs make.
	signed, err := SignCookie(name, testSecret, testDoor, payload(200, 200), 12*time.Hour, testNow)
	if err != nil {
		t.Fatalf("a session with a 200-byte subject and email must fit: %v", err)
	}
	if size := len(name) + len(signed); size > MaxCookieBytes {
		t.Fatalf("SignCookie returned a cookie of %d bytes", size)
	}
	t.Logf("teams and matches at their bounds, 200-byte subject and email: %d bytes", len(name)+len(signed))

	// Every size: either it is refused, or it fits. Never a cookie over
	// the limit.
	refused := 0
	for _, size := range []int{0, 100, 300, 500, 700, 1000, 2000, 5000, 100000} {
		for _, p := range []Payload{payload(size+1, 0), payload(size+1, size+13), {Subject: strings.Repeat("s", size+1)}} {
			signed, err := SignCookie(name, testSecret, testDoor, p, 12*time.Hour, testNow)
			switch {
			case err == nil && len(name)+len(signed) > MaxCookieBytes:
				t.Errorf("subject %d, email %d: a cookie of %d bytes was signed", len(p.Subject), len(p.Email), len(name)+len(signed))
			case err != nil && !errors.Is(err, ErrTooLarge):
				t.Errorf("subject %d, email %d: %v", len(p.Subject), len(p.Email), err)
			case err != nil:
				refused++
				if signed != "" {
					t.Error("a refused session still returned a value")
				}
			default:
				if _, perr := Parse(testSecret, testDoor, signed, testNow); perr != nil {
					t.Errorf("a signed session does not parse: %v", perr)
				}
			}
		}
	}
	if refused == 0 {
		t.Error("no session was ever refused")
	}

	// The cookie's name counts: a value that fits under a short name
	// does not fit under a long one.
	edge := Payload{Subject: strings.Repeat("s", 2850)}
	if _, err := SignCookie("s", testSecret, testDoor, edge, time.Hour, testNow); err != nil {
		t.Fatalf("under a short name: %v", err)
	}
	if _, err := SignCookie(strings.Repeat("n", 300), testSecret, testDoor, edge, time.Hour, testNow); !errors.Is(err, ErrTooLarge) {
		t.Errorf("under a long name: %v", err)
	}
	// Sign alone refuses what no cookie name could make fit.
	if _, err := Sign(testSecret, testDoor, Payload{Subject: strings.Repeat("s", 4000)}, time.Hour, testNow); !errors.Is(err, ErrTooLarge) {
		t.Errorf("Sign with a 4000-byte subject: %v", err)
	}
	// The error names sizes, not the identity.
	_, err = SignCookie(name, testSecret, testDoor, Payload{Subject: strings.Repeat("s", 4000), Email: "secret@example.org"}, time.Hour, testNow)
	if err == nil || strings.Contains(err.Error(), "secret@example.org") || strings.Contains(err.Error(), "ssss") {
		t.Errorf("error text: %v", err)
	}
}
