package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/dop251/goja"

	"github.com/ethpandaops/service-authenticatoor/internal/directivecases"
	"github.com/ethpandaops/service-authenticatoor/pkg/auth"
	"github.com/ethpandaops/service-authenticatoor/pkg/issuer"
)

// The tests in this file run the client libraries as they are served —
// the shared claims code included, minified or not — in a JavaScript
// interpreter, behind the little of a browser they touch.

// browserPrelude is that little: a window with a location, a document
// that hands out inert iframes, timers that only run when the test says
// so, sessionStorage, and URL / URLSearchParams as far as the clients
// use them. __hash and __stored are set by the test before it runs.
const browserPrelude = `
var window = this;
var __timers = [];
var __listeners = [];
var __frames = [];
var __posted = [];

window.location = {
  origin: 'https://app.test.example', pathname: '/', search: '', hash: __hash, href: '',
};
window.addEventListener = function (type, cb) {
  if (type === 'message') __listeners.push(cb);
};
window.removeEventListener = function (type, cb) {
  var i = __listeners.indexOf(cb);
  if (i !== -1) __listeners.splice(i, 1);
};

var history = { replaceState: function () {} };

var document = {
  body: {
    appendChild: function (el) { el.parentNode = this; },
    removeChild: function (el) { el.parentNode = null; },
  },
  addEventListener: function () {},
  createElement: function () {
    var el = {
      style: {},
      parentNode: null,
      setAttribute: function () {},
      addEventListener: function () {},
      contentWindow: { postMessage: function (msg) { __posted.push(msg); } },
    };
    __frames.push(el);
    return el;
  },
};

function setTimeout(fn, ms) {
  __timers.push({ fn: fn, ms: ms || 0 });
  return __timers.length;
}
function clearTimeout(id) {
  if (__timers[id - 1]) __timers[id - 1].fn = null;
}
// Runs the timers that are due at once (late-subscriber replays); the
// long ones (frame and request timeouts) never fire.
function __flush() {
  for (var i = 0; i < __timers.length; i++) {
    var t = __timers[i];
    if (t.fn && t.ms === 0) { var fn = t.fn; t.fn = null; fn(); }
  }
}

var sessionStorage = {
  getItem: function (k) {
    return Object.prototype.hasOwnProperty.call(__stored, k) ? __stored[k] : null;
  },
  setItem: function (k, v) { __stored[k] = String(v); },
  removeItem: function (k) { delete __stored[k]; },
};

function URL(u) {
  var m = /^(https?:\/\/[^\/?#]+)/.exec(u);
  if (!m) throw new TypeError('invalid URL');
  this.origin = m[1];
}

function URLSearchParams(s) {
  this.pairs = [];
  var parts = s ? s.split('&') : [];
  for (var i = 0; i < parts.length; i++) {
    var kv = parts[i].split('=');
    this.pairs.push([decodeURIComponent(kv[0]), decodeURIComponent(kv[1] || '')]);
  }
}
URLSearchParams.prototype.get = function (k) {
  for (var i = 0; i < this.pairs.length; i++) {
    if (this.pairs[i][0] === k) return this.pairs[i][1];
  }
  return null;
};
URLSearchParams.prototype.delete = function (k) {
  this.pairs = this.pairs.filter(function (p) { return p[0] !== k; });
};
URLSearchParams.prototype.toString = function () {
  return this.pairs.map(function (p) {
    return encodeURIComponent(p[0]) + '=' + encodeURIComponent(p[1]);
  }).join('&');
};

// Delivers a message from the shared-session frame to the v2 client.
function __deliver(data) {
  var ls = __listeners.slice();
  for (var i = 0; i < ls.length; i++) {
    ls[i]({ source: __frames[0].contentWindow, origin: 'https://auth.test.example', data: data });
  }
}
`

// jsAtob is the browser's atob: base64 in, one character per byte out.
func jsAtob(in string) (string, error) {
	in = strings.TrimRight(in, "=")

	raw, err := base64.RawStdEncoding.Strict().DecodeString(in)
	if err != nil {
		return "", errors.New("InvalidCharacterError")
	}

	chars := make([]rune, 0, len(raw))
	for _, b := range raw {
		chars = append(chars, rune(b))
	}

	return string(chars), nil
}

// clientVariants are the forms a client library is served in.
var clientVariants = []struct {
	name    string
	devMode bool
}{
	{name: "minified", devMode: false},
	{name: "source", devMode: true},
}

// servedClient returns a client library exactly as the server hands it
// out.
func servedClient(t *testing.T, version string, devMode bool) string {
	t.Helper()

	s, _, _ := newTestServer(t)
	s.cfg.DevMode = devMode

	asset, err := s.clientAsset("static/authenticatoor-v"+version+".js", "")
	if err != nil {
		t.Fatalf("load client v%s: %v", version, err)
	}

	return string(asset.code)
}

// page is one page load: a fresh interpreter with a client library in it.
type page struct {
	t  *testing.T
	vm *goja.Runtime
}

// pageOptions describe the page a client library is loaded into.
type pageOptions struct {
	// hash is location.hash, as left behind by the /auth/login redirect.
	hash string
	// stored is the initial content of sessionStorage.
	stored map[string]string
}

// loadPage runs a served client library in a new page.
func loadPage(t *testing.T, script string, opts pageOptions) *page {
	t.Helper()

	vm := goja.New()
	stored := make(map[string]any, len(opts.stored))
	for k, v := range opts.stored {
		stored[k] = v
	}

	for name, value := range map[string]any{
		"atob":     jsAtob,
		"__hash":   opts.hash,
		"__stored": stored,
	} {
		if err := vm.Set(name, value); err != nil {
			t.Fatalf("set %s: %v", name, err)
		}
	}

	p := &page{t: t, vm: vm}
	p.run(browserPrelude)
	p.run(script)
	p.run("var auth = window.ethpandaops.authenticatoor;")

	return p
}

// run executes JavaScript in the page and returns its value.
func (p *page) run(src string) goja.Value {
	p.t.Helper()

	v, err := p.vm.RunString(src)
	if err != nil {
		p.t.Fatalf("javascript: %v\n%s", err, firstLines(src, 3))
	}

	return v
}

// json evaluates an expression and returns it as JSON text.
func (p *page) json(expr string) string {
	p.t.Helper()

	return p.run("JSON.stringify(" + expr + ")").String()
}

// expect compares expressions, as JSON, with what they must be.
func (p *page) expect(want map[string]string) {
	p.t.Helper()

	for expr, w := range want {
		if got := p.json(expr); got != w {
			p.t.Errorf("%s = %s, want %s", expr, got, w)
		}
	}
}

// fn returns a function of the client's public object.
func (p *page) fn(name string) goja.Callable {
	p.t.Helper()

	fn, ok := goja.AssertFunction(p.run("auth." + name))
	if !ok {
		p.t.Fatalf("auth.%s is not a function", name)
	}

	return fn
}

// pushStatus delivers the frame's status push for a session with the
// given token; an empty token is the unauthenticated state.
func (p *page) pushStatus(token string) {
	p.t.Helper()

	msg := map[string]any{
		"ns": "ethpandaops.authenticatoor", "v": 2, "type": "status",
		"status": "unauthenticated", "token": nil,
		"tokenInfo": map[string]any{
			"status": "unauthenticated", "authenticated": false, "user": "", "exp": 0,
		},
	}
	if token != "" {
		msg["status"] = "authenticated"
		msg["token"] = token
		msg["tokenInfo"] = map[string]any{
			"status": "authenticated", "authenticated": true, "user": "user@test.example",
			"exp": farFuture,
		}
	}

	raw, err := json.Marshal(msg)
	if err != nil {
		p.t.Fatalf("marshal status: %v", err)
	}
	p.run("__deliver(" + string(raw) + ");")
}

func firstLines(s string, n int) string {
	lines := strings.SplitN(s, "\n", n+1)
	if len(lines) > n {
		lines = lines[:n]
	}
	out := strings.Join(lines, "\n")
	if len(out) > 400 {
		out = out[:400] + "…"
	}

	return out
}

// unauthInfo is the v2 TokenInfo of the unauthenticated state, as JSON
// (the keys in the order pushStatus delivers them).
const unauthInfo = `{"authenticated":false,"exp":0,"status":"unauthenticated","user":"",` +
	`"teams":[],"services":""}`

// farFuture is an expiry no test run reaches.
const farFuture = 4102444800 // 2100-01-01

// fakeToken wraps a payload — any bytes — into the shape of a JWT. The
// clients do not look at the header or the signature.
func fakeToken(payload string) string {
	return "eyJhbGciOiJSUzI1NiJ9." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".c2ln"
}

// ─── the evaluator: JavaScript == Go ────────────────────────────────────────

// evalQuery is one question to both evaluators. Without hasFeature it
// is the service question only.
type evalQuery struct {
	directives, service, feature string
	hasFeature                   bool
}

// tableQueries returns every question the tables of pkg/auth's tests
// ask.
func tableQueries() []evalQuery {
	queries := make([]evalQuery, 0, 4096)
	add := func(directives, service string, features ...string) {
		queries = append(queries, evalQuery{directives: directives, service: service})
		for _, feature := range features {
			queries = append(queries, evalQuery{
				directives: directives, service: service, feature: feature, hasFeature: true,
			})
		}
	}

	for _, tc := range directivecases.Service {
		add(tc.Directives, tc.Service, "", "basic")
	}
	for _, tc := range directivecases.Grammar {
		add(tc.Directives, tc.Service, tc.Feature, "basic", " Basic ")
	}
	for _, tc := range directivecases.TruthTable {
		add(tc.Directives, directivecases.TruthTableService, directivecases.TruthTableFeature)
	}
	for _, tc := range directivecases.Arguments {
		add(tc.Directives, tc.Service, tc.Feature)
	}
	for _, service := range directivecases.EmptyClaimServices {
		add("", service, directivecases.EmptyClaimFeatures...)
		add("+all", service, directivecases.EmptyClaimFeatures...)
	}
	for _, q := range directivecases.LegacyQueries {
		add(q.Directives, q.Service, "", "basic", "f1")
	}
	for _, tc := range directivecases.V003Diff {
		add(tc.Directives, tc.Service, "", "basic", "x")
	}
	for _, in := range directivecases.OddInputs {
		if len(in) >= oddInputLong {
			continue // see longOddQueries
		}
		for _, service := range directivecases.OddServices {
			add(in, service, directivecases.OddFeatures...)
		}
	}

	return queries
}

// oddInputLong is the length from which an odd input counts as long.
const oddInputLong = 1000

// longOddQueries asks about the very long odd inputs. The interpreter
// walks them at a few microseconds per directive (a second per answer
// under the race detector), so each gets one question — about a service
// or about a feature, in turn — and they are run once.
func longOddQueries() []evalQuery {
	queries := make([]evalQuery, 0, len(directivecases.OddInputs))
	for i, in := range directivecases.OddInputs {
		if len(in) < oddInputLong {
			continue
		}
		q := evalQuery{directives: in, service: "spamoor"}
		if i%2 == 1 {
			q.feature, q.hasFeature = "x", true
		}
		queries = append(queries, q)
	}

	return queries
}

// generatedQueries builds directive lists from the fragment lists the
// generated tests of pkg/auth use, n lists per generator. Each list is
// asked about a few of the services and features those tests ask about,
// picked at random, and always about basic access.
func generatedQueries(seed int64, n int) []evalQuery {
	rng := rand.New(rand.NewSource(seed))
	pick := func(from []string) string { return from[rng.Intn(len(from))] }
	list := func(maxLen int, directive func() string) string {
		parts := make([]string, 0, maxLen)
		for range rng.Intn(maxLen + 1) {
			parts = append(parts, directive())
		}

		return strings.Join(parts, ",")
	}

	features := append([]string{"", "b", "basics", "backup", "user", "all"},
		directivecases.FeatureFeatures...)
	queries := make([]evalQuery, 0, n*40)
	ask := func(directives string, services []string) {
		for _, service := range services {
			queries = append(queries, evalQuery{directives: directives, service: service})
			for _, feature := range []string{"basic", pick(features), pick(features)} {
				queries = append(queries, evalQuery{
					directives: directives, service: service, feature: feature, hasFeature: true,
				})
			}
		}
	}

	for range n {
		// The full grammar, as TestFeatureAllowed_NeverWithoutBaseAccess.
		ask(list(6, func() string { return pick(directivecases.FeatureFragments) }),
			directivecases.FeatureServices)
		// Sign + name + segments, as TestFeatureAllowed_BasicIsServiceAllowed.
		ask(list(5, func() string {
			return pick(directivecases.BasicSigns) + pick(directivecases.BasicNames) +
				pick(directivecases.BasicSegments)
		}), []string{pick(directivecases.BasicServices), pick(directivecases.BasicServices)})
		// No ":", as TestServiceAllowed_SameAsV003WithoutColons.
		ask(list(6, func() string { return pick(directivecases.LegacyFragments) }),
			[]string{pick(directivecases.LegacyServices)})
	}

	return queries
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}

	return true
}

// compareEvaluators asks both evaluators every query. For ASCII input
// the answers must be the same. Input with anything else is outside the
// grammar; there the JavaScript must answer false, so it can never allow
// what Go refuses.
func compareEvaluators(t *testing.T, p *page, queries []evalQuery) {
	t.Helper()

	serviceAllowed := p.fn("serviceAllowed")
	featureAllowed := p.fn("featureAllowed")
	call := func(fn goja.Callable, args ...any) bool {
		values := make([]goja.Value, 0, len(args))
		for _, arg := range args {
			values = append(values, p.vm.ToValue(arg))
		}

		v, err := fn(goja.Undefined(), values...)
		if err != nil {
			t.Fatalf("javascript: %v (arguments %q)", err, args)
		}
		b, ok := v.Export().(bool)
		if !ok {
			t.Fatalf("javascript returned %v, not a boolean (arguments %q)", v, args)
		}

		return b
	}

	failures := 0
	check := func(what string, got, want, ascii bool) {
		if !ascii {
			want = false
		}
		if got == want {
			return
		}
		if failures++; failures <= 20 {
			t.Errorf("%s: javascript says %t, want %t (ascii input: %t)", what, got, want, ascii)
		}
	}

	yes, no := 0, 0
	for _, q := range queries {
		ascii := isASCII(q.directives) && isASCII(q.service) && isASCII(q.feature)
		if !q.hasFeature {
			got := call(serviceAllowed, q.directives, q.service)
			check(fmt.Sprintf("serviceAllowed(%.80q, %q)", q.directives, q.service),
				got, auth.ServiceAllowed(q.directives, q.service), ascii)
			continue
		}

		for _, mode := range []auth.FeatureDefault{auth.FeatureDefaultDeny, auth.FeatureDefaultAllow} {
			defaultAllow := mode == auth.FeatureDefaultAllow
			got := call(featureAllowed, q.directives, q.service, q.feature, defaultAllow)
			check(fmt.Sprintf("featureAllowed(%.80q, %q, %q, %t)",
				q.directives, q.service, q.feature, defaultAllow),
				got, auth.FeatureAllowed(q.directives, q.service, q.feature, mode), ascii)
			if got {
				yes++
			} else {
				no++
			}
		}
	}

	if failures > 20 {
		t.Errorf("… and %d more differences", failures-20)
	}
	if oneSidedOK := len(queries) < 100; !oneSidedOK && (yes == 0 || no == 0) {
		t.Fatalf("the queries are one-sided: %d allowed, %d refused", yes, no)
	}
	t.Logf("%d queries: %d feature answers yes, %d no", len(queries), yes, no)
}

// TestClientEvaluator_SameAsGo is the proof that the browser clients
// evaluate a "services" claim like pkg/auth does: the evaluator inside
// each served client library answers every row of pkg/auth's test
// tables, and a fixed-seed run of generated directive lists, exactly as
// auth.ServiceAllowed and auth.FeatureAllowed do, in both modes.
func TestClientEvaluator_SameAsGo(t *testing.T) {
	tables := tableQueries()
	// 3 × 1000 directive lists.
	generated := generatedQueries(20261115, 1000)

	for _, version := range []string{"1", "2"} {
		for _, variant := range clientVariants {
			t.Run("v"+version+"/"+variant.name, func(t *testing.T) {
				p := loadPage(t, servedClient(t, version, variant.devMode), pageOptions{})

				start := time.Now()
				compareEvaluators(t, p, tables)
				// The evaluator is the same text in every client
				// (TestClientClaimsInclude): the generated lists and
				// the long inputs go once over what ships.
				if version == "2" && !variant.devMode {
					compareEvaluators(t, p, generated)
					compareEvaluators(t, p, longOddQueries())
				}
				t.Logf("took %s", time.Since(start).Round(time.Millisecond))
			})
		}
	}
}

// TestClientEvaluator_Arguments covers what has no counterpart in Go:
// arguments of the wrong type, an absent claim, names outside ASCII.
func TestClientEvaluator_Arguments(t *testing.T) {
	for _, version := range []string{"1", "2"} {
		t.Run("v"+version, func(t *testing.T) {
			p := loadPage(t, servedClient(t, version, false), pageOptions{})
			p.expect(map[string]string{
				// An absent claim is the empty directive list.
				`auth.serviceAllowed(undefined, 'spamoor')`:              `true`,
				`auth.serviceAllowed(null, 'spamoor')`:                   `true`,
				`auth.featureAllowed(undefined, 'spamoor', 'x', true)`:   `true`,
				`auth.featureAllowed(undefined, 'spamoor', 'x', false)`:  `false`,
				`auth.featureAllowed(undefined, 'spamoor', 'x')`:         `false`,
				`auth.featureAllowed(undefined, 'spamoor', 'basic')`:     `true`,
				`auth.featureAllowed('+spamoor:x', 'spamoor', 'x')`:      `true`,
				`auth.featureAllowed('+spamoor', 'spamoor', 'x', true)`:  `true`,
				`auth.featureAllowed('+spamoor', 'spamoor', 'x', 1)`:     `false`,
				`auth.featureAllowed('+spamoor', 'spamoor', 'x', 'yes')`: `false`,

				// Anything that is not a string is refused.
				`auth.serviceAllowed(5, 'spamoor')`:                    `false`,
				`auth.serviceAllowed({}, 'spamoor')`:                   `false`,
				`auth.serviceAllowed(['+all'], 'spamoor')`:             `false`,
				`auth.serviceAllowed('+all', undefined)`:               `false`,
				`auth.serviceAllowed('', undefined)`:                   `false`,
				`auth.serviceAllowed('', null)`:                        `false`,
				`auth.serviceAllowed('+all', 5)`:                       `false`,
				`auth.featureAllowed('', 'spamoor', undefined, true)`:  `false`,
				`auth.featureAllowed('', undefined, 'basic', true)`:    `false`,
				`auth.featureAllowed('+all:all', 'spamoor', {}, true)`: `false`,
				`auth.featureAllowed(true, 'spamoor', 'x', true)`:      `false`,

				// Outside ASCII: refused, whatever Go would say. U+212A
				// (Kelvin) lowercases to "k", U+0130 to "i", U+00A0 is
				// space to Go's TrimSpace. The escapes are JavaScript's.
				`auth.serviceAllowed('-\u212Aurtosis', 'spamoor')`:              `false`,
				`auth.serviceAllowed('+all', 'spamoor\u00a0')`:                  `false`,
				`auth.serviceAllowed('', 'sp\u00e4moor')`:                       `false`,
				`auth.serviceAllowed('+all,+\u00e4', 'spamoor')`:                `false`,
				`auth.featureAllowed('+spamoor:plug\u0130ns', 'spamoor', 'x')`:  `false`,
				`auth.featureAllowed('+all:all', 'spamoor', 'plug\u0130ns')`:    `false`,
				`auth.featureAllowed('+all:all', 'spamoor', 'x\u2028', true)`:   `false`,
				`auth.featureAllowed('+all:all\ufeff', 'spamoor', 'x', true)`:   `false`,
				`auth.featureAllowed('', 'sp\u00e4moor', 'basic', true)`:        `false`,
				`auth.featureAllowed('+all:all', 'spamoor', '\ud83d\ude00', 1)`: `false`,
			})
		})
	}
}

// ─── the session: claims of the current token ───────────────────────────────

// noClaims is what the claim functions answer without a usable token:
// unauthenticated, or a token that cannot be decoded.
func noClaims() map[string]string {
	return map[string]string{
		`auth.getClaims()`:                                           `null`,
		`auth.getTeams()`:                                            `[]`,
		`auth.hasService('spamoor')`:                                 `false`,
		`auth.hasService('')`:                                        `false`,
		`auth.hasFeature('spamoor', 'basic')`:                        `false`,
		`auth.hasFeature('spamoor', 'plugins')`:                      `false`,
		`auth.hasFeature('spamoor', 'plugins', {defaultAllow:true})`: `false`,
	}
}

// claimTokens are tokens and what the clients must make of them. info
// is the teams and services of the v2 TokenInfo.
var claimTokens = []struct {
	name    string
	token   string
	info    string
	answers map[string]string
	// undecodable: the token yields no claims at all — the answers are
	// those of noClaims.
	undecodable bool
}{
	{
		name: "services and teams",
		token: fakeToken(`{"sub":"u","email":"user@test.example",` +
			`"services":"-all,+spamoor,+spamoor:plugins:user*,+dora:all:-roll",` +
			`"teams":["lighthouse","panda"]}`),
		info: `{"teams":["lighthouse","panda"],` +
			`"services":"-all,+spamoor,+spamoor:plugins:user*,+dora:all:-roll"}`,
		answers: map[string]string{
			`auth.getClaims().email`:                                                    `"user@test.example"`,
			`auth.getClaims().teams`:                                                    `["lighthouse","panda"]`,
			`auth.getTeams()`:                                                           `["lighthouse","panda"]`,
			`auth.hasService('spamoor')`:                                                `true`,
			`auth.hasService(' Spamoor ')`:                                              `true`,
			`auth.hasService('dora')`:                                                   `true`,
			`auth.hasService('buildoor')`:                                               `false`,
			`auth.hasService()`:                                                         `false`,
			`auth.hasFeature('spamoor', 'basic')`:                                       `true`,
			`auth.hasFeature('spamoor', 'plugins')`:                                     `true`,
			`auth.hasFeature('spamoor', 'user-admin')`:                                  `true`,
			`auth.hasFeature('spamoor', 'txpool')`:                                      `false`,
			`auth.hasFeature('spamoor', 'txpool', {})`:                                  `false`,
			`auth.hasFeature('spamoor', 'txpool', {defaultAllow:1})`:                    `false`,
			`auth.hasFeature('spamoor', 'txpool', {defaultAllow:true})`:                 `true`,
			`auth.hasFeature('dora', 'anything')`:                                       `true`,
			`auth.hasFeature('dora', 'roll')`:                                           `false`,
			`auth.hasFeature('dora', 'roll', {defaultAllow:true})`:                      `false`,
			`auth.hasFeature('buildoor', 'x', {defaultAllow:true})`:                     `false`,
			`auth.hasFeature('spamoor')`:                                                `false`,
			`(function(){var a=auth.getTeams();a.push('x');return auth.getTeams();})()`: `["lighthouse","panda"]`,
			`auth.getTeams() !== auth.getTeams()`:                                       `true`,
		},
	},
	{
		name:  "no services claim, no teams",
		token: fakeToken(`{"sub":"u","email":"user@test.example"}`),
		info:  `{"teams":[],"services":""}`,
		answers: map[string]string{
			`auth.getClaims().sub`:                                       `"u"`,
			`auth.getTeams()`:                                            `[]`,
			`auth.hasService('spamoor')`:                                 `true`,
			`auth.hasService('anything-else')`:                           `true`,
			`auth.hasFeature('spamoor', 'basic')`:                        `true`,
			`auth.hasFeature('spamoor', 'plugins')`:                      `false`,
			`auth.hasFeature('spamoor', 'plugins', {defaultAllow:true})`: `true`,
			`auth.hasFeature('spamoor', 'all', {defaultAllow:true})`:     `false`,
		},
	},
	{
		name:  "empty services claim",
		token: fakeToken(`{"sub":"u","services":"","teams":[]}`),
		info:  `{"teams":[],"services":""}`,
		answers: map[string]string{
			`auth.hasService('spamoor')`:            `true`,
			`auth.hasFeature('spamoor', 'plugins')`: `false`,
			`auth.getTeams()`:                       `[]`,
		},
	},
	{
		name:  "payload outside ASCII",
		token: fakeToken(`{"sub":"ü","name":"Zoë 🐼","services":"+all:all","teams":["panda"]}`),
		info:  `{"teams":["panda"],"services":"+all:all"}`,
		answers: map[string]string{
			`auth.getClaims().name`:                 `"Zoë 🐼"`,
			`auth.getClaims().sub`:                  `"ü"`,
			`auth.hasFeature('spamoor', 'plugins')`: `true`,
		},
	},

	// A services claim that is not a string: the Go verifier refuses the
	// token, so there is no service and no feature. The payload is still
	// what getClaims returns.
	{
		name:  "services is a number",
		token: fakeToken(`{"sub":"u","services":5,"teams":["panda"]}`),
		info:  `{"teams":["panda"],"services":""}`,
		answers: map[string]string{
			`auth.getClaims().services`:                                  `5`,
			`auth.getTeams()`:                                            `["panda"]`,
			`auth.hasService('spamoor')`:                                 `false`,
			`auth.hasService('')`:                                        `false`,
			`auth.hasFeature('spamoor', 'basic')`:                        `false`,
			`auth.hasFeature('spamoor', 'plugins', {defaultAllow:true})`: `false`,
		},
	},
	{
		name:  "services is an array",
		token: fakeToken(`{"sub":"u","services":["+all:all"]}`),
		info:  `{"teams":[],"services":""}`,
		answers: map[string]string{
			`auth.hasService('spamoor')`:                                 `false`,
			`auth.hasFeature('spamoor', 'plugins', {defaultAllow:true})`: `false`,
		},
	},
	{
		name:  "services is null",
		token: fakeToken(`{"sub":"u","services":null}`),
		info:  `{"teams":[],"services":""}`,
		answers: map[string]string{
			`auth.hasService('spamoor')`:                                 `false`,
			`auth.hasFeature('spamoor', 'plugins', {defaultAllow:true})`: `false`,
		},
	},
	{
		// Go's JSON decoder would read this key as the services claim.
		name:  "services under another spelling",
		token: fakeToken(`{"sub":"u","Services":"-all","TEAMS":["panda"]}`),
		info:  `{"teams":[],"services":""}`,
		answers: map[string]string{
			`auth.getTeams()`:            `[]`,
			`auth.hasService('spamoor')`: `false`,
			`auth.hasFeature('spamoor', 'plugins', {defaultAllow:true})`: `false`,
		},
	},
	{
		name:  "services under a spelling only case folding finds",
		token: fakeToken(`{"sub":"u","ſervices":"-all"}`),
		info:  `{"teams":[],"services":""}`,
		answers: map[string]string{
			`auth.hasService('spamoor')`: `false`,
		},
	},

	// Teams that are not an array of strings: no teams. The services
	// claim is unaffected.
	{
		name:  "teams is a string",
		token: fakeToken(`{"sub":"u","services":"+spamoor:plugins","teams":"panda"}`),
		info:  `{"teams":[],"services":"+spamoor:plugins"}`,
		answers: map[string]string{
			`auth.getTeams()`:                       `[]`,
			`auth.getClaims().teams`:                `"panda"`,
			`auth.hasFeature('spamoor', 'plugins')`: `true`,
		},
	},
	{
		name:  "teams has an entry that is not a string",
		token: fakeToken(`{"sub":"u","teams":["panda",7,"lighthouse"]}`),
		info:  `{"teams":[],"services":""}`,
		answers: map[string]string{
			`auth.getTeams()`:            `[]`,
			`auth.hasService('spamoor')`: `true`,
		},
	},
	{
		name:  "teams is an object",
		token: fakeToken(`{"sub":"u","teams":{"0":"panda","length":1}}`),
		info:  `{"teams":[],"services":""}`,
		answers: map[string]string{
			`auth.getTeams()`: `[]`,
		},
	},

	// Tokens that cannot be decoded: no claims, no service, no feature.
	{name: "not three parts", token: "abc", undecodable: true},
	{name: "two parts", token: "eyJhbGciOiJSUzI1NiJ9.e30", undecodable: true},
	{name: "four parts", token: "a.e30.c.d", undecodable: true},
	{name: "empty payload part", token: "a..c", undecodable: true},
	{name: "payload is not base64url", token: "a.e30!.c", undecodable: true},
	{name: "payload is standard base64 with padding", token: "a.e30=.c", undecodable: true},
	{name: "payload of an impossible length", token: "a.e30ab.c", undecodable: true},
	{name: "payload is not JSON", token: fakeToken(`{"sub":`), undecodable: true},
	{name: "payload is not UTF-8", token: fakeToken("{\"sub\":\"\xff\xfe\"}"), undecodable: true},
	{name: "payload is an array", token: fakeToken(`[{"services":"+all:all"}]`), undecodable: true},
	{name: "payload is a string", token: fakeToken(`"+all:all"`), undecodable: true},
	{name: "payload is a number", token: fakeToken(`5`), undecodable: true},
	{name: "payload is null", token: fakeToken(`null`), undecodable: true},
}

func TestClientV2_Claims(t *testing.T) {
	script := servedClient(t, "2", false)

	t.Run("surface", func(t *testing.T) {
		p := loadPage(t, script, pageOptions{})
		p.expect(map[string]string{
			`auth.version`: `2`,
			`['getClaims','hasService','hasFeature','getTeams','serviceAllowed','featureAllowed',` +
				`'addEventListener','removeEventListener','getStatus','getToken','login','logout',` +
				`'authServiceURL'].filter(function(n){return typeof auth[n] !== 'function';})`: `[]`,
			`typeof auth.hasFeature === 'function'`: `true`,
		})
	})

	t.Run("before the first status", func(t *testing.T) {
		p := loadPage(t, script, pageOptions{})
		p.expect(noClaims())
	})

	t.Run("unauthenticated", func(t *testing.T) {
		p := loadPage(t, script, pageOptions{})
		p.run(`var events = []; auth.addEventListener('status', function (i) { events.push(i); });
			var resolved = null; auth.getStatus().then(function (i) { resolved = i; });`)
		p.pushStatus("")
		p.expect(noClaims())
		p.expect(map[string]string{
			`events`:   "[" + unauthInfo + "]",
			`resolved`: unauthInfo,
		})
	})

	for _, tc := range claimTokens {
		t.Run(tc.name, func(t *testing.T) {
			p := loadPage(t, script, pageOptions{})
			p.run(`var events = []; auth.addEventListener('status', function (i) { events.push(i); });
				var resolved = null; auth.getStatus().then(function (i) { resolved = i; });`)
			p.pushStatus(tc.token)

			answers, info := tc.answers, tc.info
			if tc.undecodable {
				answers, info = noClaims(), `{"teams":[],"services":""}`
			}
			p.expect(answers)

			// The status event and getStatus carry the teams and the raw
			// services claim next to the fields they always had.
			pick := `{teams: %[1]s.teams, services: %[1]s.services}`
			p.expect(map[string]string{
				`events.length`:                 `1`,
				fmt.Sprintf(pick, "events[0]"):  info,
				fmt.Sprintf(pick, "resolved"):   info,
				`Object.keys(events[0]).sort()`: `["authenticated","exp","services","status","teams","user"]`,
				`[events[0].status, events[0].authenticated, events[0].user, events[0].exp]`: fmt.Sprintf(
					`["authenticated",true,"user@test.example",%d]`, farFuture),
			})

			// A late subscriber is replayed the same info.
			p.run(`var late = []; auth.addEventListener('status', function (i) { late.push(i); });
				__flush();`)
			p.expect(map[string]string{
				`late.length`:                `1`,
				fmt.Sprintf(pick, "late[0]"): info,
			})

			// Logged out: nothing is left of the token.
			p.pushStatus("")
			p.expect(noClaims())
			p.expect(map[string]string{
				`events.length`: `2`,
				`events[1]`:     unauthInfo,
			})
		})
	}

	t.Run("a new token with other claims is a status change", func(t *testing.T) {
		p := loadPage(t, script, pageOptions{})
		p.run(`var events = []; auth.addEventListener('status', function (i) { events.push(i); });`)
		p.pushStatus(fakeToken(`{"sub":"u","services":"+spamoor"}`))
		// Same user, same expiry, same token: nothing to tell.
		p.pushStatus(fakeToken(`{"sub":"u","services":"+spamoor"}`))
		p.expect(map[string]string{
			`events.length`:                         `1`,
			`auth.hasFeature('spamoor', 'plugins')`: `false`,
		})
		p.pushStatus(fakeToken(`{"sub":"u","services":"+spamoor,+spamoor:plugins","teams":["panda"]}`))
		p.expect(map[string]string{
			`events.length`:                         `2`,
			`events[1].services`:                    `"+spamoor,+spamoor:plugins"`,
			`events[1].teams`:                       `["panda"]`,
			`auth.hasFeature('spamoor', 'plugins')`: `true`,
		})
	})

	t.Run("token from the login redirect", func(t *testing.T) {
		token := fakeToken(`{"sub":"u","email":"user@test.example","services":"+spamoor:plugins",` +
			`"teams":["panda"]}`)
		p := loadPage(t, script, pageOptions{
			hash: fmt.Sprintf("#auth_token=%s&exp=%d", token, farFuture),
		})
		// Provisional state, before the frame said anything.
		p.run(`var resolved = null; auth.getStatus().then(function (i) { resolved = i; });`)
		p.expect(map[string]string{
			`auth.getTeams()`:                       `["panda"]`,
			`auth.hasFeature('spamoor', 'plugins')`: `true`,
			`auth.hasFeature('spamoor', 'other')`:   `false`,
			`resolved`: fmt.Sprintf(`{"status":"authenticated","authenticated":true,`+
				`"user":"user@test.example","exp":%d,"teams":["panda"],"services":"+spamoor:plugins"}`,
				farFuture),
		})
	})

	t.Run("a token the issuer minted", func(t *testing.T) {
		_, iss, _ := newTestServer(t)
		token, claims, err := iss.IssueFor(issuer.Identity{
			Subject: "user@test.example", Email: "user@test.example", SubjectIsEmail: true,
			Teams: []string{"panda", "lighthouse"},
		}, nil)
		if err != nil {
			t.Fatalf("issue: %v", err)
		}

		p := loadPage(t, script, pageOptions{})
		p.pushStatus(token)

		teams, err := json.Marshal(claims.Teams)
		if err != nil {
			t.Fatalf("marshal teams: %v", err)
		}
		p.expect(map[string]string{
			`auth.getClaims().email`:     `"user@test.example"`,
			`auth.getClaims().iss`:       `"https://auth.test.example"`,
			`auth.getTeams()`:            string(teams),
			`auth.getTeams().length`:     `2`,
			`auth.hasService('spamoor')`: fmt.Sprint(auth.ServiceAllowed(claims.Services, "spamoor")),
			`auth.hasFeature('spamoor', 'plugins')`: fmt.Sprint(
				claims.HasFeature("spamoor", "plugins", auth.FeatureDefaultDeny)),
			`auth.hasFeature('spamoor', 'plugins', {defaultAllow:true})`: fmt.Sprint(
				claims.HasFeature("spamoor", "plugins", auth.FeatureDefaultAllow)),
		})
	})
}

// TestClientV1_Claims: the v1 client answers about the token getToken()
// returns — the fresh one in sessionStorage — and keeps its own API.
func TestClientV1_Claims(t *testing.T) {
	script := servedClient(t, "1", false)
	stored := func(token string, exp int64) map[string]string {
		return map[string]string{
			"ethpandaops.authenticatoor.token": token,
			"ethpandaops.authenticatoor.exp":   fmt.Sprint(exp),
			"ethpandaops.authenticatoor.user":  "user@test.example",
		}
	}

	t.Run("surface", func(t *testing.T) {
		p := loadPage(t, script, pageOptions{})
		p.expect(map[string]string{
			`Object.keys(auth).sort()`: `["authServiceURL","checkLogin","featureAllowed","getClaims",` +
				`"getTeams","getToken","hasFeature","hasService","isLoggedIn","login","logout",` +
				`"serviceAllowed"]`,
		})
	})

	t.Run("no token yet", func(t *testing.T) {
		p := loadPage(t, script, pageOptions{})
		p.expect(noClaims())
	})

	t.Run("stored token expired", func(t *testing.T) {
		p := loadPage(t, script, pageOptions{
			stored: stored(fakeToken(`{"sub":"u","services":"+all:all","teams":["panda"]}`), 1000),
		})
		p.expect(noClaims())
	})

	for _, tc := range claimTokens {
		t.Run(tc.name, func(t *testing.T) {
			p := loadPage(t, script, pageOptions{stored: stored(tc.token, farFuture)})
			answers := tc.answers
			if tc.undecodable {
				answers = noClaims()
			}
			p.expect(answers)

			// checkLogin resolves to what it always did.
			p.run(`var login = null; auth.checkLogin().then(function (i) { login = i; });`)
			p.expect(map[string]string{
				`Object.keys(login).sort()`: `["authenticated","exp","token","user"]`,
				`[login.authenticated, login.token, login.exp, login.user]`: fmt.Sprintf(
					`[true,%q,%d,"user@test.example"]`, tc.token, farFuture),
			})

			p.run(`auth.logout();`)
			p.expect(noClaims())
		})
	}

	t.Run("token from the login redirect", func(t *testing.T) {
		token := fakeToken(`{"sub":"u","services":"+spamoor:plugins","teams":["panda"]}`)
		p := loadPage(t, script, pageOptions{
			hash: fmt.Sprintf("#auth_token=%s&exp=%d", token, farFuture),
		})
		// Nothing before checkLogin picked the token up.
		p.expect(noClaims())
		p.run(`auth.checkLogin();`)
		p.expect(map[string]string{
			`auth.getTeams()`:                       `["panda"]`,
			`auth.hasFeature('spamoor', 'plugins')`: `true`,
		})
	})
}

// TestClientClaimsInclude: the claims code is one file, included into
// every client library and into nothing else.
func TestClientClaimsInclude(t *testing.T) {
	claims, err := authenticatoorFS.ReadFile(claimsIncludeFile)
	if err != nil {
		t.Fatalf("read %s: %v", claimsIncludeFile, err)
	}

	for _, name := range []string{"static/authenticatoor-v1.js", "static/authenticatoor-v2.js"} {
		raw, err := authenticatoorFS.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if n := strings.Count(string(raw), claimsIncludeMarker); n != 1 {
			t.Errorf("%s: %d include markers, want 1", name, n)
		}

		src, err := clientSource(name)
		if err != nil {
			t.Fatalf("clientSource(%s): %v", name, err)
		}
		if strings.Contains(src, claimsIncludeMarker) {
			t.Errorf("%s: include marker left in the source", name)
		}
		if n := strings.Count(src, string(claims)); n != 1 {
			t.Errorf("%s: the claims code is included %d times, want 1", name, n)
		}
	}

	frame, err := clientSource("static/authenticatoor-frame-v2.js")
	if err != nil {
		t.Fatalf("clientSource(frame): %v", err)
	}
	if strings.Contains(frame, "claimsServiceAllowed") {
		t.Error("the frame script must not carry the claims code")
	}

	for _, variant := range clientVariants {
		for _, version := range []string{"1", "2"} {
			served := servedClient(t, version, variant.devMode)
			if strings.Contains(served, "__AUTHENTICATOOR_CLAIMS__") {
				t.Errorf("v%s (%s): include marker served", version, variant.name)
			}
		}
	}
}
