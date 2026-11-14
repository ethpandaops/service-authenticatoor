# service-authenticatoor

An HTTP service that issues short-lived RS256 JWTs to users authenticated
by an upstream reverse-proxy SSO. The matching public keys are published
as a JWKS so any resource server can validate the issued tokens locally —
no shared secrets, no per-service SSO configuration.

## What it does

Behind the active protection provider (`/auth/*`):

- `GET /auth/token` — issue a JWT for the authenticated user (JSON
  response, CORS-enabled, accepts `credentials: include`).
- `GET /auth/login?return_to=<url>` — issue a JWT and 302 to `return_to`
  with the token in the URL fragment. `return_to` host must match
  `allowedReturnHosts`.
- `GET /auth/userinfo` — small introspection endpoint (email, subject,
  teams, audience, scope).
- `GET /auth/embed?target_origin=…` — issues a JWT and posts it to the
  parent window via `postMessage`, restricted to the validated origin.
  This is the silent token-acquisition path (loaded via an invisible
  iframe).
- `POST /auth/logout` — provider-dispatched logout. Always reachable,
  regardless of authentication state.

Public (no upstream auth — reachable by JWKS verifiers and browser JS):

- `GET /jwks.json` — RS256 public keys.
- `GET /.well-known/openid-configuration` — minimal OIDC discovery doc.
- `GET /client-v{n}.js` — drop-in browser client library, exposed as
  `window.ethpandaops.authenticatoor`. `client-v1.js` is the
  polling-style API (`{checkLogin, login, logout, getToken, isLoggedIn}`);
  `client-v2.js` is the shared-session, event-emitting API described
  below. Auth service URL is templated in at serve time. Served minified
  with an external source map at `/client-v{n}.js.map`; set
  `devMode: true` to serve the readable source instead. The legacy
  `/client.js` path keeps serving v1 for existing consumers.
- `GET /clientFrame?v=2&origin=…` — HTML shell for the hidden
  shared-session iframe mounted by the v2 client, with the frame script
  inlined. The `origin` param must match `allowedReturnHosts` and is
  pinned via CSP `frame-ancestors`; script execution is pinned to the
  exact inlined script via a CSP `sha256` hash source.
- `GET /healthz` — liveness probe.
- `GET /` — landing page.

## Browser integration (v2 — shared session)

```html
<script src="https://auth.<devnet>.ethpandaops.io/client-v2.js"></script>
<script>
  const auth = window.ethpandaops.authenticatoor;

  // Fires on every session change: "unauthenticated" | "authenticated"
  // | "refreshing". Fired once with the current state right after
  // subscribing (asynchronously), so it can drive the whole auth UI.
  auth.addEventListener('status', (info) => {
    // info = { status, authenticated, user, exp }
    if (info.authenticated) renderAuthedUI(info);
    else renderLoginButton();
  });

  // Bearer token for API calls — resolves to a token with comfortable
  // remaining validity (refreshed behind the scenes), or null when
  // unauthenticated.
  async function callAPI() {
    const token = await auth.getToken();
    return fetch('/api/thing', { headers: { Authorization: `Bearer ${token}` } });
  }

  // login(): resolves true if already authenticated, otherwise runs the
  // full-page /auth/login redirect flow.
  document.querySelector('#login').addEventListener('click', () => auth.login());

  // logout(): logs out everywhere — every app and tab converges to
  // "unauthenticated".
  document.querySelector('#logout').addEventListener('click', () => auth.logout());
</script>
```

How v2 works: the client mounts a hidden iframe on the auth-service
origin (`/clientFrame`). The frame owns the session — it keeps the token
in auth-origin `localStorage` (shared by every app's frame), refreshes it
before expiry with exactly one elected refresher across all tabs (Web
Locks API), and pushes status changes to each app over origin-checked
`postMessage`. The raw token never touches app-origin storage.

Because browsers partition third-party-iframe storage **and cookies** by
top-level site (eTLD+1), the full v2 behavior requires apps and the auth
service to share a **registrable domain** (e.g. `*.<devnet>.ethpandaops.io`).
On a foreign-domain app the frame cannot see the auth session cookie
(Firefox's Total Cookie Protection partitions it for every cross-site
embed), so silent refresh is unavailable there: the token captured from
the `/auth/login` redirect is kept until it expires, then the user goes
through the full-page login again.

Local-dev pitfall: `localhost` is itself the effective TLD, so
`auth.localhost` and `app.localhost` (or `localhost:<port>`) are
*different sites* and Firefox will not send the cookie from the frame.
Either run everything on plain `localhost:<port>`s, or give every host a
shared parent zone (`auth.dev.localhost` + `app.dev.localhost`).

v1 remains available (and the default) for existing consumers; it is
unchanged.

## Browser integration (v1)

```html
<script src="https://auth.<devnet>.ethpandaops.io/client.js"></script>
<script>
  const auth = window.ethpandaops.authenticatoor;

  // 1. Render the unauthenticated UI right away — don't await.
  renderLoginButton();

  // 2. checkLogin tries fragment → cache → silent iframe (up to 30s).
  //    When it resolves with authenticated:true, swap to the authed UI.
  auth.checkLogin().then((info) => {
    if (info.authenticated) renderAuthedUI(info);
  });

  // 3. The login button calls auth.login() — full-page redirect, comes
  //    back with #auth_token=… in the fragment (handled on next load).
  document.querySelector('#login').addEventListener('click', () => auth.login());
</script>
```

`checkLogin()` runs through three sources in order:
1. **Fragment capture** — picks up `#auth_token=…&exp=…` if the page just
   came back from `/auth/login`. Resolves immediately.
2. **Cached token** — returns the still-fresh token from `sessionStorage`.
   Resolves immediately.
3. **Silent iframe** — loads `/auth/embed` in an invisible iframe, which
   either posts the token back via `postMessage` (if the user already has
   a CF Access cookie) or hangs there silently (CF Access tries to render
   its login page in the iframe; the page's own `X-Frame-Options` blocks
   it). The promise resolves when the iframe responds, or after 30s with
   `authenticated: false`.

Render the unauthenticated UI immediately — never block on the promise.
The user can click "Login" any time during the 30-second window; the
in-flight promise simply becomes irrelevant once the page navigates.

## Token format

```json
{
  "iss":   "https://auth.example.com",
  "sub":   "alice@example.com",
  "email": "alice@example.com",
  "aud":   ["example.com"],
  "scope": "*.example.com",
  "teams": ["lighthouse", "panda"],
  "iat":   1714492800,
  "nbf":   1714492800,
  "exp":   1714494600,
  "jti":   "8b3f…"
}
```

Signed RS256, `kid` in the header. Verifiers must check `iss`, `aud`,
`exp`, and the signature.

### Teams

**Teams say who you are; grants say what you may use.**

`teams` lists the teams the user belongs to. It is an identity
attribute: a resource server uses it to tell whose things are whose (a
client team acting on its own nodes). authenticatoor does not manage
memberships: the claim carries what the provider that authenticated the
user knows. Each provider takes a static list (`teams: [panda]`) and
`teamRules` that derive teams from the attributes it verified — the
`team:<slug>` groups of the central IdP's id_token, an org list, an
email address:

```yaml
oidc:
  teamRules:
    - claim: groups
      prefix: "team:"       # "team:lighthouse" → lighthouse
```

Access does not hang on a team name. Which tools a user may use is
decided by the `grants` section, whose members always name the provider
they come through (`cfaccess/team:panda`, `oidc/team:lighthouse`,
`oidc/groups:panda-access`, `oidc/user:alice@example.org`), and reaches
a tool as the `services` claim below. In a resource server, use `teams`
for ownership and features (`HasFeature`) for what a user may do; do
not hang privileges on a team name.

See [`docs/config.md`](docs/config.md#teams) for the attributes of each
provider, the rule forms, and how sessions and config changes interact.

The claim is an array of lowercase names (`[a-z0-9][a-z0-9._-]{0,62}`),
de-duplicated, sorted, at most 32 entries. It is **omitted** when the
user has no teams, and absent from tokens issued by older versions —
treat a missing claim as "no teams", never as "all teams".

A Go resource server reads it from the verified claims of
[`pkg/auth`](pkg/auth):

```go
claims, err := verifier.Verify(token) // unchanged
if err != nil { /* 401 */ }

if claims.HasTeam("panda") {
	// internal team: everything
} else if claims.HasAnyTeam(node.OwnerTeams...) {
	// a client team acting on its own node
} else {
	// 403
}
```

`HasTeam` / `HasAnyTeam` normalize their argument and compare exactly
(no prefixes, no wildcards); `claims.Teams` is the raw slice. Other
languages read the `teams` array from the JWT payload after verifying
the token. Verification itself does not look at the claim, so tokens
without it verify exactly as before.

### Services

`services` is an allow/deny directive list (`+name` / `-name`, `all` for
every service, later entries win) saying which tools the token may be
used against — `"-all,+dora"` is a token for dora only. A
resource server enforces it by naming itself to the verifier:

```go
verifier, err := auth.NewJWKSVerifier(ctx, auth.VerifierConfig{
	// ...
	ExpectedService: "dora",
})
```

`Verify` then rejects tokens whose directive does not allow that
service. Two properties matter:

- A missing or empty claim means **basic access to every service and
  nothing more** — such a token passes every service check and holds no
  granted feature (see below). That is what tokens look like unless the
  [`grants`](docs/config.md#service-grants-grants) config section is
  set.
- The claim only binds resource servers that set `ExpectedService`
  (spamoor and assertoor do; buildoor does once its branch
  `pk910/services-gate` is merged). One that does not accepts any valid
  token.

With `grants` configured, authenticatoor computes the claim per user
from the groups they are a member of — by team, by user id or by any
attribute their provider verified, always together with that provider:
`+all` for someone granted every service, `-all,+<service>…` for
specific grants, and `-all` for a user in no group.

### Checking features in a resource server

A service directive grants basic access; features are extras on top.
`+dora` is basic access to dora, `+dora:admin` adds its
feature `admin`, `+dora:all` every feature, `+dora:user*` every
feature whose name starts with `user`, and `-dora:admin` or
`+dora:all:-admin` exclude one. (`basic` is the reserved name of
basic access itself; `all` is reserved too.)

Keep the service gate (`ExpectedService`) and add feature checks to it —
never replace it. Each feature is checked in one of two modes:

```go
// Privileged: must be handed out deliberately. Needs +dora:admin or
// +dora:all.
if !claims.HasFeature("dora", "admin", auth.FeatureDefaultDeny) {
	http.Error(w, "forbidden", http.StatusForbidden)
	return
}

// Ordinary: comes with basic access unless it was excluded.
if claims.HasFeature("dora", "view-logs", auth.FeatureDefaultAllow) {
	// ...
}

// As middleware: 401 without claims, 403 when not allowed.
mux.Handle("POST /api/admin/reindex", auth.RequireFeature(
	"dora", "admin", auth.FeatureDefaultDeny, handleReindex))
```

| Basic access to the service | Feature  | `FeatureDefaultDeny` | `FeatureDefaultAllow` |
| --------------------------- | -------- | -------------------- | --------------------- |
| denied                      | any      | no                   | no                    |
| allowed                     | unset    | no                   | yes                   |
| allowed                     | granted  | yes                  | yes                   |
| allowed                     | excluded | no                   | no                    |
| *token without a `services` claim* | *(unset)* | no              | yes                   |

A feature is never allowed without basic access. A token without the
claim has basic access to every service and nothing more: it is the row
"allowed / unset", exactly as if the claim were `+all`. That is what an
authenticatoor without `grants` mints, so such an instance hands out no
default-deny feature — configure `grants` to give them out.

Features name capabilities (`admin`), not endpoints. Because a grant can
be a prefix (`user*`), feature names are namespaces: group them
deliberately (`user-view`, `user-edit`). Introducing a
default-deny feature takes it away from every group that only has the
bare service — the internal team should be granted `all:all`. In
`grants`, a grant names features as `svc:f1:f2`, `svc:all`,
`all:f1` or `all:all`; the emitted claim always carries the bare
directive too (`-all,+dora,+dora:admin`), so tools built
against older versions of `pkg/auth` keep reading basic access
correctly. Details:
[`docs/config.md`](docs/config.md#features).

## Build

```sh
go build -o authenticatoor ./cmd/authenticatoor
```

Or via Docker:

```sh
docker build -t authenticatoor:dev .
```

## Run

Generate a signing key:

```sh
authenticatoor genkey > /etc/authenticatoor/keys/private.pem
chmod 600 /etc/authenticatoor/keys/private.pem
```

Write a config (see [`config.example.yaml`](config.example.yaml)
and [`docs/config.md`](docs/config.md)):

```yaml
issuer: "https://auth.example.com"
signing:
  rs256:
    privateKeyFile: "/etc/authenticatoor/keys/private.pem"
cloudflareAccess:
  teamDomain: "<team>.cloudflareaccess.com"
  audTag: "<CF Access app AUD tag>"
```

Run:

```sh
authenticatoor --config /etc/authenticatoor/config.yaml
```

For local development without an upstream SSO, switch to the `any`
provider — every HTTP Basic credential is accepted and the supplied
username becomes the identity:

```yaml
authMode: any
```

See [`docs/config.md`](docs/config.md#protection-modes) for the full
reference and the alternatives (`basic`, `github`).

## Upgrading

Configs written for earlier versions load unchanged — the single-string
`authMode`, the top-level `userHeader` and the top-level provider blocks
(`cloudflareAccess:`, `basicAuth:`, `anyAuth:`, `githubOAuth:`, `oidc:`)
stay valid, and without the new settings (`teams`, `teamRules`,
`grants`) the tokens carry the same claims as before. Three things to
know:

- **Everyone logs in again, once.** Session cookies of earlier versions
  are not accepted. Invisible behind Cloudflare Access; a redirect
  through the IdP for `oidc` and `github`.
- **`oidc`: an email counts only when the id_token says
  `email_verified: true`.** Otherwise the user's token has the IdP's
  `sub` as its `sub` and no `email` — where earlier versions used the
  email regardless. With an IdP that sends `false` or nothing, every
  user's subject changes with the upgrade; with one that flips the flag
  between logins, a user's subject alternates. Set
  `oidc.trustUnverifiedEmail: true` to get the earlier behaviour (only
  for an IdP that verifies addresses without saying so) or `false` to
  keep the rule; until the key is set, the service warns at startup.
- **Unknown keys are checked.** A misspelled key inside a provider
  block, a top-level key within two edits of `grants`, and a map
  written where a list belongs are startup errors that name the key.
  Keys earlier versions knew and that are gone (`anyAuth.loginPath`,
  `githubOAuth.sessionSecret`, `githubOAuth.sessionSecretFile`) are
  ignored with a deprecation warning; other unknown top-level keys only
  get a warning.

Cloudflare Access needs no `audTag`: a provider without it keeps
accepting the assertions of every Access application of the Cloudflare
team, also when it gives teams or is named in `grants` — the service
then says so in a startup warning. Set `audTag` to limit it to one
application.

Details: [`docs/config.md`](docs/config.md#upgrading).

## Dev quickstart

```sh
# 1. Build
go build -o /tmp/authenticatoor ./cmd/authenticatoor

# 2. Generate a key
mkdir -p /tmp/authtest
/tmp/authenticatoor genkey > /tmp/authtest/key.pem

# 3. Write a minimal config
cat > /tmp/authtest/config.yaml <<EOF
listen: "127.0.0.1:18080"
issuer: "https://auth.example.com"
signing:
  rs256:
    privateKeyFile: "/tmp/authtest/key.pem"
cloudflareAccess:
  verifyJWT: false
EOF

# 4. Run
/tmp/authenticatoor --config /tmp/authtest/config.yaml &

# 5. Mint a token (simulating an authenticated request)
curl -H "Cf-Access-Authenticated-User-Email: alice@example.com" \
     http://127.0.0.1:18080/auth/token

# 6. Inspect public keys
curl http://127.0.0.1:18080/jwks.json
curl http://127.0.0.1:18080/.well-known/openid-configuration
```

## Tests

```sh
go test ./...
```

## Protection providers

Providers decide who is allowed to mint tokens. The `providers` list
defines the instances — all enabled: on each `/auth/*` request the chain
runs in order and the first provider recognizing a credential (session
cookie, ambient Cloudflare Access headers, Basic `Authorization`) wins.
`authMode` (a name, or a list of names) picks what unauthenticated users
are offered: a single advertised provider redirects into its own login
flow, several redirect to the `/login` selector page. Each provider mounts
its interactive login flow under its own prefix (`/cfaccess/login`,
`/htpasswd/login`, `/github/login`, `/oidc/login`, `/anyauth/login`),
so `/auth/*` itself needs no edge protection.

- **`cloudflare`** (default): trust headers from a Cloudflare Access (or
  similar) reverse-proxy SSO; optionally verify the assertion JWT. Works
  with the edge covering `/auth/*` (ambient) or just `/cfaccess/*`
  (cookie via `/cfaccess/login`; machine token alias at `/cfaccess/token`).
- **`basic`**: HTTP Basic auth backed by an htpasswd file. Self-contained.
- **`any`**: dev-only — any Basic credential is accepted, username = identity.
- **`github`**: GitHub OAuth with org-membership gating; signed session cookie.
- **`oidc`**: OpenID Connect against any IdP, with group gating.

See [`docs/config.md`](docs/config.md#protection-providers) for the
per-provider config blocks and trade-offs.

## Repo layout

```
cmd/authenticatoor/   entrypoint
pkg/auth/             verifier library: claims, JWKS verifier, middleware, scope matcher
pkg/issuer/           issuer-side: RSA keys, RS256 signing, JWKS marshaling
pkg/cors/             CORS middleware with strict allow-list
pkg/cfaccess/         Cf-Access-Jwt-Assertion verification
pkg/config/           YAML + env config loader, derivation, validation
pkg/protection/       Provider interface; sub-packages cloudflare/basic/anyauth/github/oidc
pkg/server/           HTTP server: routes, handlers, lifecycle
Dockerfile            multi-stage source build
Dockerfile-stub       packages a pre-built binary into a distroless image (used by CI)
config.example.yaml   annotated example config
docs/                 config reference
```

`pkg/auth` is intended for resource servers that consume tokens; it has
no signing, key-loading, or HTTP-server logic and is safe to depend on
without pulling in the issuer-side machinery.
