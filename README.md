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
- `GET /auth/userinfo` — small introspection endpoint.
- `GET /auth/embed?target_origin=…` — issues a JWT and posts it to the
  parent window via `postMessage`, restricted to the validated origin.
  This is the silent token-acquisition path (loaded via an invisible
  iframe).
- `POST /auth/logout` — provider-dispatched logout. Always reachable,
  regardless of authentication state.

Public (no upstream auth — reachable by JWKS verifiers and browser JS):

- `GET /jwks.json` — RS256 public keys.
- `GET /.well-known/openid-configuration` — minimal OIDC discovery doc.
- `GET /client.js?v=1|2` — drop-in browser client library, exposed as
  `window.ethpandaops.authenticatoor`. `v=1` (the default) is the
  polling-style API (`{checkLogin, login, logout, getToken, isLoggedIn}`);
  `v=2` is the shared-session, event-emitting API described below. Auth
  service URL is templated in at serve time.
- `GET /clientFrame?v=2&origin=…` — HTML shell for the hidden
  shared-session iframe mounted by the v2 client. The `origin` param must
  match `allowedReturnHosts` and is pinned via CSP `frame-ancestors`.
- `GET /client.frame.js?v=2` — the script running inside that iframe.
- `GET /healthz` — liveness probe.
- `GET /` — landing page.

When deploying behind an authenticating proxy, `/clientFrame` and
`/client.frame.js` must be exempted from upstream auth exactly like
`/client.js` — they are loaded before the user is authenticated.

## Browser integration (v2 — shared session)

```html
<script src="https://auth.<devnet>.ethpandaops.io/client.js?v=2"></script>
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
  "iat":   1714492800,
  "nbf":   1714492800,
  "exp":   1714494600,
  "jti":   "8b3f…"
}
```

Signed RS256, `kid` in the header. Verifiers must check `iss`, `aud`,
`exp`, and the signature.

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

## Protection modes

`authMode` selects who is allowed to mint tokens. One provider per process:

- **`cloudflare`** (default): trust headers from a Cloudflare Access (or
  similar) reverse-proxy SSO; optionally verify the assertion JWT.
- **`basic`**: HTTP Basic auth backed by an htpasswd file. Self-contained.
- **`any`**: dev-only — any Basic credential is accepted, username = identity.
- **`github`**: GitHub OAuth with org-membership gating; signed session cookie.

See [`docs/config.md`](docs/config.md#protection-modes) for the per-mode
config blocks and trade-offs.

## Repo layout

```
cmd/authenticatoor/   entrypoint
pkg/auth/             verifier library: claims, JWKS verifier, middleware, scope matcher
pkg/issuer/           issuer-side: RSA keys, RS256 signing, JWKS marshaling
pkg/cors/             CORS middleware with strict allow-list
pkg/cfaccess/         Cf-Access-Jwt-Assertion verification
pkg/config/           YAML + env config loader, derivation, validation
pkg/protection/       Provider interface; sub-packages cloudflare/basic/anyauth/github
pkg/server/           HTTP server: routes, handlers, lifecycle
Dockerfile            multi-stage source build
Dockerfile-stub       packages a pre-built binary into a distroless image (used by CI)
config.example.yaml   annotated example config
docs/                 config reference
```

`pkg/auth` is intended for resource servers that consume tokens; it has
no signing, key-loading, or HTTP-server logic and is safe to depend on
without pulling in the issuer-side machinery.
