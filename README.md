# service-authenticatoor

An HTTP service that issues short-lived RS256 JWTs to users authenticated
by an upstream reverse-proxy SSO. The matching public keys are published
as a JWKS so any resource server can validate the issued tokens locally —
no shared secrets, no per-service SSO configuration.

## What it does

Behind the upstream proxy (`/auth/*`):

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

Public (no upstream auth — reachable by JWKS verifiers and browser JS):

- `GET /jwks.json` — RS256 public keys.
- `GET /.well-known/openid-configuration` — minimal OIDC discovery doc.
- `GET /client.js` — drop-in browser client library. Exposes
  `window.ethpandaops.authenticatoor.{checkLogin, login, logout,
  getToken, isLoggedIn}`. Auth service URL is templated in at serve time.
- `GET /healthz` — liveness probe.
- `GET /` — landing page.

## Browser integration

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

For local development without an upstream SSO:

```yaml
cloudflareAccess:
  verifyJWT: false
```

The service will warn that CF JWT verification is disabled and trust the
`Cf-Access-Authenticated-User-Email` header. Don't do this in production.

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

## Repo layout

```
cmd/authenticatoor/   entrypoint
pkg/auth/             verifier library: claims, JWKS verifier, middleware, scope matcher
pkg/issuer/           issuer-side: RSA keys, RS256 signing, JWKS marshaling
pkg/cors/             CORS middleware with strict allow-list
pkg/cfaccess/         Cf-Access-Jwt-Assertion verification
pkg/config/           YAML + env config loader, derivation, validation
pkg/server/           HTTP server: routes, handlers, lifecycle
Dockerfile            multi-stage source build
Dockerfile-stub       packages a pre-built binary into a distroless image (used by CI)
config.example.yaml   annotated example config
docs/                 config reference
```

`pkg/auth` is intended for resource servers that consume tokens; it has
no signing, key-loading, or HTTP-server logic and is safe to depend on
without pulling in the issuer-side machinery.
