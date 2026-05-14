# Configuration reference

`authenticatoor` reads its configuration from a YAML file (path supplied via
`--config`) and applies environment-variable overrides on top.

## Environment variables

Every field can be overridden by an env var of the form
`AUTHENTICATOOR_<UPPER_DOTTED_PATH>`, where dots in the path are replaced by
underscores. For example:

| YAML path                          | Env var                                          |
| ---------------------------------- | ------------------------------------------------ |
| `listen`                           | `AUTHENTICATOOR_LISTEN`                          |
| `issuer`                           | `AUTHENTICATOOR_ISSUER`                          |
| `tokenTTL`                         | `AUTHENTICATOOR_TOKENTTL`                        |
| `authMode`                         | `AUTHENTICATOOR_AUTHMODE`                        |
| `cloudflareAccess.audTag`          | `AUTHENTICATOOR_CLOUDFLAREACCESS_AUDTAG`         |
| `githubOAuth.clientSecret`         | `AUTHENTICATOOR_GITHUBOAUTH_CLIENTSECRET`        |
| `signing.rs256.privateKeyFile`     | `AUTHENTICATOOR_SIGNING_RS256_PRIVATEKEYFILE`    |
| `metrics.enabled`                  | `AUTHENTICATOOR_METRICS_ENABLED`                 |

This is convenient for putting secrets/paths into Kubernetes Secrets and
non-sensitive values into ConfigMaps.

## Minimal config

```yaml
issuer: "https://auth.example.com"

signing:
  rs256:
    privateKeyFile: "/etc/authenticatoor/keys/private.pem"

cloudflareAccess:
  teamDomain: "<team>.cloudflareaccess.com"
  audTag: "<from CF Access app config>"
```

Everything else is derived from the issuer URL (audience, scope, return-host
allow-list, CORS origins) or covered by sensible defaults.

## Full reference

| Field                                  | Type        | Default                              | Notes                                                                 |
| -------------------------------------- | ----------- | ------------------------------------ | --------------------------------------------------------------------- |
| `listen`                               | string      | `:8080`                              | Bind address.                                                         |
| `issuer`                               | string      | (required)                           | Canonical URL; used as JWT `iss`.                                     |
| `externalURL`                          | string      | = `issuer`                           | Used in OIDC discovery + `jwks_uri`.                                  |
| `audience`                             | string list | parent zone of `issuer` host         | JWT `aud`.                                                            |
| `scopePattern`                         | string      | `*.<parent zone>`                    | JWT `scope` (host wildcard).                                          |
| `tokenTTL`                             | duration    | `30m`                                | JWT lifetime.                                                         |
| `authMode`                             | string      | `cloudflare`                         | `cloudflare`, `basic`, `any`, or `github`. See **Protection modes** below. |
| `userHeader`                           | string      | `Cf-Access-Authenticated-User-Email` | **Deprecated** alias for `cloudflareAccess.userHeader`. Folded in by Load when the new field is empty; emits a startup warning when both are set. |
| `allowedReturnHosts`                   | string list | `["*.<parent zone>"]`                | Hosts allowed in `/auth/login?return_to=…`.                           |
| `cors.allowedOrigins`                  | string list | = `allowedReturnHosts`               | Browsers allowed to call `/auth/*` with credentials.                  |
| `cloudflareAccess.verifyJWT`           | bool        | `true`                               | Verify `Cf-Access-Jwt-Assertion` against CF JWKS.                     |
| `cloudflareAccess.teamDomain`          | string      | (required when `verifyJWT`)          | e.g. `<team>.cloudflareaccess.com`.                                   |
| `cloudflareAccess.audTag`              | string      | `""`                                 | AUD tag of the CF Access application. When empty the audience claim is not checked — signature + issuer still pin the assertion to the team. |
| `cloudflareAccess.jwtHeader`           | string      | `Cf-Access-Jwt-Assertion`            |                                                                       |
| `cloudflareAccess.userHeader`          | string      | `Cf-Access-Authenticated-User-Email` | Header carrying the authenticated email. Replaces top-level `userHeader`. |
| `basicAuth.htpasswdFile`               | string      | (required for `basic`)               | Path to the htpasswd password file.                                   |
| `basicAuth.realm`                      | string      | `authenticatoor`                     | Sent in `WWW-Authenticate: Basic realm="…"`.                          |
| `anyAuth.cookieName`                   | string      | `authenticatoor_anyauth_user`        | Cookie holding the chosen username for the dev-only any-auth provider. |
| `anyAuth.loginPath`                    | string      | `/auth/anyauth/login`                | Path of the dev-login form (GET to render, POST to submit).           |
| `anyAuth.cookieTTL`                    | duration    | `12h`                                | Cookie lifetime for the dev-only any-auth provider.                   |
| `githubOAuth.clientId`                 | string      | (required for `github`)              | OAuth app client ID.                                                  |
| `githubOAuth.clientSecret`             | string      | (required for `github`)              | OAuth app client secret. Inline alternative to `clientSecretFile`.    |
| `githubOAuth.clientSecretFile`         | string      |                                      | File path holding the OAuth app secret.                               |
| `githubOAuth.sessionSecret`            | string      | (required for `github`)              | HMAC secret signing the session cookie. ≥16 bytes. Inline alternative. |
| `githubOAuth.sessionSecretFile`        | string      |                                      | File path holding the HMAC secret.                                    |
| `githubOAuth.callbackPath`             | string      | `/auth/oauth/callback`               | Must match the redirect URI registered with the GitHub OAuth app.    |
| `githubOAuth.sessionCookieName`        | string      | `authenticatoor_session`             | Browser cookie name for the session.                                  |
| `githubOAuth.stateCookieName`          | string      | `authenticatoor_oauth_state`         | Browser cookie name for the OAuth CSRF state.                         |
| `githubOAuth.sessionTTL`               | duration    | `12h`                                | Session cookie lifetime.                                              |
| `githubOAuth.allowedOrgs`              | string list | (required for `github`)              | GitHub orgs whose members may authenticate. Case-insensitive.         |
| `signing.mode`                         | string      | `rs256`                              | Only `rs256` is supported.                                            |
| `signing.rs256.privateKeyFile`         | string      | (required)                           | PEM-encoded RSA-2048+ private key (PKCS#1 or PKCS#8).                 |
| `signing.rs256.keyId`                  | string      | hash of public key                   | `kid` put in JWT header.                                              |
| `signing.rs256.generateIfMissing`      | bool        | `false`                              | Dev only: generate a new key if the file is absent.                   |
| `signing.rs256.previousKeys[].keyId`   | string      |                                      | During rotation, kid of an old public key.                            |
| `signing.rs256.previousKeys[].publicKeyFile` | string |                                    | PEM file with the old public key (private half is no longer needed). |
| `logging.level`                        | string      | `info`                               | `debug`, `info`, `warn`, `error`.                                     |
| `logging.format`                       | string      | `text`                               | `text` or `json`.                                                     |
| `metrics.enabled`                      | bool        | `false`                              | Expose `/metrics` on a separate port.                                 |
| `metrics.listen`                       | string      | `:9090`                              | Bind address for the metrics server.                                  |

## Protection modes

`authMode` selects the active protection provider. Exactly one provider
gates `/auth/*` per process. The defaults preserve the original Cloudflare
Access behavior.

### `cloudflare` (default)

A reverse-proxy SSO sits in front of the service. The provider trusts the
proxy's user-email header and (when `verifyJWT: true`) verifies the
proxy's signed assertion against Cloudflare's JWKS. There is no
service-side login UI — Cloudflare's login page handles unauthenticated
users before they ever reach this service. Logout 302s to
`/cdn-cgi/access/logout`, which the CF edge intercepts on the protected
origin to clear the local `CF_Authorization` cookie.

```yaml
authMode: cloudflare
cloudflareAccess:
  verifyJWT: true
  teamDomain: "<team>.cloudflareaccess.com"
  audTag: "<from CF Access app config>"
```

### `basic`

HTTP Basic auth backed by an htpasswd file. Self-contained — no upstream
proxy required. The browser handles the credential dialog and caches
credentials per (origin, realm) until the tab closes. Hot-reload of the
htpasswd file is not currently supported; redeploy on change.

```yaml
authMode: basic
basicAuth:
  htpasswdFile: "/etc/authenticatoor/htpasswd"
  realm: "authenticatoor"
```

### `any`

**Development only.** Unauthenticated `/auth/*` requests are redirected
to a small login form (`/auth/anyauth/login` by default) where the user
types any username. That username is stored in a plain, HttpOnly cookie
and reused as the identity until the cookie is cleared via `POST
/auth/logout` — handy for switching between identities while iterating
locally. Logs a loud warning at startup.

```yaml
authMode: any
# All anyAuth fields are optional; defaults are fine for local dev.
# anyAuth:
#   cookieName: "authenticatoor_anyauth_user"
#   loginPath:  "/auth/anyauth/login"
#   cookieTTL:  "12h"
```

### `github`

GitHub OAuth with organization-membership gating. The provider issues a
signed session cookie after the user authenticates with GitHub and is
confirmed to be a member of one of the configured `allowedOrgs`. The JWT
emitted to downstream services has the GitHub login as `sub` and the
primary verified email as `email`.

The OAuth callback is registered at `githubOAuth.callbackPath` (default
`/auth/oauth/callback`); this must match the redirect URI registered in
the GitHub OAuth app.

```yaml
authMode: github
githubOAuth:
  clientId: "Iv1.…"
  clientSecretFile: "/etc/authenticatoor/gh-secret"
  sessionSecretFile: "/etc/authenticatoor/session-secret"
  allowedOrgs:
    - "ethpandaops"
```

For Kubernetes deployments, mount `clientSecretFile` and
`sessionSecretFile` from a Secret. For ad-hoc deployments, the `Inline`
variants (`clientSecret`, `sessionSecret`) accept the value directly via
env var, e.g. `AUTHENTICATOOR_GITHUBOAUTH_CLIENTSECRET=…`.

### Logout (`/auth/logout`)

Always reachable, regardless of authentication state. Per-provider
behavior:

- **cloudflare**: 302 to `/cdn-cgi/access/logout`. CF Access intercepts that path on the protected origin and clears the `CF_Authorization` cookie.
- **any**: clears the username cookie (`authenticatoor_anyauth_user` by default). The next `/auth/*` request redirects back to the login form.
- **github**: clears the session cookie. The next `/auth/*` request kicks off a fresh OAuth round-trip.
- **basic**: 200 with a "close the tab" hint. HTTP Basic credentials are cached by the browser and the server has no reliable way to invalidate them — deliberately no `WWW-Authenticate` challenge so the iframe-based client logout doesn't pop a credential dialog.

The bundled `client.js` calls `/auth/logout` from `logout()` via a hidden
iframe after clearing local sessionStorage; the iframe follows any
redirect (e.g. CF Access logout) so the upstream session is invalidated
without a visible navigation.

## Wildcards

`scopePattern`, `allowedReturnHosts`, and `cors.allowedOrigins` use the same
DNS-label glob syntax:

- `foo.bar` matches only `foo.bar`.
- `*.foo.bar` matches `x.foo.bar`, `y.foo.bar`, `x.y.foo.bar` — but **not**
  `foo.bar` (the leading `*` requires at least one label) and not
  `evil-foo.bar` (label boundaries are enforced).
- Partial wildcards (`foo*.bar`) and middle/trailing wildcards (`a.*.b`,
  `a.b.*`) are deliberately not supported — they invite footguns.

## Key rotation

To rotate the active signing key without downtime:

1. Add the **current** key's public half to `signing.rs256.previousKeys` and
   redeploy. The JWKS now lists both keys; verifiers continue to validate
   the still-active old kid.
2. Replace `signing.rs256.privateKeyFile` (and optionally `keyId`) with the
   new key, redeploy. New tokens are signed with the new kid; old tokens
   still validate against the previous public key.
3. After at least `tokenTTL + clock-skew-margin` (e.g. one hour for a 30
   minute TTL), drop the old entry from `previousKeys` and redeploy.

## Observability

When `metrics.enabled: true`, the service exposes a Prometheus endpoint at
`<metrics.listen>/metrics`. Counters published:

- `authenticatoor_tokens_issued_total`
- `authenticatoor_token_issue_errors_total{reason}`
- `authenticatoor_login_redirects_total`
- `authenticatoor_jwks_serves_total`

Each `/auth/token` issuance also produces a structured log line
(`msg="issued token" email=… jti=…`). The access log line for every
request explicitly omits the `Authorization` and `Location` headers — the
latter to avoid leaking tokens carried in the URL fragment of `/auth/login`
redirects.
