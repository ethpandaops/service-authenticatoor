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
| `authMode`                             | string      | `cloudflare`                         | `cloudflare`, `basic`, `any`, `github`, or `oidc`. See **Protection modes** below. |
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
| `githubOAuth.callbackPath`             | string      | `/auth/oauth/callback`               | Must match the redirect URI registered with the GitHub OAuth app.    |
| `githubOAuth.sessionCookieName`        | string      | `authenticatoor_session`             | Browser cookie name for the session.                                  |
| `githubOAuth.stateCookieName`          | string      | `authenticatoor_oauth_state`         | Browser cookie name for the OAuth CSRF state.                         |
| `githubOAuth.sessionTTL`               | duration    | `12h`                                | Session cookie lifetime.                                              |
| `githubOAuth.allowedOrgs`              | string list | (required for `github`)              | GitHub orgs whose members may authenticate. Case-insensitive.         |
| `oidc.issuerURL`                       | string      | (required for `oidc`)                | IdP issuer URL. Discovery doc fetched from `<issuerURL>/.well-known/openid-configuration` at startup. |
| `oidc.callbackURL`                     | string      | (required for `oidc`)                | Absolute callback URL registered at the IdP as this client's `redirect_uri`. Use the shared relay URL for relay-fronted deployments, or `<externalURL>/auth/oidc/callback` for direct ones. |
| `oidc.clientId`                        | string      | (required for `oidc`)                | OAuth client_id registered at the IdP.                                |
| `oidc.clientSecret`                    | string      | (required for `oidc`)                | OAuth client secret. Inline alternative to `clientSecretFile`.        |
| `oidc.clientSecretFile`                | string      |                                      | File path holding the OAuth client secret.                            |
| `oidc.callbackPath`                    | string      | `/auth/oidc/callback`                | Local path the relay forwards the callback to.                        |
| `oidc.sessionCookieName`               | string      | `authenticatoor_oidc_session`        | Browser cookie name for the session.                                  |
| `oidc.stateCookieName`                 | string      | `authenticatoor_oidc_state`          | Browser cookie name for the OAuth CSRF / OIDC nonce state.            |
| `oidc.sessionTTL`                      | duration    | `12h`                                | Session cookie lifetime.                                              |
| `oidc.allowedGroups`                   | string list | `[]` (inherit IdP gating)            | Groups (as emitted by the IdP) whose members may authenticate. For dex's GitHub connector each group is `<org>` or `<org>:<team>`. Case-insensitive. A bare `<org>` entry matches both `<org>` and any `<org>:<team>` (useful because dex emits `<org>:<team>` for orgs even without a `teams:` filter). An `<org>:<team>` entry matches that exact team only. Empty list = trust the IdP's own gating. |
| `oidc.scopes`                          | string list | `[openid, email, groups]`            | OIDC scopes requested. `openid` is required.                          |
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
  allowedOrgs:
    - "ethpandaops"
```

For Kubernetes deployments, mount `clientSecretFile` from a Secret. For
ad-hoc deployments, the `clientSecret` inline variant accepts the value
directly via env var, e.g. `AUTHENTICATOOR_GITHUBOAUTH_CLIENTSECRET=…`.

The session-cookie HMAC key is derived from the JWT signing key (see
`issuer.DeriveHMACKey`) — no separate session secret to manage. Rotating
the signing key invalidates active sessions.

### `oidc`

Standard OIDC against any IdP (designed against the ethpandaops central
dex but works against Google, Keycloak, etc.). Group membership gating is
done against the `groups` claim in the id_token — for dex's GitHub
connector that's the user's GitHub org list (and `<org>:<team>` entries
when teams are configured in the dex connector).

Unlike the `github` mode, every authenticatoor instance shares **one**
confidential client at the IdP. To avoid registering a per-instance
redirect URI with the IdP, the redirect target is a stateless
**callback relay** (see `platform/applications/oidc-relay`) that
forwards each callback to the originating authenticatoor based on the
host encoded in the OAuth `state` parameter. The state contract:

```
state = "<our-public-url>~<base64url-signed-blob>"
```

where `<our-public-url>` is this instance's `externalURL` (the relay's
regex constrains it to `*.ethpandaops.io` / `localhost` / `127.0.0.1`)
and the signed blob is HMAC-signed against a key derived from the JWT
signing key. The relay never inspects the signed blob — only the
originating instance can verify it.

The provider also works **without** a relay: register
`<externalURL>/auth/oidc/callback` directly at the IdP as the
`redirect_uri` and set `oidc.callbackURL` to the same value.

```yaml
authMode: oidc
externalURL: "https://auth.<devnet>.ethpandaops.io"
oidc:
  issuerURL: "https://dex.primary.production.platform.ethpandaops.io"
  callbackURL: "https://oidc-relay.primary.production.platform.ethpandaops.io/oidc/callback"
  clientId: "authenticatoor"
  clientSecretFile: "/etc/authenticatoor/oidc-client-secret"
  allowedGroups:
    - "ethpandaops"
    - "EthDevOpsAccess:validatorops"
    - "sigp"
    # ...
```

Per-instance setup is purely on the authenticatoor side: the IdP and
relay are deployed once globally; new devnet authenticatoors just need
their own `externalURL`, `clientSecret` mount, and `allowedGroups`.

For Kubernetes, mount the client secret from a Kubernetes Secret. The
inline `oidc.clientSecret` variant works for ad-hoc deployments via
`AUTHENTICATOOR_OIDC_CLIENTSECRET=…`. The session HMAC key is derived
from the JWT signing key — no separate session secret to configure.

### Logout (`/auth/logout`)

Always reachable, regardless of authentication state. Per-provider
behavior:

- **cloudflare**: 302 to `/cdn-cgi/access/logout`. CF Access intercepts that path on the protected origin and clears the `CF_Authorization` cookie.
- **any**: clears the username cookie (`authenticatoor_anyauth_user` by default). The next `/auth/*` request redirects back to the login form.
- **github**: clears the session cookie. The next `/auth/*` request kicks off a fresh OAuth round-trip.
- **oidc**: clears the session cookie. The next `/auth/*` request kicks off a fresh OIDC round-trip via dex. The IdP session is left intact (dex 2.x has no robust RP-initiated logout).
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
