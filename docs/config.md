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

providers:
  - name: cfaccess
    type: cloudflare
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
| `authMode`                             | string \| string list | all defined providers      | Provider(s) *advertised* to unauthenticated users, referenced by instance name. One entry → direct login redirect; several → `/login` selection page (in this order). All defined providers stay enabled regardless — unlisted ones just aren't offered. With an empty `providers` list, entries name provider *types* whose legacy top-level blocks are converted. Env override accepts a comma-separated value. |
| `providers`                            | list        | converted from legacy blocks         | Canonical provider instance definitions. See **Protection providers** below. |
| `providers[].name`                     | string      | (required)                           | Instance name; doubles as the path prefix (`/<name>/login`, …), the selector-page label, and the reference key in `authMode`. Unique, `[a-z0-9-]`. |
| `providers[].type`                     | string      | (required)                           | Provider implementation: `cloudflare`, `basic`, `any`, `github`, or `oidc`. |
| `devMode`                              | bool        | `false`                              | Serve client scripts unminified for local development (no source maps generated). |
| `userHeader`                           | string      | `Cf-Access-Authenticated-User-Email` | **Deprecated** alias for `cloudflareAccess.userHeader`. Folded in by Load when the new field is empty; emits a startup warning when both are set. |
| `allowedReturnHosts`                   | string list | `["*.<parent zone>"]`                | Hosts allowed in `/auth/login?return_to=…`.                           |
| `cors.allowedOrigins`                  | string list | = `allowedReturnHosts`               | Browsers allowed to call `/auth/*` with credentials.                  |
| `cloudflareAccess.verifyJWT`           | bool        | `true`                               | Verify `Cf-Access-Jwt-Assertion` against CF JWKS.                     |
| `cloudflareAccess.teamDomain`          | string      | (required when `verifyJWT`)          | e.g. `<team>.cloudflareaccess.com`.                                   |
| `cloudflareAccess.audTag`              | string      | `""`                                 | AUD tag of the CF Access application. When empty the audience claim is not checked — signature + issuer still pin the assertion to the team. |
| `cloudflareAccess.jwtHeader`           | string      | `Cf-Access-Jwt-Assertion`            |                                                                       |
| `cloudflareAccess.userHeader`          | string      | `Cf-Access-Authenticated-User-Email` | Header carrying the authenticated email. Replaces top-level `userHeader`. |
| `cloudflareAccess.allowServiceTokens`  | bool        | `true`                               | Allow non-identity CF Access service tokens, using the token's `common_name` (client ID) as the identity subject. Still gated by the app's CF Access policy. Requires `verifyJWT`. |
| `cloudflareAccess.sessionCookieName`   | string      | `authenticatoor_<name>_session`      | Browser cookie name for login-path sessions. |
| `cloudflareAccess.sessionTTL`          | duration    | `12h`                                | Lifetime of login-path sessions; the CF Access policy is only re-checked on expiry. |
| `basicAuth.htpasswdFile`               | string      | (required for `basic`)               | Path to the htpasswd password file.                                   |
| `basicAuth.realm`                      | string      | `authenticatoor`                     | Sent in `WWW-Authenticate: Basic realm="…"`.                          |
| `basicAuth.sessionCookieName`          | string      | `authenticatoor_<name>_session`      | Browser cookie name for login-path sessions. |
| `basicAuth.sessionTTL`                 | duration    | `12h`                                | Lifetime of login-path sessions. |
| `anyAuth.cookieName`                   | string      | `authenticatoor_anyauth_user`        | Cookie holding the chosen username for the dev-only any-auth provider. |
| `anyAuth.cookieTTL`                    | duration    | `12h`                                | Cookie lifetime for the dev-only any-auth provider.                   |
| `githubOAuth.clientId`                 | string      | (required for `github`)              | OAuth app client ID.                                                  |
| `githubOAuth.clientSecret`             | string      | (required for `github`)              | OAuth app client secret. Inline alternative to `clientSecretFile`.    |
| `githubOAuth.clientSecretFile`         | string      |                                      | File path holding the OAuth app secret.                               |
| `githubOAuth.callbackPath`             | string      | `/<name>/callback`                   | Must match the redirect URI registered with the GitHub OAuth app.    |
| `githubOAuth.sessionCookieName`        | string      | `authenticatoor_<name>_session`      | Browser cookie name for the session.                                  |
| `githubOAuth.stateCookieName`          | string      | `authenticatoor_<name>_state`        | Browser cookie name for the OAuth CSRF state.                         |
| `githubOAuth.sessionTTL`               | duration    | `12h`                                | Session cookie lifetime.                                              |
| `githubOAuth.allowedOrgs`              | string list | (required for `github`)              | GitHub orgs whose members may authenticate. Case-insensitive.         |
| `oidc.issuerURL`                       | string      | (required for `oidc`)                | IdP issuer URL. Discovery doc fetched from `<issuerURL>/.well-known/openid-configuration` at startup. |
| `oidc.callbackURL`                     | string      | (required for `oidc`)                | Absolute callback URL registered at the IdP as this client's `redirect_uri`. Use the shared relay URL for relay-fronted deployments, or `<externalURL>/oidc/callback` for direct ones. |
| `oidc.clientId`                        | string      | (required for `oidc`)                | OAuth client_id registered at the IdP.                                |
| `oidc.clientSecret`                    | string      | (required for `oidc`)                | OAuth client secret. Inline alternative to `clientSecretFile`.        |
| `oidc.clientSecretFile`                | string      |                                      | File path holding the OAuth client secret.                            |
| `oidc.callbackPath`                    | string      | `/<name>/callback`                   | Local path the relay forwards the callback to.                        |
| `oidc.sessionCookieName`               | string      | `authenticatoor_<name>_session`      | Browser cookie name for the session.                                  |
| `oidc.stateCookieName`                 | string      | `authenticatoor_<name>_state`        | Browser cookie name for the OAuth CSRF / OIDC nonce state.            |
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

## Protection providers

Providers gate `/auth/*`. The `providers` list defines the instances —
all of them enabled: on each `/auth/*` request every defined provider
passively inspects the credentials already present — a session cookie,
ambient Cloudflare Access headers, a Basic `Authorization` header — and
the first match wins. No provider ever starts a login flow from
`/auth/*` itself.

`authMode` (a string or a list of instance names) controls what is
*advertised* to unauthenticated users: one entry sends them straight
into that provider's login flow, several entries send them to the
`/login` selection page listing exactly those providers. Providers left
out of `authMode` keep authenticating and their `/<name>/login` routes
stay reachable — they just aren't offered. Useful for machine-only or
soft-launched providers.

Legacy compatibility: when `providers` is empty, each `authMode` entry
names a provider *type* (`cloudflare`, `basic`, `any`, `github`, `oidc`)
and the matching legacy top-level block (`cloudflareAccess:`, …) is
converted into a provider entry, named after the type (cloudflare→
`cfaccess`, basic→`htpasswd`, any→`anyauth`, github→`github`,
oidc→`oidc`) — an old `authMode: cloudflare` config keeps working
bit-for-bit. Prefer the `providers` list for new configs.

Interactive login lives under each provider's own path prefix, derived
from the entry's (required) `name`:

| Route              | Providers          | Purpose                                              |
| ------------------ | ------------------ | ---------------------------------------------------- |
| `/<name>/login`    | all                | Login entry: authenticates, mints a signed session cookie, redirects back via `return_to`. |
| `/<name>/callback` | `github`, `oidc`   | OAuth/OIDC callback.                                 |
| `/<name>/token`    | `cloudflare`       | Machine token alias: `/auth/token` contract, authenticated purely from ambient CF headers (service tokens; never redirects). |
| `/login`           | server             | Provider selector listing the `authMode` entries. Redirects straight to the login entry when only one provider is advertised. |

When no provider authenticates a request, an instance advertising a
single provider applies that provider's own fallback (redirect to its
login entry, or the Basic challenge); with several advertised providers
the request 302s to the `/login` selection page.

`/auth/*` itself needs **no edge protection** in this model. For the
`cloudflare` type, only the `/cfaccess/*` prefix has to be covered by the
CF Access application; an edge that (still) covers `/auth/*` keeps
working unchanged, because the ambient headers authenticate before any
redirect happens. That makes migration a pure Cloudflare-side change:
narrow the CF Access app from the whole host (or `/auth/*`) down to
`/cfaccess/*`, no service redeploy needed.

Session cookies are HMAC-signed with a per-provider key derived from the
JWT signing key — no separate session secret to manage, and one
provider's cookie cannot be replayed as another's. Rotating the signing
key invalidates all active sessions.

```yaml
# Multi-provider example: CF Access for the edge-protected path plus a
# second OIDC IdP; both advertised, so unauthenticated users pick one
# on /login.
authMode: [cfaccess, oidc]
providers:
  - name: cfaccess
    type: cloudflare
    cloudflareAccess:
      teamDomain: "<team>.cloudflareaccess.com"
  - name: oidc
    type: oidc
    oidc:
      issuerURL: "https://dex.primary.production.platform.ethpandaops.io"
      callbackURL: "https://oidc-relay.primary.production.platform.ethpandaops.io/oidc/callback"
      clientId: "authenticatoor"
      clientSecretFile: "/etc/authenticatoor/oidc-client-secret"
      allowedGroups: ["ethpandaops"]
```

### `cloudflare` (default)

Cloudflare Access authenticates the user at the edge and forwards the
identity as request headers. The provider trusts the user-email header
and (when `verifyJWT: true`) verifies the signed assertion against
Cloudflare's JWKS. Two topologies:

- **Edge covers `/auth/*`** (the original deployment): every request
  arrives with CF headers and authenticates ambiently. The login path is
  never used.
- **Edge covers `/cfaccess/*` only**: `/auth/*` is publicly reachable;
  unauthenticated browsers are redirected to `/cfaccess/login`, which
  sits behind CF Access, converts the ambient identity into a session
  cookie, and bounces back. Machines holding CF Access service tokens
  call `/cfaccess/token` (same JSON contract as `/auth/token`) on the
  protected prefix.

Logout 302s to `/cdn-cgi/access/logout`, which the CF edge intercepts on
the protected origin to clear the local `CF_Authorization` cookie.

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
credentials per (origin, realm) until the tab closes. An `Authorization`
header on `/auth/*` authenticates directly; the `/htpasswd/login` entry
additionally converts valid credentials into a session cookie (needed
when several providers share the instance, since `/auth/*` can only
challenge for one realm). Hot-reload of the htpasswd file is not
currently supported; redeploy on change.

```yaml
authMode: basic
basicAuth:
  htpasswdFile: "/etc/authenticatoor/htpasswd"
  realm: "authenticatoor"
```

### `any`

**Development only.** Unauthenticated `/auth/*` requests are redirected
to a small login form (`/anyauth/login` by default) where the user
types any username. That username is stored in a plain, HttpOnly cookie
and reused as the identity until the cookie is cleared via `POST
/auth/logout` — handy for switching between identities while iterating
locally. Logs a loud warning at startup.

```yaml
authMode: any
# All anyAuth fields are optional; defaults are fine for local dev.
# anyAuth:
#   cookieName: "authenticatoor_anyauth_user"
#   cookieTTL:  "12h"
```

### `github`

GitHub OAuth with organization-membership gating. The provider issues a
signed session cookie after the user authenticates with GitHub and is
confirmed to be a member of one of the configured `allowedOrgs`. The JWT
emitted to downstream services has the GitHub login as `sub` and the
primary verified email as `email`.

The OAuth callback is registered at `githubOAuth.callbackPath` (default
`/github/callback`); this must match the redirect URI registered in
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
`<externalURL>/oidc/callback` directly at the IdP as the
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

Always reachable, regardless of authentication state. With multiple
providers configured, logout clears every provider's session cookie in
one JSON response. With a single provider, its specific behavior applies:

- **cloudflare**: clears the local session cookie and 302s to `/cdn-cgi/access/logout`. CF Access intercepts that path on the protected origin and clears the `CF_Authorization` cookie.
- **any**: clears the username cookie (`authenticatoor_anyauth_user` by default). The next `/auth/*` request redirects back to the login form.
- **github**: clears the session cookie. The next `/auth/*` request kicks off a fresh OAuth round-trip.
- **oidc**: clears the session cookie. The next `/auth/*` request kicks off a fresh OIDC round-trip via dex. The IdP session is left intact (dex 2.x has no robust RP-initiated logout).
- **basic**: clears the session cookie; cached HTTP Basic credentials may re-authenticate ambiently until the tab closes (the server has no reliable way to invalidate the browser cache) — deliberately no `WWW-Authenticate` challenge so the iframe-based client logout doesn't pop a credential dialog.

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
