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
| `cloudflareAccess.audTag`          | `AUTHENTICATOOR_CLOUDFLAREACCESS_AUDTAG`         |
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
| `userHeader`                           | string      | `Cf-Access-Authenticated-User-Email` | Header carrying authenticated user's email.                           |
| `allowedReturnHosts`                   | string list | `["*.<parent zone>"]`                | Hosts allowed in `/auth/login?return_to=…`.                           |
| `cors.allowedOrigins`                  | string list | = `allowedReturnHosts`               | Browsers allowed to call `/auth/*` with credentials.                  |
| `cloudflareAccess.verifyJWT`           | bool        | `true`                               | Verify `Cf-Access-Jwt-Assertion` against CF JWKS.                     |
| `cloudflareAccess.teamDomain`          | string      | (required when `verifyJWT`)          | e.g. `<team>.cloudflareaccess.com`.                                   |
| `cloudflareAccess.audTag`              | string      | `""`                                 | AUD tag of the CF Access application. When empty the audience claim is not checked — signature + issuer still pin the assertion to the team. |
| `cloudflareAccess.jwtHeader`           | string      | `Cf-Access-Jwt-Assertion`            |                                                                       |
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
