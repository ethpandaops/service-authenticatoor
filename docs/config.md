# Configuration reference

`authenticatoor` reads its configuration from a YAML file (path supplied via
`--config`) and applies environment-variable overrides on top.

## Environment variables

A setting with a fixed path can be overridden by an env var of the form
`AUTHENTICATOOR_<UPPER_DOTTED_PATH>`, where dots in the path are replaced by
underscores. For example:

| YAML path                          | Env var                                          |
| ---------------------------------- | ------------------------------------------------ |
| `listen`                           | `AUTHENTICATOOR_LISTEN`                          |
| `issuer`                           | `AUTHENTICATOOR_ISSUER`                          |
| `tokenTTL`                         | `AUTHENTICATOOR_TOKENTTL`                        |
| `authMode`                         | `AUTHENTICATOOR_AUTHMODE`                        |
| `cloudflareAccess.audTag`          | `AUTHENTICATOOR_CLOUDFLAREACCESS_AUDTAG`         |
| `oidc.trustUnverifiedEmail`        | `AUTHENTICATOOR_OIDC_TRUSTUNVERIFIEDEMAIL`       |
| `githubOAuth.clientSecret`         | `AUTHENTICATOOR_GITHUBOAUTH_CLIENTSECRET`        |
| `signing.rs256.privateKeyFile`     | `AUTHENTICATOOR_SIGNING_RS256_PRIVATEKEYFILE`    |
| `metrics.enabled`                  | `AUTHENTICATOOR_METRICS_ENABLED`                 |

This is convenient for putting secrets/paths into Kubernetes Secrets and
non-sensitive values into ConfigMaps.

Every setting of the **Full reference** below has such a variable, and
it is honoured whether or not the file mentions the key — with these
exceptions, which are read from the file only:

- the entries of `providers` (`providers[]…`), of `teamRules` and of
  `signing.rs256.previousKeys`: lists of structured entries;
- the whole `grants` section. An `AUTHENTICATOOR_GRANTS…` variable is a
  startup error rather than ignored — with no `grants` in the file the
  instance would otherwise run without any, although its operator
  configured some.

List settings take a comma-separated value
(`AUTHENTICATOOR_AUDIENCE=a.example,b.example`).

The variables of the provider blocks (`AUTHENTICATOOR_CLOUDFLAREACCESS_…`,
`AUTHENTICATOOR_OIDC_…`, …) set the **legacy top-level blocks**. With a
`providers` list those blocks are not read, so such a variable changes
nothing; the service says so in a startup warning naming the variable.
Entries of the `providers` list are configured in the file.

The config file is one YAML document (JSON, being YAML, works too). A
file with a second document (after a `---`) is a startup error: only
the first would be read.

## How the file is checked

Keys are read case-insensitively (`tokenTTL` and `tokenttl` are the same
setting). These mistakes, which would otherwise go unnoticed, are
caught at startup:

- **The same key in two spellings** — `Panda:` next to `panda:`,
  `grants:` next to `Grants:`, anywhere in the file — is an error that
  names both. (They would be merged, and which one wins would change
  from one start to the next.)
- **A key that was meant to be the grants section but is not** is an
  error. Ignored, it would leave every service open where they were
  meant to be restricted. What is recognised, ignoring case and the
  separators `_`, `-`, `.` and space:
  - at the top level, a **misspelling of `grants`**: a key at most two
    edits away from it, an edit being a dropped, added or replaced
    letter or two neighbouring letters swapped (`garnts`, `grnts`,
    `grabts`, `gratns`);
  - at the top level and nested under another key, a key that contains
    `grant`, starts with `teamserv`, or is `permission(s)`,
    `serviceaccess` or `teamaccess` (`grant:`, `teamService:`,
    `team_services:`, `serviceGrants:`, and `grants:` itself when it is
    not at the top level).

  Nothing else is: a section written under a name that has nothing to
  do with these (`acl:`, `access:`) is an unknown key like any other.
- **An unknown key inside the provider configuration** — in a
  `providers` entry, in a provider type block (`oidc:`, `cloudflareAccess:`,
  … also in the legacy top-level form, used or not), in a `teamRules`
  entry — or in a `grants` group is an error that names the key and the
  allowed ones. A dropped key there changes what the config means: a
  rule written with `prefx:` would be a rule without a prefix. The
  exception are the keys earlier versions knew and that are gone
  (`anyAuth.loginPath`, `githubOAuth.sessionSecret`,
  `githubOAuth.sessionSecretFile`): they are ignored with a deprecation
  warning, so a config that started before still starts.
- **A map where a list belongs, and the other way round.** `providers`,
  `teamRules`, `grants`, and the `members` and `services` of a group are
  lists; a provider type block and a `providers` entry are maps.
  Writing a single rule directly under `teamRules:` (without the `- `),
  or one entry under `providers:`, is an error — it would otherwise be
  taken as a list of one, and that one entry would escape the checks
  above. `providers:` or `teamRules:` without a value (every entry
  commented out) is an empty list; `grants:` without a value is an
  error (see **Service grants**).
- **Any other unknown top-level key** is reported in a warning, not an
  error: earlier versions ignored such keys, and a config that started
  then has to start now.

YAML anchors and merge keys (`<<: *base`) can be used anywhere. They are
resolved before the checks run, so a key, a rule or a grants group that
comes in through a merge is checked exactly like one written in place.

**Other file formats.** The checks above read the file as YAML. A config
file in another format that the loader understands (`.toml`, …) cannot
be checked at all. Such a file is accepted with a startup warning as
long as it configures no `teams`, no `teamRules` and no `grants` —
neither in the file nor through the environment; as soon as it does,
startup fails and asks for a YAML (or JSON) file.

Names that are data keep their spelling: the members of a `grants`
group and the keys of a team rule's `map` are taken exactly as written,
dots and capitals included. Team names written in the config
(`teams`, the lists in a rule `map`, a `team:` member of a grants
group) must be in their normal form; `Panda` is an error, not another
way to write `panda`.

## Upgrading

**Configs written for earlier versions load unchanged.** The legacy
forms stay valid: a single-string `authMode`, the top-level `userHeader`,
and the top-level `cloudflareAccess:` / `basicAuth:` / `anyAuth:` /
`githubOAuth:` / `oidc:` blocks without a `providers` list. A config
that uses none of the new settings (`teams`, `teamRules`, `grants`)
resolves to the same providers, paths and cookie names and yields tokens
with the same claims as before; the test suite loads the example config
and every documentation snippet of each release, and the config the
Helm chart renders, and compares the result with what the previous
version made of them. What changes for such a config:

1. **Everyone logs in again, once.** Session cookies of earlier versions
   are not accepted (see *Which sessions count* under Teams). For
   Cloudflare Access and cached Basic credentials this is invisible; for
   `oidc` and `github` it is a redirect through the IdP.
2. **`oidc`: an email counts only when the IdP marks it verified.**
   Earlier versions used the id_token's `email` as the identity
   whatever `email_verified` said. Now, when the token does not say
   `email_verified: true`, the user's token has the IdP's `sub` as its
   `sub` and no `email` claim. With an IdP that sends `false` or omits
   the claim, **the subject of every user changes with the upgrade** —
   tools that key anything on `sub` or `email` see new users. This is
   per login, not per provider: if an IdP sets the flag for some users
   and not for others, or flips it for one user between two logins,
   that user's subject alternates between the email and the IdP `sub`.
   Decide per provider:
   - leave it, and tell the service so with
     `oidc.trustUnverifiedEmail: false`;
   - or set `oidc.trustUnverifiedEmail: true` to get the earlier
     behaviour back — only for an IdP that verifies addresses itself
     and merely does not say so (see **Attributes** under Teams).

   Until the key is set either way, the service logs one warning per
   `oidc` provider at startup that explains this, and an info line at
   every login whose email was dropped.
3. **Unknown keys in the provider configuration are errors**, as are
   keys within two edits of `grants` at the top level and a map written
   where a list belongs (see *How the file is checked*). Earlier
   versions ignored all of them. A config with a misspelled key in a
   provider block therefore fails at startup, with a message naming the
   key; correct or remove it. Other unknown top-level keys only get a
   warning.

**Deprecated keys.** None of them stops the service; remove them when
convenient:

| Key                                                      | What happens                                                   |
| -------------------------------------------------------- | -------------------------------------------------------------- |
| top-level `userHeader`                                   | Still read, as an alias of `cloudflareAccess.userHeader`. A startup warning when both are set to different values (the top-level one is then ignored). |
| `anyAuth.loginPath`                                      | Ignored, with a startup warning: the login form is at `/<name>/login`. |
| `githubOAuth.sessionSecret`, `githubOAuth.sessionSecretFile` | Ignored, with a startup warning: the session key is derived from the signing key. |

**Cloudflare Access needs no `audTag`.** A `cloudflare` provider without
`audTag` keeps working as it did, also when it is given `teams` or
`teamRules` or is named in `grants`: it then accepts an assertion of any
Access application of the same Cloudflare team, and the service says so
in a startup warning. Set `audTag` to limit the door to one application
(see **Hardening** under Teams).

**When you start using the new settings**, write the config as YAML (or
JSON), and list team rules and providers as lists; the strict checks
described above exist for exactly these settings.

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
| `grants`                               | list of groups | (absent)                          | Service grants: which services, and which features of them, an identity may use (the token's `services` claim). Each group has `members` (`<provider>/team:<team>`, `<provider>/user:<id>`, `<provider>/<attribute>:<value>`), `services` (`svc`, `svc:feature…`, `svc:prefix*`, `svc:all`, `all`, `all:feature…`, `all:all`) and an optional `name`. Absent = no per-identity constraint. See **Service grants** below. |
| `devMode`                              | bool        | `false`                              | Serve client scripts unminified for local development (no source maps generated). |
| `userHeader`                           | string      | `Cf-Access-Authenticated-User-Email` | **Deprecated** alias for `cloudflareAccess.userHeader`. Folded in by Load when the new field is empty; emits a startup warning when both are set. |
| `allowedReturnHosts`                   | string list | `["*.<parent zone>"]`                | Hosts allowed in `/auth/login?return_to=…`.                           |
| `cors.allowedOrigins`                  | string list | = `allowedReturnHosts`               | Browsers allowed to call `/auth/*` with credentials.                  |
| `cloudflareAccess.verifyJWT`           | bool        | `true`                               | Verify `Cf-Access-Jwt-Assertion` against CF JWKS.                     |
| `cloudflareAccess.teamDomain`          | string      | (required when `verifyJWT`)          | e.g. `<team>.cloudflareaccess.com`.                                   |
| `cloudflareAccess.audTag`              | string      | `""` (detected)                      | AUD tag of the CF Access application. When set, assertions for any other application are rejected everywhere. When empty (and `verifyJWT` is on), the tag is detected from Cloudflare's login redirect for `/<name>/login` and enforced on `/<name>/login` and `/<name>/token`; those routes answer 503 until it is detected. `/auth/*` then checks signature + issuer only, pinning the assertion to the team but not the application — which a provider with `teams`, `teamRules` or `grants` members is warned about at startup. |
| `cloudflareAccess.jwtHeader`           | string      | `Cf-Access-Jwt-Assertion`            |                                                                       |
| `cloudflareAccess.userHeader`          | string      | `Cf-Access-Authenticated-User-Email` | Header carrying the authenticated email. Replaces top-level `userHeader`. |
| `cloudflareAccess.allowServiceTokens`  | bool        | `true`                               | Allow non-identity CF Access service tokens, using the token's `common_name` (client ID) as the identity subject. Still gated by the app's CF Access policy. Requires `verifyJWT`. |
| `cloudflareAccess.sessionCookieName`   | string      | `authenticatoor_<name>_session`      | Browser cookie name for login-path sessions. |
| `cloudflareAccess.sessionTTL`          | duration    | `12h`                                | Lifetime of login-path sessions; the CF Access policy is only re-checked on expiry. |
| `cloudflareAccess.teams`               | string list | `[]`                                 | Static teams put into the token's `teams` claim for every identity this provider authenticates — service tokens included. See **Teams** below. |
| `cloudflareAccess.teamRules`          | list        | `[]`                                 | Rules that turn the attributes this provider verified about the user into teams. See **Teams** below. |
| `basicAuth.htpasswdFile`               | string      | (required for `basic`)               | Path to the htpasswd password file.                                   |
| `basicAuth.realm`                      | string      | `authenticatoor`                     | Sent in `WWW-Authenticate: Basic realm="…"`.                          |
| `basicAuth.sessionCookieName`          | string      | `authenticatoor_<name>_session`      | Browser cookie name for login-path sessions. |
| `basicAuth.sessionTTL`                 | duration    | `12h`                                | Lifetime of login-path sessions. |
| `basicAuth.teams`                      | string list | `[]`                                 | Static teams put into the token's `teams` claim for every identity this provider authenticates. See **Teams** below. |
| `basicAuth.teamRules`                 | list        | `[]`                                 | Rules that turn the attributes this provider verified about the user into teams. See **Teams** below. |
| `anyAuth.cookieName`                   | string      | `authenticatoor_anyauth_user`        | Cookie holding the chosen username for the dev-only any-auth provider. |
| `anyAuth.cookieTTL`                    | duration    | `12h`                                | Cookie lifetime for the dev-only any-auth provider.                   |
| `anyAuth.teams`                        | string list | `[]`                                 | Static teams put into the token's `teams` claim for every identity this provider authenticates. See **Teams** below. |
| `anyAuth.teamRules`                   | list        | `[]`                                 | Rules that turn the attributes this provider verified about the user into teams. See **Teams** below. |
| `githubOAuth.clientId`                 | string      | (required for `github`)              | OAuth app client ID.                                                  |
| `githubOAuth.clientSecret`             | string      | (required for `github`)              | OAuth app client secret. Inline alternative to `clientSecretFile`.    |
| `githubOAuth.clientSecretFile`         | string      |                                      | File path holding the OAuth app secret.                               |
| `githubOAuth.callbackPath`             | string      | `/<name>/callback` (legacy block: `/auth/oauth/callback`) | Must match the redirect URI registered with the GitHub OAuth app.    |
| `githubOAuth.sessionCookieName`        | string      | `authenticatoor_<name>_session` (legacy block: `authenticatoor_session`) | Browser cookie name for the session.                                  |
| `githubOAuth.stateCookieName`          | string      | `authenticatoor_<name>_state` (legacy block: `authenticatoor_oauth_state`) | Browser cookie name for the OAuth CSRF state.                         |
| `githubOAuth.sessionTTL`               | duration    | `12h`                                | Session cookie lifetime.                                              |
| `githubOAuth.allowedOrgs`              | string list | (required for `github`)              | GitHub orgs whose members may authenticate. Case-insensitive.         |
| `githubOAuth.teams`                    | string list | `[]`                                 | Static teams put into the token's `teams` claim for every identity this provider authenticates. See **Teams** below. |
| `githubOAuth.teamRules`               | list        | `[]`                                 | Rules that turn the attributes this provider verified about the user into teams. See **Teams** below. |
| `oidc.issuerURL`                       | string      | (required for `oidc`)                | IdP issuer URL. Discovery doc fetched from `<issuerURL>/.well-known/openid-configuration` at startup. |
| `oidc.callbackURL`                     | string      | (required for `oidc`)                | Absolute callback URL registered at the IdP as this client's `redirect_uri`. Use the shared relay URL for relay-fronted deployments, or `<externalURL>/oidc/callback` for direct ones. |
| `oidc.clientId`                        | string      | (required for `oidc`)                | OAuth client_id registered at the IdP.                                |
| `oidc.clientSecret`                    | string      | (required for `oidc`)                | OAuth client secret. Inline alternative to `clientSecretFile`.        |
| `oidc.clientSecretFile`                | string      |                                      | File path holding the OAuth client secret.                            |
| `oidc.callbackPath`                    | string      | `/<name>/callback` (legacy block: `/auth/oidc/callback`) | Local path the relay forwards the callback to. Must end in `/callback` for relay routing. |
| `oidc.sessionCookieName`               | string      | `authenticatoor_<name>_session`      | Browser cookie name for the session.                                  |
| `oidc.stateCookieName`                 | string      | `authenticatoor_<name>_state`        | Browser cookie name for the OAuth CSRF / OIDC nonce state.            |
| `oidc.sessionTTL`                      | duration    | `12h`                                | Session cookie lifetime.                                              |
| `oidc.allowedGroups`                   | string list | `[]` (inherit IdP gating)            | Groups (as emitted by the IdP) whose members may authenticate. For dex's GitHub connector each group is `<org>` or `<org>:<team>`. Case-insensitive. A bare `<org>` entry matches both `<org>` and any `<org>:<team>` (useful because dex emits `<org>:<team>` for orgs even without a `teams:` filter). An `<org>:<team>` entry matches that exact team only. Empty list = trust the IdP's own gating. |
| `oidc.scopes`                          | string list | `[openid, email, groups]`            | OIDC scopes requested. `openid` is required.                          |
| `oidc.trustUnverifiedEmail`           | bool        | `false`                              | Use the id_token's `email` although the token does not say `email_verified: true`. Off by default: an unverified email is whatever its user typed. While the key is not set at all, the service logs a startup warning explaining the rule; `false` keeps the rule and silences it. See **Attributes** under Teams and **Upgrading**. |
| `oidc.teams`                           | string list | `[]`                                 | Static teams put into the token's `teams` claim for every identity this provider authenticates. See **Teams** below. |
| `oidc.teamRules`                      | list        | `[]`                                 | Rules that turn the attributes this provider verified about the user into teams. See **Teams** below. |
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
oidc→`oidc`). Converted `github` / `oidc` entries keep the previous
defaults for unset fields — callback paths `/auth/oauth/callback` /
`/auth/oidc/callback` and cookie names `authenticatoor_session` /
`authenticatoor_oauth_state` (github) — so registered redirect URIs keep
working. Session cookies are signed with a new per-provider key, so
existing sessions require one re-login after the upgrade. Prefer the
`providers` list for new configs.

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

Without a configured `audTag`, the provider learns its application's
AUD tag on its own: it requests `<externalURL>/<name>/login` without
credentials, and once the CF Access edge covers that path, Cloudflare's
login redirect carries a team-signed `meta` token naming the
application and hostname. The tag is verified against the team JWKS and
the instance's own hostname, then required on `/<name>/login` and
`/<name>/token`. Until the edge covers the prefix, those two routes
answer 503 — they never accept assertions issued for other applications
of the team. Detection retries every minute (and on demand when a login
arrives), so narrowing the CF Access app takes effect without a restart.

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

### Teams

**Teams say who you are; grants say what you may use.** The two are
separate on purpose.

A token can carry a `teams` claim — a sorted array of team names such as
`["lighthouse", "panda"]`. It is an *identity* attribute: tools use it
to tell whose things are whose (which team's nodes a user may touch).
authenticatoor does not decide who is in which team; it carries into
the token what the provider that authenticated the user knows.

Nothing about *access* hangs on a bare team name. Which tools an
identity may use is decided by [`grants`](#service-grants-grants), and a
grant always names the provider a team came through: `panda` from the
Cloudflare door and `panda` from the OIDC door are different subjects
there.

Every provider type block takes the same two settings:

| Field               | Meaning                                                              |
| ------------------- | -------------------------------------------------------------------- |
| `<block>.teams`     | A fixed list for every identity the provider authenticates.          |
| `<block>.teamRules` | Rules that derive teams from the **attributes** the provider verified about the user (token claims, a login, an org list). |

The sources of one provider add up. Where several providers are
configured, a token carries the teams of the provider that authenticated
the request — the first one in `providers` order that recognizes a
credential — and never a union across providers. A provider's rules see
only that provider's attributes. Teams are never taken from request
parameters, request headers or anything else a client controls.

#### Attributes

What a rule can read depends on the provider:

| Provider     | Attributes                                                            |
| ------------ | --------------------------------------------------------------------- |
| `oidc`       | Every claim of the verified id_token, by name: `sub`, `groups`, …; nested claims by dotted path (`realm_access.roles`, `resource_access.myapp.roles`). Only the id_token is read — no userinfo call is made. **`email` exists only when the token says `email_verified: true`** (see below). |
| `cloudflare` | Every claim of the verified Access token: `email`, `sub`, `country`, `custom.<…>`, `common_name` (service tokens), and whatever else Cloudflare puts there. Plus `principal`: `user` for a person, `service` for a service token. `email` is the one Cloudflare Access authenticated the user with (from the verified token; from the trusted header without `verifyJWT`). |
| `github`     | `login`, `email`, `orgs` (the list of org logins). All from the API calls the `allowedOrgs` check already makes — no further calls or scopes. `email` is an address GitHub reports as **verified** (the profile's public email if it is verified, else the primary verified address); when there is none, or the address list cannot be fetched, there is no `email`. |
| `basic`      | `username`.                                                           |
| `any`        | `username`.                                                           |

With `cloudflareAccess.verifyJWT: false` there is no verified token. The
attributes are then only `email` and `principal: user`, and rules on
them **rest on a header the edge is trusted to set** — exactly as much
as the identity itself does in that mode. Service tokens
(`principal: service`, `common_name`) exist only with `verifyJWT` and
`allowServiceTokens`.

**Verified emails only (`oidc`).** An email is an identity only if
someone checked that the user owns the address. The `oidc` provider
uses the id_token's `email` only when the token carries
`email_verified: true` — the JSON boolean, or the string `"true"` that
some IdPs send. `false`, any other value, and a **missing** claim count
as not verified. An unverified email is then nothing at all: it is not
the `email` attribute, not the token's `email` claim, not the token's
`sub` (the IdP's own `sub` is used instead), and it cannot match a
`user:` or `email:` member of a grants group. Otherwise a user of an
IdP that does not confirm addresses could type someone else's and
collect their email-keyed teams and grants. The claims are read by
their exact names: `Email_Verified: true` verifies nothing.

**The IdP's `sub` is not an email, even when it looks like one.** Some
IdPs can be configured to use the user's address as `sub`. Such a
subject is a raw IdP subject: authenticatoor remembers that it is not a
verified email, and a `user:` member that names an address never
matches it (see **Members**). It does become the token's `sub` as it
is, and the token carries no mark saying that the address in it was not
verified — the service logs a warning at each such login. A tool that
needs a verified address must read the token's `email` claim, which is
only ever a verified one, and not take `sub` for an email.

The rule is applied per login. If an IdP marks a user's email verified
at one login and not at the next, that user's `sub` alternates between
the email and the IdP subject, and with it everything keyed on either.

What the usual IdPs send (from their documentation as we know it — check
your own before relying on it): dex emits `email_verified`, and its
GitHub connector sets it to `true` because it takes the user's verified
primary address; Authentik's default `email` scope mapping emitted
`email_verified: true` in older releases and emits `false` since
2025.10 unless the mapping is customised. With an IdP that sends
`false` or nothing, logins keep working, but users are identified by
the IdP's `sub`, tokens carry no `email`, and email-keyed rules and
members do not match.

`oidc.trustUnverifiedEmail: true` switches the check off for one
provider. Set it only for an IdP that verifies addresses itself and
merely does not say so. With it, whoever can set their email at that
IdP can become any email identity this provider has rules or grants
for.

An attribute path is case-sensitive. Where a claim's own name contains
dots (`https://example.org/groups`), the longest existing name wins, so
it can be written as it is. A missing attribute yields nothing.

A value may be a string, a number or a boolean (taken as text: `3`,
`true`), or a list of those. Anything else — an object, a nested list,
null — is ignored, never turned into text. Values longer than 256 bytes
are ignored, and at most 1024 values of one attribute are looked at.

#### Rules

```yaml
teamRules:
  - claim: groups              # each value starting with the prefix: the rest is the team
    prefix: "team:"
  - claim: groups              # value → teams
    map:
      ethpandaops: [panda]
      "sigp:*": [lighthouse]
  - claim: department          # the capture group is the team
    regex: "^eng-([a-z0-9-]+)$"
  - claim: realm_access.roles  # every value is a team, as it is
    value: true
  - claim: scope               # split a string into several values first
    split: " "
    prefix: "team-"
  - claim: email               # a team for individual users
    map: { "alice@example.org": [lighthouse] }
```

| Key      | Meaning                                                                         |
| -------- | ------------------------------------------------------------------------------- |
| `claim`  | The attribute to read. Required.                                                |
| `prefix` | Only values that start with it; the rest of the value is the team.              |
| `map`    | Value → list of teams. A key is compared with the **whole** value. `*` in a key matches any run of characters — including none, and including separators such as `:` and `/`. There is no other wildcard. |
| `regex`  | An RE2 expression with exactly one capture group, which is the team. It must match the whole value, whether or not it is written with `^…$`. |
| `value`  | `value: true`: every value of the attribute is itself a team.                   |
| `split`  | Splits a string value at this separator into several values before the rule is applied. Can be combined with any of the above. |

A rule sets **exactly one** of `prefix`, `map`, `regex` and `value`.
There is no default: a rule with none of them is a startup error, and
so is a key that is written down but empty (`prefix: ""`, `map: {}`,
`map:`, `regex: ""`, `claim: ""`) or misspelled (`prefx:`). A rule never
quietly becomes "every value is a team" — that has to be asked for with
`value: true`.

**How values are compared.** `prefix` and `map` keys ignore the case of
ASCII letters and nothing else: no whitespace is trimmed, no Unicode
letter is treated as an ASCII one. `staff` matches `Staff`, but not
`staff ` and not a look-alike.

**What becomes a team.** A name taken *from a value* — the rest after a
`prefix`, a `regex` capture, a value taken with `value: true` — becomes a team only if it
already is one, byte for byte: lowercase `[a-z0-9][a-z0-9._-]{0,62}`.
Nothing is trimmed or lowercased. With `prefix: "team:"`, the group
`team:lighthouse` gives `lighthouse`; `team:Lighthouse`, `team:lighthouse `
and `team:Core Devs` give nothing and are reported in a warning at login.
This is deliberate: on an IdP where users can create groups, two
different groups must never turn into the same team. Teams named in the
config (`teams`, the lists in a `map`) are checked at startup.

**Matching an org and its teams.** `map` keys are whole-value matches,
so `ethpandaops` matches the group `ethpandaops` and nothing else — not
`ethpandaops:core`, not `ethpandaops-evil`. dex's GitHub connector emits
`<org>:<team>` groups; to give a team to everyone in an org, list both
forms:

```yaml
- claim: groups
  map:
    ethpandaops: [panda]
    "ethpandaops:*": [panda]
```

Do **not** write `ethpandaops*` for this: it also matches
`ethpandaops-evil` and `ethpandaopsx:anything`.

**Bound.** A token holds at most 32 teams. If a provider's static teams
and the rule results exceed that, the static ones are kept and the room
that is left goes to the rule results in alphabetical order; the rest
are dropped with a warning at login. The bound keeps the teams' share
of the session cookie at about 3 KB.

**Session cookies always fit.** Browsers drop a cookie whose name and
value exceed 4096 bytes. Teams and grant-member matches are bounded
together so that they leave room for the rest, and with the default
cookie names a subject and an email of up to 200 bytes of plain text
each always fit next to them. Subject and email themselves have no fixed limit: if a
login would need a larger cookie — a subject or an email of many
hundred bytes — the login is refused with an error page (403) and a
warning in the log, instead of setting a cookie the browser would drop
and sending the user round the login again. Identities that are not
stored in a cookie (Cloudflare Access headers, a Basic `Authorization`
header) are not affected.

Rule matching cannot be made slow: regular expressions are RE2 (linear
time, no backtracking), `*` keys are matched without a regex engine, and
the lengths of patterns (256 bytes) and values are bounded.

#### When rules run, and sessions

- **`oidc`, `github`** — the attributes exist only at login. The rule
  results are captured then and stored in the signed session cookie, so
  a token refresh carries them without a new login. They stay as
  captured until the session expires (`sessionTTL`, 12h by default): a
  change of the user's groups at the IdP, or of `teamRules`, takes
  effect at the next login.
- **`cloudflare`** — on requests that carry the Access headers (the edge
  covers `/auth/*`, or the `/<name>/token` alias) the rules run on every
  request against the current config. A session started at
  `/<name>/login` captures the rule results from the Access token of
  that moment, like `oidc`.
- **`basic`, `any`** — the username is all there is, so the rules run on
  every request against the current config, for a session cookie as
  well. These providers store no teams in a session and read none from
  one.

The static `teams` list is never stored in a cookie: it is read from the
current config on every request, so changing it applies to existing
sessions as soon as the service restarts.

**Which sessions count.** Each provider signs its cookies with its own
key, derived from the provider's `name`, so one provider's session
cannot be replayed as another's. The name alone does not say what
stands behind it, though — an entry can keep its name while its `type`
changes, or while it is pointed at another IdP. Every session therefore
also records, inside the signed payload, the *door* it was opened at:
the provider type plus its identity source (`oidc`: issuer and client
id; `cloudflare`: team domain and whether assertions are verified;
`github`, `basic`: the type). A session ends — its user logs in again —
when:

- it expires (`sessionTTL`), or the user logs out;
- the signing key changes (the session keys are derived from it);
- its provider entry is renamed;
- its provider entry changes its `type` or its identity source under
  the same name: the session was opened at another door, and no team
  or match from the old source carries over;
- it has no door at all, as cookies issued by versions before this one.

**Upgrading logs everyone in again, once** (see also
[Upgrading](#upgrading)). Session cookies issued by
earlier versions carry no door and are not accepted any more: nothing
in such a cookie says what it was opened at, so it could not be told
from a session of a provider entry that has since been retyped. After
the upgrade every user with such a cookie goes through their provider's
login once (for Cloudflare Access and cached Basic credentials that is
invisible; for `oidc` and `github` it is a redirect through the IdP,
usually without a prompt).

#### Hardening

- **The `teams` claim reports what the door says — all of it.** Rules
  look at every value of an attribute: every group in the id_token, not
  only the ones that got the user past `allowedGroups`. If an IdP emits
  `team:panda` for someone, a `prefix: "team:"` rule puts `panda` into
  their token. That is harmless for access, because a grant only counts
  a team together with its provider (below) — but a tool that reads
  `teams` sees it. Tools should use `teams` for ownership and features
  for privileges; see *Checking features in a resource server*.
- **Only list a door's team in a grants group if you trust that door to
  say who is in it.** `oidc/team:lighthouse` means "whoever the `oidc`
  provider's rules call lighthouse".
- **A Cloudflare door without `audTag` is the door of the whole
  Cloudflare team.** Without it, `/auth/*` accepts an Access assertion
  issued for *any* application of the same Cloudflare team — the
  audience detected on its own is only enforced on `/<name>/login` and
  `/<name>/token`. Someone admitted to another application of the team
  can present that assertion and is then whatever this door makes of
  its visitors. That is how a Cloudflare provider without `audTag` has
  always worked, and where one Access policy covers every application
  of the team it is what is meant. Where it is not, set `audTag`: then
  only assertions for this application count. A `cloudflare` provider
  that has `teams` or `teamRules`, or that a `grants` member names,
  and has no `audTag` gets **one warning at startup** saying that its
  teams and grants apply to everyone admitted to any application of the
  team. (With `verifyJWT` off no assertion is checked at all and the
  door is only as good as the network in front of it.)
- **Give staff teams to people, not machines.** On a Cloudflare door,
  static `teams` apply to service tokens as well. Use a rule on
  `principal` instead: `{claim: principal, map: {user: [panda]}}`.
- `any` gives its teams to whoever types a username. Development only.
- With the legacy top-level blocks, the static `teams` lists can be set
  through the environment as comma-separated values
  (`AUTHENTICATOOR_CLOUDFLAREACCESS_TEAMS=panda`). Rules cannot. With a
  `providers` list these variables have no effect (and are warned
  about).

`/auth/userinfo` reports the identity's teams in its `teams` field
(always an array, `[]` when there are none). A complete configuration
with two doors is at the end of the next section.

### Service grants (`grants`)

`grants` says which of the tools behind this authenticatoor an identity
may use at all. Without it, opening a second door — say `oidc` for
client teams next to the staff-only Cloudflare Access — gives everyone
who gets through either door a token that every tool accepts, because
tools do not look at teams on their own.

**A grant names the door, and what the door vouched for.**

```yaml
grants:
  - name: staff                        # optional label, for logs and errors
    members:
      - "cfaccess/team:panda"          # the team panda, as the provider cfaccess resolves it
      - "oidc/team:ethpandaops"        # the team ethpandaops, as the provider oidc resolves it
    services: ["all:all"]
  - name: internal-tooling
    members: ["oidc/groups:panda-access"]     # a plain IdP group, without making it a team
    services: [assertoor]
  - name: client-devs
    members: ["oidc/team:lighthouse", "oidc/team:geth"]
    services: [dora, "spamoor:user*"]
  - members: ["oidc/user:alice@example.org"]  # one user
    services: ["dora:reindex"]
```

`grants` is a list of groups. Each has:

| Key        | Meaning                                                                    |
| ---------- | -------------------------------------------------------------------------- |
| `members`  | Who is in the group. Required, at least one.                               |
| `services` | What the group may use: a list of grants (see **Features** below). Required. May be empty — `services: []` grants nothing and just documents the members. |
| `name`     | Optional label used in the startup log and in error messages. Unique.      |

An identity's grants are the **union** of the `services` of every group
it is a member of. Unknown keys in a group, wrong types, a group name
used twice, the same member twice in one group, an empty `grants:`
without a value — each is a startup error; write `grants: []` to grant
nothing to anyone. The earlier shapes of this section (`teamServices`,
and `grants` with `everyone` / `teams` / `users`) are gone and fail at
startup with a pointer to this one.

#### Members

A member has the form `<provider>/<attribute>:<value>`. The provider is
the text before the first `/`, the attribute the text up to the first
`:` after it, the value everything after that, as written — it may
contain `:`, `/`, `@`, `|`.

| Member                           | Who                                                              |
| -------------------------------- | ---------------------------------------------------------------- |
| `<provider>/team:<team>`         | Identities that provider authenticated **and gave the team** — through its static `teams` or its `teamRules`. The team is in normal form. |
| `<provider>/user:<id>`           | The identity that provider authenticated whose subject (`sub`) **or** email is `<id>`. An `<id>` that contains an `@` is an email address and matches only an address the provider verified — see below. |
| `<provider>/<attribute>:<value>` | Identities for which that provider verified the attribute to have that value. Attributes are the ones `teamRules` read, by the same names and paths (see **Attributes** above): `oidc/groups:panda-access`, `oidc/realm_access.roles:admin`, `cfaccess/principal:user`, `github/orgs:ethpandaops`, `htpasswd/username:alice`. The attribute is read the way a rule reads it — a string, a number or boolean as text, or a list of those — and the member matches when it *contains* a value equal to `<value>`. |

- **The provider is always there.** `<provider>` is the `name` of an
  entry in `providers` (for a legacy config: `cfaccess`, `htpasswd`,
  `anyauth`, `github`, `oidc`), spelled exactly. There is no member
  without a provider, no wildcard provider, and no "everyone through
  this door". A team, an id or a group that arrives through another
  provider is somebody else.
- **Comparison is exact**, ignoring only the case of ASCII letters in
  ids and values. There are no globs and no regular expressions in
  members — pattern logic lives in one place, `teamRules`. To grant by
  a pattern, write a rule that turns it into a team and name the team.
- **`user:` with an email address means the verified owner of that
  address.** `oidc/user:alice@example.org` matches the identity whose
  *verified* email is that address — for `oidc` one the id_token marks
  `email_verified` (or any, with `trustUnverifiedEmail`), for
  `cloudflare` the email Access authenticated, for `github` a verified
  address of the account. It never matches a raw provider subject that
  merely is, or looks like, an address: an IdP `sub` of
  `alice@example.org` without a verified email, a Cloudflare service
  token id. An `<id>` without an `@` (`oidc/user:sub-123`,
  `github/user:octocat`) is compared with the subject as before. To
  grant by a raw IdP subject that is an address, name the claim:
  `oidc/sub:alice@example.org`. For `basic` and `any` the id is the
  username as the password file (or the login form) has it, whatever
  it looks like.
- Exactly `team` and `user` are reserved, in this spelling. A
  provider's own attribute called `team` or `user` cannot be reached as
  an attribute member; neither can an attribute whose name contains a
  `:`. Turn such a claim into a team with a `teamRules` entry instead.
  Anything else is an attribute name, taken as written: `oidc/teams:x`
  reads a claim called `teams`, and `oidc/Team:x` one called `Team` —
  neither is the `team:` form.
- For `github`, `basic`, `any` and `cloudflare` the attributes are a
  known set, and a member that can never match is a startup error:
  - `github`: `login`, `email`, `orgs`; `basic`, `any`: `username`;
  - `cloudflare` with `verifyJWT`: `principal` (`user` or `service`),
    `email`, `sub`, `common_name`, `country`, `type`, `identity_nonce`,
    `iss`, `aud`, and `custom.<claim>` with a claim name after the dot;
  - `cloudflare` without `verifyJWT`: only `email` and
    `principal:user` — there is no token to read anything else from;
  - `principal:service` and `common_name` need service tokens, that is
    `verifyJWT` and `allowServiceTokens`.

  For `oidc` any path is accepted, because any claim can exist; a
  member naming a claim the IdP never sends simply never matches.
  Attribute and value together may be at most 300 bytes.
- The same verification rules apply as for team rules: only attributes
  the provider verified count.

**When members are evaluated.** `team:` and `user:` members are checked
against the identity every time a token is minted. Attribute members
need the upstream attributes, which for `oidc` and `github` (and a
Cloudflare session started at `/<name>/login`) exist only at login. At
login the provider checks which attribute members of the *current*
`grants` the identity satisfies and stores those matches — the
`<attribute>:<value>` strings, never the claims themselves — in the
signed session, next to the captured teams. So:

- **adding** an attribute member takes effect for a logged-in `oidc` /
  `github` user at their next login (the session remembers the matches
  of the config that was current when they logged in);
- **removing** a member, or changing a group's `services`, takes effect
  at the next token mint;
- `basic`, `any` and Cloudflare requests that carry the Access headers
  evaluate attribute members on every request and never read them from
  a cookie.

A session holds at most 64 matches, and matches and teams together are
limited so that the cookie stays under the browsers' 4 KB limit; what
does not fit is dropped from the end of the sorted list with a warning
at login. The limit belongs to the cookie: where nothing is stored in
one — `basic`, `any`, and Cloudflare requests that carry the Access
headers — every member the identity satisfies counts.

At startup the resolved groups are logged at info level, one line each:
`staff: cfaccess/team:panda, oidc/team:ethpandaops → all:all`.

The grants reach a tool through the token's `services` claim, an ordered
allow/deny directive list (`+name` / `-name`, `all` for every service,
later entries override earlier ones). With the section present, the
claim is computed for each token from the union of the identity's
grants:

| The identity's grants…          | `services` claim                                   |
| ------------------------------- | -------------------------------------------------- |
| include `all`                   | `+all`                                             |
| are `dora` and `spamoor`        | `-all,+dora,+spamoor` (sorted)                     |
| are empty: it is in no group    | `-all`                                             |

(Grants that name features add feature directives to these; see **The
emitted `services` claim** below.)

A user without any grant still gets a token — they are authenticated —
but a tool that checks its service refuses it. The grants are read from
the current config every time a token is minted (they are not stored in
the session), so a change applies to existing sessions after a restart,
at the next token refresh. At startup the resolved table is logged at
info level.

When the section is **absent**, nothing changes from earlier versions:
no per-team `services` claim is computed, and tokens carry no service
constraint. If the instance has more than one provider, or any provider
produces teams, the service logs one warning at startup saying that
every authenticated identity receives tokens valid for every service.

Two things to keep in mind:

- **An empty or missing `services` claim means "no constraint".** That
  is how verifiers have always read it, and it is what tokens look like
  without `grants`. Once the section exists, the claim is never
  empty: an identity with no grant gets an explicit `-all`.
- **The gate binds only tools that check it.** A resource server
  enforces the claim when it sets its own name as
  `VerifierConfig.ExpectedService` in `pkg/auth` (spamoor and assertoor
  do; buildoor does once its branch `pk910/services-gate` is merged). A tool that does not set it accepts any valid token,
  whatever `grants` says — list a service here only once the tool
  enforces it, and do not rely on this section to keep anyone out of a
  tool that does not.

#### Features

**A service directive grants basic access; features are extras on top.**
Naming a service gives a group *basic* access to that tool. A tool can
additionally put individual capabilities — rebuilding an index, say —
behind named *features*, and a grant can hand those out per group:

| Grant        | Meaning                                                        |
| ------------ | -------------------------------------------------------------- |
| `svc`        | Basic access to `svc`.                                         |
| `svc:f1:f2`  | Basic access to `svc`, plus its features `f1` and `f2`.        |
| `svc:user*`  | Basic access to `svc`, plus every feature whose name starts with `user` (`user`, `user-view`, `userxyz`). |
| `svc:all`    | Basic access to `svc`, plus every feature of it.               |
| `all`        | Basic access to every service.                                 |
| `all:f1`     | Every service: basic access, plus feature `f1`.                |
| `all:all`    | Every service, every feature. What the internal team gets.     |

```yaml
grants:
  - members: ["cfaccess/team:panda"]
    services: ["all:all"]                      # staff: everything
  - members: ["oidc/team:lighthouse"]
    services: ["dora:admin", spamoor]          # dora incl. admin; spamoor basic
  - members: ["oidc/user:alice@example.org"]
    services: ["dora:reindex"]                 # one more feature for one user
```

Feature names are lowercase `[a-z0-9][a-z0-9-]*`. `basic` is the
reserved name of basic access itself: `svc:basic` is the same grant as
`svc`, may be written out, and is never a tool's own feature. The grants
of all the groups an identity is in add up: `dora` from one group,
`dora:admin` from another and `dora:all` from a third make
`dora:all`.

A feature may end in `*`, which makes it a prefix: `spamoor:user*`
grants every feature of spamoor whose name starts with `user`. The `*`
is only a wildcard as the last character — `us*er`, `*admin` and `u**`
are startup errors — and a lone `*` is the same as `all`. There is no
wildcard for service names; `all` is the only way to address every
service. A prefix never covers the reserved `basic`.

Grants are positive only. `-svc` or `svc:-f1` is a startup error:
because the grants of several groups are a union, a denial in one group's
list would depend on the order the groups are evaluated in. Leave out
what a group should not have.

**What a bare service means for features.** A tool checks each of its
features in one of two modes (see *Checking features in a resource
server* below):

- a *default-allow* feature comes with basic access, so a group granted
  the bare `svc` has every default-allow feature of that tool;
- a *default-deny* feature needs its own grant (`svc:feature`) or
  `svc:all`, so a group granted the bare `svc` has none of them.

A config cannot take a single default-allow feature away from a group —
that would need a negative form, which grants do not have.

A group granted the bare service (or the bare `all`) has basic access
and no default-deny feature. That is fine as long as no tool requires
one; once a tool does, such a group — staff under `services: [all]`
included — is refused that feature. Give the internal team `all:all`.

#### The emitted `services` claim

The claim is an ordered directive list, read left to right with later
entries overriding earlier ones:

```
directive = [+|-]service(:grantSpec)*      grantSpec = feature | -feature | all
feature   = name | prefix*

+spamoor                 basic access, no further features
+spamoor:all             basic + every feature
+spamoor:f1:f2           basic + f1 + f2
+spamoor:user*           basic + every feature starting with "user"
+spamoor:all:-plugins    basic + every feature except plugins
+spamoor:all:-user*      basic + every feature except those starting with "user"
+all:featA               every service: basic + featA
-spamoor                 deny spamoor entirely
-spamoor:f1              remove f1, basic access untouched
```

A verifier skips a **malformed directive as a whole** — it then grants
nothing and denies nothing, for basic access and for features alike. A
directive is malformed when any of its segments is: an empty segment
(`+svc:`), a `*` that is not the last character (`us*er`, `*admin`,
`u**`), `-basic` in a positive directive, a signed segment in a
negative one (`-svc:-x`), or a `*` in the service position
(`+spam*:x`). So `-all,+svc:us*er` grants nothing. (A directive without
any `:` is read exactly as older verifiers read it.)

authenticatoor only ever emits the positive forms plus `-all`, and
never a malformed directive. For the
union of an identity's grants:

| Grants (union)                                 | `services` claim                                  |
| ---------------------------------------------- | ------------------------------------------------- |
| none, or no teams                              | `-all`                                            |
| `dora`                                         | `-all,+dora`                                      |
| `spamoor`, `dora:admin:api`                    | `-all,+dora,+dora:admin:api,+spamoor`             |
| `dora`, `dora:admin`, `dora:all`               | `-all,+dora,+dora:all`                            |
| `all`                                          | `+all`                                            |
| `all`, `dora:admin`                            | `+all,+dora:admin`                                |
| `all:logs`, `dora:admin:logs`                  | `+all,+all:logs,+dora:admin`                      |
| `all:all`                                      | `+all,+all:all`                                   |
| `spamoor:user*`, `spamoor:plugins`             | `-all,+spamoor,+spamoor:plugins:user*`            |

Prefix grants are emitted as written, sorted among the other features.
Nothing is expanded or folded: `user*` next to `user-view` stays
`user*:user-view`; only exact duplicates are dropped, and everything
once `all` is granted.

The order is fixed — `all` forms first, then services by name, features
by name — so the same grants always give the same string. `basic` is
never written into a claim.

**Compatibility with deployed tools.** A feature directive is always
emitted *in addition to* the bare directive for the same basic access
(`+dora,+dora:admin`, `+all,+all:all`). Tools built against
`pkg/auth` v0.0.3 or earlier do not know features: they read
`+dora:admin` as an unknown service name and skip it. The bare
directives alone therefore decide basic access for them, exactly as the
whole list does for current tools. Upgrading authenticatoor and adding
features to `grants` neither locks a deployed tool out nor lets
anyone into it who was not allowed before; the test suite checks every
emitted claim against a copy of the old parser.

**What is guaranteed, exactly.** For a claim without any `:`, old and
current verifiers evaluate basic access identically. For a claim with a
`:` they can differ — an old verifier reading `-all,+spamoor:x` denies
spamoor, a current one allows it; `-spamoor:basic` is a denial only to
a current one. The claims authenticatoor emits never get into that:
the bare directive is always there, no denial carries segments, and
`basic` is never written. **A claim written by hand** — an instance-wide
directive set by a program embedding the issuer, a token minted by
another tool — must follow the same rule and repeat the bare directive
(`+spamoor,+spamoor:x`), or it will mean different things to different
verifiers.

**The instance-wide bound.** The issuer library has an instance-wide
`services` directive (`issuer.Config.Services`) that every token of an
instance carries, and that with `grants` acts as an upper bound on
basic access: a service it denies gets no directive at all for an
identity, so no features of it either. **No config key sets it** —
authenticatoor itself always runs with an empty one; it concerns only
programs that embed `pkg/issuer`. Together with grants the bound is
about basic access only and must consist of `+service` / `-service`
entries: one that names features (contains a `:`) is refused when the
issuer is constructed, because it would have no consistent meaning. A
blank bound counts as none.

#### Checking features in a resource server

For tool authors. The service gate stays what it is: configure the
verifier with `ExpectedService` and a token not meant for the tool is
rejected before any handler runs. A feature check is an **addition** to
that gate, never a replacement for it.

A feature is checked in one of two modes, chosen by the tool per
feature:

- **`auth.FeatureDefaultAllow`** — the feature follows basic access
  unless it was explicitly excluded. For ordinary functionality that you
  may want to take away from someone later.
- **`auth.FeatureDefaultDeny`** — the feature needs its own grant
  (`+svc:feature`) or every feature (`+svc:all`), and must not be
  excluded later. For anything privileged that must be handed out
  deliberately.

```go
// In a handler, with the verified claims:
if !claims.HasFeature("dora", "admin", auth.FeatureDefaultDeny) {
	http.Error(w, "forbidden", http.StatusForbidden) // privileged: needs the grant
	return
}
if claims.HasFeature("dora", "view-logs", auth.FeatureDefaultAllow) {
	// ordinary: everyone with basic access, unless excluded
}

// Or as middleware (401 without claims, 403 when not allowed):
mux.Handle("POST /api/admin/reindex", auth.RequireFeature(
	"dora", "admin", auth.FeatureDefaultDeny, handleReindex))
mux.Handle("GET /api/logs", auth.RequireFeature(
	"dora", "view-logs", auth.FeatureDefaultAllow, handleLogs))
```

What the claim says about one feature is one of three things: nothing
(*unset*), *granted* (`+svc:feature`, `+svc:all`, `+all:…`), or
*excluded* (`-svc:feature`, `-all:feature`, a `-feature` segment as in
`+svc:all:-feature`). The answer:

| Basic access to the service | Feature  | `FeatureDefaultDeny` | `FeatureDefaultAllow` |
| --------------------------- | -------- | -------------------- | --------------------- |
| denied                      | any      | no                   | no                    |
| allowed                     | unset    | no                   | yes                   |
| allowed                     | granted  | yes                  | yes                   |
| allowed                     | excluded | no                   | no                    |
| *token without a `services` claim* | —  | **yes**              | **yes**               |

A feature is never allowed without basic access to its service, in
either mode. `HasFeature(svc, "basic", …)` is the service gate itself:
it always answers what `ServiceAllowed` / `ExpectedService` answer.

**The last row is the one case where default-deny says yes without a
grant.** A token without a `services` claim has no constraint; that has
always been the meaning of an empty claim, and it is what an
authenticatoor without `grants` mints. Such an instance gates
nothing per user and has only its own operators behind it. An
authenticatoor with `grants` never mints an empty claim (an
identity with no grant gets `-all`), so configure `grants` on
every instance that lets anyone but staff in.

**Teams or features?** Use the `teams` claim for *ownership*-type
decisions — whose nodes these are, which team's dashboard to show — and
features (`HasFeature`) for what a user *may do*. Do not hang a
privilege on a team name: the `teams` claim says what the door reports
about a user, and the same name can come through another door. What a
user may do is decided in `grants`, door by door, and reaches the tool
as the `services` claim.

Rules of thumb:

- Features name **capabilities**, not endpoints: `admin`, not
  `post-api-v1-admin-reindex`. Several endpoints usually share one feature.
- Use a default-deny feature for anything that changes or exposes
  something sensitive; default-allow for the rest, if it needs a name at
  all.
- With prefix grants, feature names are **namespaces**. Group them
  deliberately — `user-view`, `user-edit`, `user-delete` — so that
  `user*` means something, and do not let an unrelated or more
  privileged feature share a prefix by accident (`user-impersonate`
  would be covered by `user*`). In a claim, later directives win:
  `+svc:user*,-svc:user-admin` allows `user-view` and denies
  `user-admin`; the other order allows both. Prefixes exist only in
  claims and grants — a check always asks for one exact feature.
- Do not call a feature `basic` or `all`; both are reserved.
- Introducing a default-deny feature takes it away from every group that
  has only the bare service until its grants name it. Staff should be
  `all:all`.

### A complete devnet

Two doors and one grants section. Staff come through Cloudflare Access
(people become `panda`; service tokens get no team) or through the
central IdP, where they are in the team `ethpandaops`. Client teams
come through the central IdP, whose `team:<slug>` groups become teams;
one user joins a team by email. Everyone the IdP puts into the plain
group `panda-access` may use the internal tooling, without that group
being a team. One user gets one extra feature.

```yaml
issuer: "https://auth.<devnet>.ethpandaops.io"
signing:
  rs256:
    privateKeyFile: "/etc/authenticatoor/keys/private.pem"

authMode: [cfaccess, oidc]
providers:
  - name: cfaccess
    type: cloudflare
    cloudflareAccess:
      teamDomain: "<team>.cloudflareaccess.com"
      audTag: "0123456789abcdef"       # the AUD tag of THIS Access application
      teamRules:
        - claim: principal            # people are staff; service tokens are not
          map: { user: [panda] }

  - name: oidc
    type: oidc
    oidc:
      issuerURL: "https://<central-idp>"
      callbackURL: "https://<oidc-relay>/oidc/callback"
      clientId: "authenticatoor"
      clientSecretFile: "/etc/authenticatoor/oidc-client-secret"
      trustUnverifiedEmail: false     # emails count only when the IdP marks them verified
      teamRules:
        - claim: groups               # team:lighthouse → lighthouse
          prefix: "team:"
        - claim: email                # one user joins a team by email
          map: { "carol@example.org": [geth] }

grants:
  - name: staff
    members:
      - "cfaccess/team:panda"         # panda as the Cloudflare door says it
      - "oidc/team:ethpandaops"       # ethpandaops as the central IdP says it
    services: ["all:all"]
  - name: internal-tooling
    members: ["oidc/groups:panda-access"]   # a plain IdP group, not a team
    services: [assertoor]
  - name: client-devs
    members: ["oidc/team:lighthouse", "oidc/team:geth"]
    services: [dora, "spamoor:user*"]
  - members: ["oidc/user:alice@example.org"]
    services: ["dora:reindex"]
```

| Who                                                             | `teams`           | `services`                                                  |
| --------------------------------------------------------------- | ----------------- | ----------------------------------------------------------- |
| A person through Cloudflare Access                              | `["panda"]`       | `+all,+all:all`                                             |
| A service token through Cloudflare Access                       | *(none)*          | `-all`                                                      |
| Staff via `oidc`, groups `team:ethpandaops`, `panda-access`     | `["ethpandaops"]` | `+all,+all:all`                                             |
| `alice@example.org` via `oidc`, group `team:lighthouse`         | `["lighthouse"]`  | `-all,+dora,+dora:reindex,+spamoor,+spamoor:user*`          |
| `bob@example.org` via `oidc`, group `team:lighthouse`           | `["lighthouse"]`  | `-all,+dora,+spamoor,+spamoor:user*`                        |
| `carol@example.org` via `oidc`, no `team:` group                | `["geth"]`        | `-all,+dora,+spamoor,+spamoor:user*`                        |
| `dave@example.org` via `oidc`, group `panda-access` only        | *(none)*          | `-all,+assertoor`                                           |
| Someone via `oidc` with group `team:panda`                      | `["panda"]`       | `-all`                                                      |

The last row is the point of naming the door: the IdP can call someone
`panda`, and the token says so, but the staff group lists `panda` only
as the Cloudflare door reports it.

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

`audTag` — the AUD tag of the Access application, from its settings in
the Cloudflare dashboard — is optional. With it, only assertions issued
for this application are accepted. Without it, `/auth/*` accepts the
assertion of any Access application of the same Cloudflare team; a
provider that has `teams` or `teamRules` or is named in a `grants`
member then logs a startup warning, because its teams and grants apply
to all of them (see **Hardening** under Teams).

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
`/<name>/callback`, or `/auth/oauth/callback` for the legacy top-level
block); this must match the redirect URI registered in
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
URL encoded in the OAuth `state` parameter. The state contract:

```
state = "<our-public-url><callback-dir>~<base64url-signed-blob>"
```

where `<our-public-url>` is this instance's `externalURL` (the relay's
regex constrains it to `*.ethpandaops.io` / `localhost` / `127.0.0.1`)
and `<callback-dir>` is `oidc.callbackPath` minus its trailing
`/callback` (e.g. `/oidc`); the relay redirects to
`<our-public-url><callback-dir>/callback`,
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
