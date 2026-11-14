# Non-browser clients

How a command-line tool (or any client without a browser session) gets a
token from an authenticatoor instance and uses it against the services of
a devnet. This page is the contract; it is meant to be enough to
implement a client without reading the service's code.

The operator's side — the `oidc.bearer` config block and its security
notes — is in
[`config.md`](config.md#non-browser-clients-bearer-tokens).

## Overview

```
 client ──(1) device-code / loopback login──▶ IdP            → IdP token (a JWT)
 client ──(2) GET /<provider>/token, Bearer IdP token──▶ authenticatoor
                                                             → devnet token
 client ──(3) Authorization: Bearer devnet token──▶ devnet services
```

1. The client logs its user in at the identity provider (IdP) with a
   client of its own and keeps the JWT it gets.
2. It presents that JWT to the authenticatoor of the devnet and receives
   the devnet token — the same token a browser gets from `/auth/token`,
   with the same subject, teams and grants.
3. It sends the devnet token to the devnet's services.

The feature is off by default. It works on instances whose `oidc`
provider has an `oidc.bearer` block listing the client's id as an
accepted audience.

## Prerequisites at the IdP

The client needs its own client registration at the same IdP the
instance's `oidc` provider logs browsers in with:

- **A public client** (no secret) with a flow that works from a
  terminal: the device authorization grant (RFC 8628), or the
  authorization code flow with PKCE and a loopback redirect
  (`http://127.0.0.1:<port>/…`).
- **Dedicated to this purpose.** Its tokens are accepted as a login by
  every authenticatoor instance that lists its client id. Do not reuse a
  client whose tokens are sent to other services, and do not send this
  client's tokens anywhere but to authenticatoor instances.
- **The same subject mode as the browser client.** The devnet token's
  `sub` is the user's verified email or, without one, the IdP's `sub`.
  If the IdP derives `sub` differently per client (pairwise subjects, a
  different "subject mode"), the same person is someone else on the
  command line, and grants made to them by user id do not apply.
- **Claims in the token.** authenticatoor reads the presented JWT and
  nothing else — it makes no userinfo call. Request the scopes, and
  configure the claim mappings, that put into the token what the
  instance's rules read: normally `email`, `email_verified` (a boolean
  `true` for a confirmed address) and `groups`. Whether to present the
  id_token or the access token is the client's choice; it has to be a
  signed JWT (RS256) that carries those claims, names the client id in
  `aud` and has `iss`, `sub` and `exp`. Many IdPs issue opaque access
  tokens or JWT access tokens without identity claims — present the
  id_token then.
- **A short token lifetime** — minutes. A token is a login at every
  instance that accepts the audience until it expires. For long
  sessions use a refresh token and get a new JWT when needed.

### Example: Authentik

*An example, not a requirement; names of settings vary between
versions.* In Authentik, create an **OAuth2/OpenID Provider** and an
application for it:

- Client type **Public**, client id e.g. `devnet-cli`.
- For the loopback flow, a redirect URI on `http://127.0.0.1` (regex
  for any port); for the device flow, set a device code flow on the
  brand.
- **Subject mode** the same as in the provider used for the browser
  login.
- Scopes `openid`, `email`, `profile` (Authentik's default `profile`
  mapping carries `groups`) and `offline_access` for a refresh token;
  **Include claims in id_token** on.
- Check what the `email` scope mapping returns for `email_verified`.
  Recent versions say `false` unless the mapping is replaced; the
  instance then identifies the user by `sub`, on the command line and
  in the browser alike.
- Access token validity of a few minutes; refresh token validity as
  long as a session should last.
- **Issuer mode**: with "each provider has a different issuer" the
  tokens' issuer is `https://<authentik>/application/o/<slug>/`, which
  is not the browser client's. The operator then sets
  `oidc.bearer.issuerURL` to it.

The operator of the instance adds:

```yaml
oidc:
  bearer:
    audiences: ["devnet-cli"]
    issuerURL: "https://<authentik>/application/o/devnet-cli/"
```

## The endpoint

```
https://auth.<devnet-domain>/<provider-name>/token
```

`<provider-name>` is the name of the instance's `oidc` provider entry
(`oidc` for a config in the legacy single-provider form). It is
deployment configuration: the service's
`/.well-known/openid-configuration` lists only its issuer and JWKS and
does not advertise this endpoint, so a client takes the URL — or the
host and the provider name — from its own configuration.

On an instance where the feature is off the path does not exist (`404`).

## Request

```
GET /<provider-name>/token HTTP/1.1
Host: auth.<devnet-domain>
Authorization: Bearer <JWT from the IdP>
```

- Method `GET` only.
- The `Authorization` header value may be at most 16 KiB.
- Optional query parameter `aud` (repeatable): the audiences the devnet
  token should carry. Each must be one the instance is configured for;
  otherwise `400`. Leave it out for the instance's default.
- No cookies are read, and none are set.

```sh
curl -sS -H "Authorization: Bearer $IDP_TOKEN" \
  https://auth.devnet-1.example.org/oidc/token
```

## Response

`200`, `Content-Type: application/json`, `Cache-Control: no-store`:

```json
{
  "token": "eyJhbGciOiJSUzI1NiIsImtpZCI6Ii4uLiJ9…",
  "user": "alice@example.org",
  "expr": 1714494600,
  "now": 1714492800
}
```

| Field   | Type   | Meaning |
| ------- | ------ | ------- |
| `token` | string | The devnet token: a JWT signed by this instance (RS256). |
| `user`  | string | The user for display: the verified email, or the subject when there is none. |
| `expr`  | number | When the token expires, in Unix seconds (its `exp`). |
| `now`   | number | The server's time when it issued the token, in Unix seconds (its `iat`). |

Use `expr - now` as the lifetime rather than comparing `expr` with the
local clock, which may be off.

### Caching

Keep the devnet token and reuse it until shortly before it expires — a
margin of a minute, or a tenth of the lifetime, is reasonable — then
request a new one with a current IdP token. If the IdP token has expired
by then, refresh it at the IdP first. There is no refresh endpoint here
and no session: every request is authenticated by the IdP token it
carries.

Store both tokens like credentials (file mode `0600`, or the system
keyring).

### Errors

Decide by the status code; the body is a short plain-text message and
not part of the contract.

| Status | Meaning | What to do |
| ------ | ------- | ---------- |
| `401`  | No `Authorization: Bearer` header (`WWW-Authenticate: Bearer`), or the token was not accepted (`WWW-Authenticate: Bearer error="invalid_token"`): malformed, bad signature, wrong issuer, an audience the instance does not accept, expired, no `sub`, header too large. | Get a fresh IdP token and try once more. If it fails again, the client id is not accepted by this instance or the issuer differs: an operator matter. |
| `403`  | The IdP token is valid, but its user gets no devnet token: they are not in a group the instance admits (`allowedGroups`), or — on an instance with service grants — no grants group names them (body: `authenticated, but not permitted to use the services of this devnet`). No `WWW-Authenticate` header. | Tell the user that they are logged in but have no access to this devnet; a new IdP token or a new login does not help. An operator has to add them. |
| `400`  | A requested `aud` is not allowed. | Fix the request. |
| `404`  | The instance has no bearer endpoint under this provider name. | Check the URL; the feature may be off. |
| `5xx`  | Server-side failure. | Retry with backoff. |

The endpoint never redirects. A `3xx` means the request went somewhere
else — usually `/auth/token`, which is the browser's endpoint.

## Using the devnet token

Send it to the devnet's services:

```
Authorization: Bearer <token>
```

```sh
TOKEN=$(curl -sS -H "Authorization: Bearer $IDP_TOKEN" \
  https://auth.devnet-1.example.org/oidc/token | jq -r .token)
curl -sS -H "Authorization: Bearer $TOKEN" https://dora.devnet-1.example.org/api/v1/…
```

A service accepts the token when:

- its signature verifies against this instance's keys
  (`https://auth.<devnet-domain>/jwks.json`) and `iss` is the instance;
- `aud` contains the audience the service expects;
- `scope` — a host pattern such as `*.devnet-1.example.org` — matches
  the host the request was sent to, where the service checks it;
- the `services` claim allows the service, and the feature for calls
  that need one.

The token's claims (`sub`, `email`, `teams`, `services`, …) are described
in the [README](../README.md#token-format). A client need not interpret
them, with one exception worth showing to the user:

**No token (`403`)** is what a user gets who is authenticated but named
by no grants group of this devnet — see the error table above. There is
no token that says "logged in, without access".

**`services` starting with `-all`** restricts the token to the services
named after it: `-all,+dora` is access to dora only, `-all,+spamoor` to
spamoor only. A bare `-all` — rare: the user is in a group that grants
no service — is a token no service accepts that checks the claim. A
token without the claim, or with `+all`, has basic access to every
service.

When a service starts refusing a token it accepted before, the token
has most likely expired: get a new one and repeat the call once. A
refusal that persists with a fresh token means the user is not granted
that service or feature.
