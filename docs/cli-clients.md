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
  JWT signed with RS256 that carries those claims, names the client id
  in `aud` and has `iss`, `sub` and `exp`. Many IdPs issue opaque access
  tokens or JWT access tokens without identity claims — present the
  id_token then.
- **An asymmetric signing key.** Only RS256 is accepted. A token signed
  with a shared secret (HS256), or with any other algorithm, is
  refused.
- **A short token lifetime** — minutes. A token is a login at every
  instance that accepts the audience until it expires, and nothing can
  revoke it earlier (see [Security](#security)). For long sessions use
  a refresh token and get a new JWT when needed.

### Example: Authentik

*An example of the points above, not a requirement and not a setup
guide. authenticatoor has no code specific to any IdP; how a setting is
called, where it lives and what a default does is for the IdP's own
documentation, and changes between its versions.* Three things have
been what mattered with Authentik:

- **One issuer per client.** Each provider (client) there usually has
  its own issuer URL, so the CLI client's tokens name another issuer
  than the browser client's. The operator then has to set
  `oidc.bearer.issuerURL` to the issuer of the CLI client — the `iss`
  of its tokens.
- **A signing key has to be selected on the provider.** The client must
  sign with an asymmetric key (RS256). Tokens signed with a shared
  secret (HS256) are refused.
- **The token presented must itself contain `email`, `email_verified`
  and `groups`.** Check a token of the client (decode its payload)
  rather than the IdP's settings: what is not in the JWT does not exist
  for authenticatoor.

The operator of the instance adds:

```yaml
oidc:
  bearer:
    audiences: ["devnet-cli"]
    issuerURL: "<the iss of the CLI client's tokens>"
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

- Method `GET` only. Every other method — `POST`, `OPTIONS`, … — gets
  `405`.
- The endpoint sends no CORS headers and answers no preflight: it is
  not for JavaScript running in a browser (a web app uses the client
  script and `/auth/token`).
- The `Authorization` header value may be at most 16 KiB. A longer one
  is refused (`401`) without the token being looked at.
- The bearer token is read on this path only. Sent to `/auth/token` or
  any other `/auth/*` path it is ignored, and the answer is the
  browser's: a redirect to a login.
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

The server allows **no clock leeway**: an IdP token is refused from the
second its `exp` has passed by the server's clock (and before its `nbf`,
if it has one). Do not present a token in its last seconds — refresh it
when less than, say, half a minute is left.

Store both tokens like credentials (file mode `0600`, or the system
keyring) — and the refresh token above all; see [Security](#security).

### Errors

Decide by the status code; the body is a short plain-text message and
not part of the contract.

| Status | Meaning | What to do |
| ------ | ------- | ---------- |
| `401`  | No `Authorization: Bearer` header (`WWW-Authenticate: Bearer`), or the token was not accepted (`WWW-Authenticate: Bearer error="invalid_token"`): malformed, bad signature, not RS256, wrong issuer, an audience the instance does not accept, expired, no `sub`, header too large — or the instance has not loaded the IdP's signing keys yet. | Get a fresh IdP token and try once more. If it fails again, the client id is not accepted by this instance or the issuer differs: an operator matter. |
| `403`  | The IdP token is valid, but its user gets no devnet token: they are not in a group the instance admits (`allowedGroups`), or — on an instance with service grants — no grants group names them (body: `authenticated, but not permitted to use the services of this devnet`). No `WWW-Authenticate` header. | Tell the user that they are logged in but have no access to this devnet; a new IdP token or a new login does not help. An operator has to add them. |
| `400`  | A requested `aud` is not allowed. | Fix the request. |
| `404`  | The instance has no bearer endpoint under this provider name. | Check the URL; the feature may be off. |
| `405`  | A method other than `GET`. | Fix the request. |
| `5xx`  | Server-side failure. | Retry with backoff. |

The endpoint never redirects. A `3xx` means the request went somewhere
else — usually `/auth/token`, which is the browser's endpoint.

## Security

What a client author has to know about the credentials involved:

- **The IdP token is a login, until it expires.** Anyone who holds it
  can fetch devnet tokens with it at every instance that accepts its
  audience. There is no revocation: the service keeps no session and no
  list of tokens, and does not ask the IdP about a token it is shown. A
  captured IdP token works until its `exp`. Send it to authenticatoor
  instances only, over https, and keep its lifetime at minutes.
- **`azp` is not checked.** A token is accepted for the audiences it
  carries (`aud`), whoever it was issued to. A token of another client
  that also names the accepted audience is accepted.
- **The refresh token is the long-lived credential.** It is what lets
  the client mint IdP tokens — and so devnet tokens — for as long as
  the IdP allows, typically far longer than any token described here.
  authenticatoor never sees it and cannot limit or revoke it. Store it
  in the system keyring where there is one, never log it, and offer the
  user a logout that revokes it at the IdP.
- **The devnet token cannot be revoked either.** It is valid until its
  `expr`.

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
