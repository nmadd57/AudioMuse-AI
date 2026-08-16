# OIDC session bridge

A small, dependency-free (Python stdlib only) reverse-proxy that sits between
a forward-auth proxy (oauth2-proxy, Authelia, Authentik, or anything else that
verifies a user against an OIDC provider and forwards identity as a request
header) and an app that has its own local login system but no native
SSO/header-trust support.

It solves a specific, common gap: your forward-auth proxy can gate *access* to
an app just fine, but if the app itself only knows "username + password ->
session cookie," everyone who gets past the proxy either shares one login or
has to log in a second time. This bridge closes that gap by minting the
app's own session cookie directly, using its own auth format, on behalf of
whoever the proxy says is authenticated - and optionally creating that user
in the app first if they don't exist yet.

It is **not** a generic OIDC client and does not talk to your OIDC provider
directly. Your forward-auth proxy does that part. This only needs whatever
identity header that proxy forwards on the *proxied* request - which family
of headers that is depends entirely on your proxy and how it's configured,
not on which OIDC server is behind it. See "A note on identity headers"
below; getting this wrong is the single most common way to deploy this and
have it silently do nothing.

## Before you deploy this anywhere

Read the module docstring in `shim.py` first. In short, you must confirm,
by reading the target app's own auth code, three things:

1. **The app's session validation trusts its own user table, not the JWT.**
   If the app reads a role/permission straight out of the JWT payload without
   cross-checking a database row it owns, this bridge can hand out privilege
   the app never actually granted. AudioMuse-AI is fine here - see the worked
   example below for how that was verified, not assumed.
2. **The cookie name, claim shape, and signing algorithm you configure here
   exactly match what the app's own login flow issues.** If they don't
   match, the app will just look logged-out - a confusing symptom the first
   time you hit it (see "How to debug it doing nothing" below).
3. **How the app signals "user already exists" on a repeat provisioning
   call.** `PROVISION_SUCCESS_STATUSES` needs to include that status code,
   or the bridge treats it as a failed provisioning attempt on every single
   request from a returning user.

## How it works

For every request carrying a configured identity header, the bridge:

1. Optionally calls the app's user-creation endpoint to provision that
   identity (idempotent - configured success codes include "already
   exists"). Skip this entirely with `PROVISION_ENABLED=false` for apps
   that provision users some other way.
2. Mints a JWT shaped `{<sub claim>: identity, <role claim>: role, iat, exp}`,
   signed HS256 with a secret shared with the app, and sets it as a cookie
   on the *proxied* request only (the browser never sees this cookie or the
   token - it's an internal server-to-server credential the app decodes and
   trusts).
3. Proxies the request through. The app sees an ordinary valid session.

No in-memory caching of "this user is already provisioned" - every request
just makes the (cheap, idempotent) provisioning call. An earlier version of
this cached that check, and the cache went stale the moment someone deleted
the app-side user record out of band: the bridge kept assuming the user
existed, kept minting cookies for a username that resolved to nothing, and
the app correctly bounced every request back to its own login with no
obvious cause. Not worth the false economy.

## A note on identity headers

Your forward-auth proxy forwards identity to the *proxied request* using
whatever header family it's configured for - check its docs, don't assume.
A concrete example of the mistake this causes: oauth2-proxy has two
completely different header families depending on config -
`--set-xauthrequest` produces `X-Auth-Request-*` headers, but those only
appear on the *response to an nginx auth_request subrequest* - they are
**never sent to `--upstream`**. If oauth2-proxy is proxying you directly
(`--upstream=...`, not fronting nginx's `auth_request` module), the headers
actually on the proxied request come from `--pass-user-headers` instead:
`X-Forwarded-User`, `X-Forwarded-Email`, `X-Forwarded-Preferred-Username`,
`X-Forwarded-Groups`. Set `IDENTITY_HEADERS` to whatever your specific
proxy/config combination actually forwards, and verify it by checking the
bridge's proxied request headers directly rather than assuming.

## Configuration

| Env var | Required | Default | Meaning |
|---|---|---|---|
| `UPSTREAM_URL` | yes | - | Base URL of the real app, e.g. `http://app:8000` |
| `SESSION_JWT_SECRET` | yes | - | HS256 signing secret, shared with the app |
| `PORT` | no | `8001` | Port the bridge listens on |
| `IDENTITY_HEADERS` | no | `X-Forwarded-Email,X-Forwarded-Preferred-Username,X-Forwarded-User` | Comma list, checked in order, first present wins |
| `GROUPS_HEADER` | no | `X-Forwarded-Groups` | Header carrying comma-separated group membership |
| `DEFAULT_ROLE` | no | `user` | Role assigned to newly provisioned users |
| `ADMIN_ROLE` | no | `admin` | Role assigned when a user/group match below fires |
| `ADMIN_USERS` | no | (empty) | Comma list of identities to provision as `ADMIN_ROLE` |
| `ADMIN_GROUPS` | no | (empty) | Comma list of groups (from `GROUPS_HEADER`) to provision as `ADMIN_ROLE` |
| `COOKIE_NAME` | no | `session_jwt` | Must match the app's own session cookie name |
| `COOKIE_PATH` | no | `/` | Unused by the bridge directly (cookie is set on a request header, not a Set-Cookie response), kept for documentation/clarity of intent |
| `JWT_SUB_CLAIM` | no | `sub` | Claim name holding the username |
| `JWT_ROLE_CLAIM` | no | `role` | Claim name holding the role; set `""` to omit role from the JWT entirely |
| `JWT_EXPIRY_SECONDS` | no | `28800` (8h) | Token lifetime |
| `PROVISION_ENABLED` | no | `true` | Set `false` to skip user-creation entirely |
| `PROVISION_METHOD` | no | `POST` | HTTP method for the provisioning call |
| `PROVISION_PATH` | no | `/api/users` | Path appended to `UPSTREAM_URL` |
| `PROVISION_BODY_TEMPLATE` | no | `{"username": "{username}", "password": "{password}", "role": "{role}"}` | `{username}`/`{role}`/`{password}` are substituted; `{password}` is a fresh random value nobody needs to know |
| `PROVISION_AUTH_HEADER_NAME` | no | `Authorization` | Header name for the provisioning call's own auth |
| `PROVISION_AUTH_HEADER_VALUE_TEMPLATE` | no | `Bearer {api_token}` | `{api_token}` substituted from `PROVISION_API_TOKEN` |
| `PROVISION_API_TOKEN` | no | (empty) | Value substituted into the auth header template. Named `PROVISION_*`, not `API_TOKEN`, so it can never collide with an env var a target app's own config already owns |
| `PROVISION_TIMEOUT_SECONDS` | no | `5` | Timeout for the provisioning HTTP call |
| `PROVISION_SUCCESS_STATUSES` | no | `200,201,204,400,409,422` | Comma list of status codes treated as "provisioned or already exists" - verify against your app's actual response |

## Worked example: AudioMuse-AI

This is exactly how it's configured in front of this fork's own AudioMuse-AI,
behind oauth2-proxy verifying Pocket ID. Point (1) from "before you deploy
this" was verified directly against `app_auth.py`: session validation looks
up `role` from the `audiomuse_users` table by the JWT's `sub` claim on every
request (`_session_from_token` -> `get_session_user`), and explicitly does
**not** trust the token's own role claim - "the role stored in the database
wins over the role claim inside the token" per its own comment. So a
forged-but-otherwise-valid JWT can only grant whatever role the database
already has for that username; the bridge including a `role` claim in the
JWT it mints is essentially decorative for AudioMuse-AI specifically (kept
in the payload only because `_issue_session_token()`'s shape always has it -
harmless, not load-bearing).

```
UPSTREAM_URL=http://flask:8000
SESSION_JWT_SECRET=<shared with AudioMuse-AI's own JWT_SECRET env var>
PROVISION_API_TOKEN=<shared with AudioMuse-AI's own API_TOKEN env var - grants admin-equivalent Bearer access for provisioning>
COOKIE_NAME=audiomuse_jwt
JWT_SUB_CLAIM=sub
JWT_ROLE_CLAIM=role
JWT_EXPIRY_SECONDS=28800
PROVISION_PATH=/api/users
PROVISION_AUTH_HEADER_VALUE_TEMPLATE=Bearer {api_token}
PROVISION_SUCCESS_STATUSES=200,201,204,400
ADMIN_GROUPS=audiomuse-admin
```

`PROVISION_SUCCESS_STATUSES` includes `400` specifically because
AudioMuse-AI's `POST /api/users` returns `400` (not `409`) for a duplicate
username - confirmed by reading `create_user_endpoint()` in `app_auth.py`,
not guessed.

## How to debug it doing nothing

If requests keep landing on the app's own login page instead of being
silently authenticated:

1. Check the identity header actually arrives at the bridge - log
   `self.headers` in `_proxy()` temporarily, or check your proxy's own
   request logs for what it's forwarding.
2. Confirm `SESSION_JWT_SECRET` matches the app's *actual* configured secret, not
   just what you think you set - a mismatch fails signature verification
   silently from the bridge's point of view (it doesn't get a response back
   saying "bad signature," the app just doesn't recognize the session).
3. Confirm `COOKIE_NAME` matches exactly, including case, what the app's own
   login flow sets.
4. Confirm the provisioning call actually succeeded - check the app's user
   table directly. A wrong `PROVISION_PATH`/`PROVISION_BODY_TEMPLATE`/auth
   header fails the provisioning call, the bridge logs a warning and still
   mints a cookie anyway (by design - don't block auth on provisioning), and
   the app then correctly rejects a session for a username with no row.
