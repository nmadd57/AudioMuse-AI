#!/usr/bin/env python3
# AudioMuse-AI - https://github.com/NeptuneHub/AudioMuse-AI
# Copyright (C) 2025 NeptuneHub
# SPDX-License-Identifier: AGPL-3.0-only
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License v3.0. See the LICENSE file
# in the project root or <https://github.com/NeptuneHub/AudioMuse-AI/blob/main/LICENSE>

"""Generic auth bridge: mints a signed session cookie from an OIDC forward-auth
proxy's identity headers and reverse-proxies to the real app.

Written for AudioMuse-AI's own auth (a POST /login -> HS256 JWT cookie with no
header-trust/SSO support of its own, see docs/AUTH.md), but nothing here is
AudioMuse-specific - every claim name, header name, cookie name, and
provisioning call shape is configurable via env vars, so this works as a
bridge in front of any app whose session mechanism is "HS256 JWT in a
cookie, validated by looking up the subject claim's username in a user
table it owns." That covers a fair number of self-hosted apps with their
own local user tables and no native OIDC/header-trust support.

This sits behind a forward-auth proxy (oauth2-proxy, Authelia, Authentik,
etc.) that has already verified the human against your OIDC provider of
choice and forwards identity as a header on the proxied request - which
one depends entirely on how you configured that proxy, not on which OIDC
server issued the original login.

IMPORTANT - read before deploying: this only works if you have verified,
by inspecting the actual target app's auth code, three specific things:
  (a) the app's session-validation looks up the *current* app-side user
      record by the sub claim's value (i.e. it does NOT just trust
      whatever role/permissions are embedded in the JWT itself - if it
      does, this shim can hand out privilege the app's own DB never
      granted);
  (b) the cookie name, claim shape, and signing algorithm the app's own
      login flow actually issues, matched exactly here; and
  (c) how the app signals "already exists" on repeat provisioning calls
      (PROVISION_SUCCESS_STATUSES needs to include that code, or every
      returning user re-triggers a failed provisioning attempt every
      request).
Get any of these wrong and you get silent auth bypass or silent breakage,
not a helpful error. AudioMuse-AI's own values are documented in
README.md in this directory as a worked example.

Main Features:
* For every request carrying a configured identity header: optionally
  auto-provisions a user for that identity in the target app (an HTTP call
  - method/path/body/auth header/success-codes are all configurable, or
  skip entirely with PROVISION_ENABLED=false), mints a JWT ({SUB_CLAIM:
  identity, ROLE_CLAIM: role, iat, exp}, HS256, SESSION_JWT_SECRET) and
  injects it as a cookie named COOKIE_NAME on the proxied request, then
  forwards the request to UPSTREAM_URL - which sees an ordinary valid
  session and never knows the shim exists.
* Deliberately stdlib-only (no pip install at container start, no build
  step) - HS256 signing is ~10 lines of hmac+base64, not worth a
  dependency for this.
* Deliberately has NO in-memory "already provisioned" cache: an earlier
  AudioMuse-AI-specific version of this had one, and it went stale the
  moment a user's app-side row was deleted out-of-band (manual cleanup,
  role fix, etc) - the shim kept assuming the user still existed, cookies
  kept minting for an identity that resolved to nothing, and the app
  correctly bounced every request back to its own login. The provisioning
  call is meant to be a cheap idempotent upsert, so just making it every
  request is the correct default.
"""

import base64
import hashlib
import hmac
import json
import os
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# All config below is read from the environment inside load_config(), called
# from __main__ - not at module import time. Every name here is only ever
# read (never written) outside load_config(), so declaring them as plain
# module globals and populating them via `global` there is enough; nothing
# in this module executes at import time beyond class/def statements, so a
# bare `import shim` works without any env vars set (required for
# test/unit/test_import_smoke.py's blanket importability check).
UPSTREAM_URL = SESSION_JWT_SECRET = PORT = None
IDENTITY_HEADERS = GROUPS_HEADER = None
DEFAULT_ROLE = ADMIN_ROLE = ADMIN_USERS = ADMIN_GROUPS = None
COOKIE_NAME = COOKIE_PATH = JWT_SUB_CLAIM = JWT_ROLE_CLAIM = JWT_EXPIRY_SECONDS = None
PROVISION_ENABLED = PROVISION_METHOD = PROVISION_PATH = PROVISION_TIMEOUT_SECONDS = None
PROVISION_BODY_TEMPLATE = PROVISION_AUTH_HEADER_NAME = PROVISION_AUTH_HEADER_VALUE_TEMPLATE = None
PROVISION_API_TOKEN = PROVISION_SUCCESS_STATUSES = None


def load_config() -> None:
    global UPSTREAM_URL, SESSION_JWT_SECRET, PORT, IDENTITY_HEADERS, GROUPS_HEADER
    global DEFAULT_ROLE, ADMIN_ROLE, ADMIN_USERS, ADMIN_GROUPS
    global COOKIE_NAME, COOKIE_PATH, JWT_SUB_CLAIM, JWT_ROLE_CLAIM, JWT_EXPIRY_SECONDS
    global PROVISION_ENABLED, PROVISION_METHOD, PROVISION_PATH, PROVISION_TIMEOUT_SECONDS
    global PROVISION_BODY_TEMPLATE, PROVISION_AUTH_HEADER_NAME, PROVISION_AUTH_HEADER_VALUE_TEMPLATE
    global PROVISION_API_TOKEN, PROVISION_SUCCESS_STATUSES

    # --- Core wiring ---
    UPSTREAM_URL = os.environ["UPSTREAM_URL"].rstrip("/")
    SESSION_JWT_SECRET = os.environ["SESSION_JWT_SECRET"]
    PORT = int(os.environ.get("PORT", "8001"))

    # --- Identity headers (set by your forward-auth proxy, not by the OIDC
    # server directly - check your proxy's docs for what it actually
    # forwards to the upstream request, which is often NOT the same header
    # family it uses for e.g. nginx auth_request responses. This bit
    # oauth2-proxy users once already: --set-xauthrequest only decorates an
    # auth_request subrequest response, never the proxied request itself.)
    IDENTITY_HEADERS = tuple(
        h.strip()
        for h in os.environ.get(
            "IDENTITY_HEADERS",
            "X-Forwarded-Email,X-Forwarded-Preferred-Username,X-Forwarded-User",
        ).split(",")
        if h.strip()
    )
    GROUPS_HEADER = os.environ.get("GROUPS_HEADER", "X-Forwarded-Groups")

    # --- Role assignment (only takes effect when provisioning a brand-new
    # user - see the module docstring's point (a) for why role changes to
    # an already-provisioned identity may not retroactively apply; that's a
    # property of the target app, this shim can't fix it generically) ---
    DEFAULT_ROLE = os.environ.get("DEFAULT_ROLE", "user")
    ADMIN_ROLE = os.environ.get("ADMIN_ROLE", "admin")
    ADMIN_USERS = {
        u.strip().lower() for u in os.environ.get("ADMIN_USERS", "").split(",") if u.strip()
    }
    ADMIN_GROUPS = {
        g.strip().lower() for g in os.environ.get("ADMIN_GROUPS", "").split(",") if g.strip()
    }

    # --- JWT shape ---
    COOKIE_NAME = os.environ.get("COOKIE_NAME", "session_jwt")
    COOKIE_PATH = os.environ.get("COOKIE_PATH", "/")
    JWT_SUB_CLAIM = os.environ.get("JWT_SUB_CLAIM", "sub")
    JWT_ROLE_CLAIM = os.environ.get("JWT_ROLE_CLAIM", "role")  # "" omits role from the JWT
    JWT_EXPIRY_SECONDS = int(os.environ.get("JWT_EXPIRY_SECONDS", str(8 * 3600)))

    # --- Provisioning (optional) ---
    PROVISION_ENABLED = os.environ.get("PROVISION_ENABLED", "true").lower() == "true"
    PROVISION_METHOD = os.environ.get("PROVISION_METHOD", "POST")
    PROVISION_PATH = os.environ.get("PROVISION_PATH", "/api/users")
    PROVISION_TIMEOUT_SECONDS = float(os.environ.get("PROVISION_TIMEOUT_SECONDS", "5"))
    # {username}/{role}/{password} are substituted in. {password} is a
    # fresh random value on every call - the point of this bridge is that
    # nobody ever needs to know or use it, the cookie is the only
    # credential that matters.
    PROVISION_BODY_TEMPLATE = os.environ.get(
        "PROVISION_BODY_TEMPLATE",
        '{"username": "{username}", "password": "{password}", "role": "{role}"}',
    )
    PROVISION_AUTH_HEADER_NAME = os.environ.get("PROVISION_AUTH_HEADER_NAME", "Authorization")
    PROVISION_AUTH_HEADER_VALUE_TEMPLATE = os.environ.get(
        "PROVISION_AUTH_HEADER_VALUE_TEMPLATE", "Bearer {api_token}"
    )
    # Named PROVISION_* (not API_TOKEN) so it can never collide with an
    # env var a target app's own config already owns - AudioMuse-AI itself
    # has an API_TOKEN, and this bridge's copy of that value is a distinct
    # concern (the provisioning call's own credential) even when it happens
    # to be set to the same value in the worked example.
    PROVISION_API_TOKEN = os.environ.get("PROVISION_API_TOKEN", "")
    # Codes to treat as "provisioning succeeded or user already existed" -
    # every app signals "already exists" differently (400, 409, 422...) and
    # getting this wrong means every returning user's request pays for one
    # failed provisioning call. Check your target app's actual response
    # code for a duplicate-user create before deploying.
    PROVISION_SUCCESS_STATUSES = {
        int(s.strip())
        for s in os.environ.get(
            "PROVISION_SUCCESS_STATUSES", "200,201,204,400,409,422"
        ).split(",")
        if s.strip()
    }


HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
}


def _b64url(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def mint_jwt(username: str, role: str) -> str:
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    now = int(time.time())
    payload_obj = {JWT_SUB_CLAIM: username, "iat": now, "exp": now + JWT_EXPIRY_SECONDS}
    if JWT_ROLE_CLAIM:
        payload_obj[JWT_ROLE_CLAIM] = role
    payload = _b64url(json.dumps(payload_obj, separators=(",", ":")).encode())
    signing_input = header + b"." + payload
    sig = _b64url(hmac.new(SESSION_JWT_SECRET.encode(), signing_input, hashlib.sha256).digest())
    return (signing_input + b"." + sig).decode()


def sanitize_username(raw: str) -> str:
    return raw.strip().lower()[:128]


def ensure_user(username: str, role: str) -> None:
    if not PROVISION_ENABLED:
        return
    body = PROVISION_BODY_TEMPLATE.format(
        username=username,
        role=role,
        password=base64.urlsafe_b64encode(os.urandom(24)).decode(),
    ).encode()
    headers = {"Content-Type": "application/json"}
    if PROVISION_AUTH_HEADER_NAME:
        headers[PROVISION_AUTH_HEADER_NAME] = PROVISION_AUTH_HEADER_VALUE_TEMPLATE.format(
            api_token=PROVISION_API_TOKEN
        )
    req = urllib.request.Request(
        f"{UPSTREAM_URL}{PROVISION_PATH}", data=body, method=PROVISION_METHOD, headers=headers
    )
    try:
        with urllib.request.urlopen(req, timeout=PROVISION_TIMEOUT_SECONDS) as resp:
            resp.read()
    except urllib.error.HTTPError as e:
        e.read()
        if e.code not in PROVISION_SUCCESS_STATUSES:
            logger_warn(
                f"provisioning {username!r} got unexpected status {e.code} "
                f"(not in PROVISION_SUCCESS_STATUSES={sorted(PROVISION_SUCCESS_STATUSES)})"
            )
    except Exception as exc:
        logger_warn(f"provisioning {username!r} failed: {exc}")


def logger_warn(msg: str) -> None:
    print(f"[oidc-session-bridge] WARNING: {msg}", flush=True)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _proxy(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else None

        identity = None
        for h in IDENTITY_HEADERS:
            v = self.headers.get(h)
            if v:
                identity = sanitize_username(v)
                break

        headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP_BY_HOP}

        if identity:
            groups = {g.strip().lower() for g in self.headers.get(GROUPS_HEADER, "").split(",") if g.strip()}
            role = ADMIN_ROLE if (identity in ADMIN_USERS or groups & ADMIN_GROUPS) else DEFAULT_ROLE
            ensure_user(identity, role)
            token = mint_jwt(identity, role)
            existing = headers.get("Cookie", "")
            kept = [c.strip() for c in existing.split(";") if c.strip() and not c.strip().startswith(f"{COOKIE_NAME}=")]
            kept.append(f"{COOKIE_NAME}={token}")
            headers["Cookie"] = "; ".join(kept)

        req = urllib.request.Request(f"{UPSTREAM_URL}{self.path}", data=body, method=self.command, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                self.send_response(resp.status)
                for k, v in resp.getheaders():
                    if k.lower() not in HOP_BY_HOP:
                        self.send_header(k, v)
                self.end_headers()
                self.wfile.write(resp.read())
        except urllib.error.HTTPError as e:
            self.send_response(e.code)
            for k, v in e.headers.items():
                if k.lower() not in HOP_BY_HOP:
                    self.send_header(k, v)
            self.end_headers()
            self.wfile.write(e.read())
        except Exception as e:
            resp_body = f"oidc-session-bridge upstream error: {e}".encode()
            self.send_response(502)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(resp_body)))
            self.end_headers()
            self.wfile.write(resp_body)

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = _proxy

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    load_config()
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
