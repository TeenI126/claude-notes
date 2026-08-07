# Adding Google Sign-In to an MCP server

How the Google login in `server.py` works, and what to repeat to put the same
thing in front of another MCP service. Written from actually doing it — the
pitfalls near the end are the ones that cost time, not hypotheticals.

## What this pattern is

The MCP server stays its own OAuth 2.0 authorization server. Clients keep
discovering it via RFC 8414 metadata, keep doing PKCE, keep redeeming codes at
`/oauth/token` for bearer tokens it signs itself. **None of the MCP-facing
contract changes.**

The only thing that moves is the step where a *human* proves identity. That was
"paste the shared `AUTH_TOKEN` into a form"; it becomes "sign in with Google,
and be on an allowlist."

```
MCP client ──GET /oauth/authorize──▶ your server
                                      │ 302, grant details in signed `state`
                                      ▼
                                   Google login
                                      │ 302 back with Google's code
                                      ▼
              your server ◀──GET /oauth/google/callback
                    │ exchange code → ID token → verify → check allowlist
                    │ 302 to the client's redirect_uri with YOUR auth code
                    ▼
MCP client ──POST /oauth/token──▶ your server → bearer token
```

### What it buys, and what it doesn't

Buys: no shared secret in the connector config, access revocable per Google
account, an audit trail, and a real identity behind each authorization.

Does **not** buy: retirement of the shared secret. `AUTH_TOKEN` remains a
full-access bearer credential on the `?token=` path, because non-interactive
clients (an iOS Scriptable script, a cron job) can't complete a browser login.
This narrows where the secret has to live. It doesn't remove it. Be honest with
yourself about that when deciding whether it's worth the work.

## Step 1 — Google OAuth client (console, once)

1. [APIs & Services → Credentials](https://console.cloud.google.com/apis/credentials)
   → **Create Credentials** → **OAuth client ID** → **Web application**.
2. Configure the consent screen if prompted: **External**, add yourself as a
   test user, leave it in **Testing**. No verification review is needed for a
   personal allowlist — publishing is what triggers that.
3. Authorized redirect URIs: `https://<host>/oauth/google/callback`.

Google matches redirect URIs **exactly** — not by prefix, not ignoring
trailing slashes. Cloud Run answers on two hostnames
(`SERVICE-PROJECTNUMBER.REGION.run.app` and `SERVICE-HASH-uc.a.run.app`), and
a client may arrive on either. Register **both**, or set `PUBLIC_URL` to pin
one. Check `run.googleapis.com/urls` in the service annotations for the full
list.

### Reusing this client for a second service

You can. Add the new service's callback URL to the **same** OAuth client's
redirect URI list — one client supports many. The `client_id` and
`client_secret` are then shared, and so is the consent screen.

That's fine, and it's the least work. The thing to *not* share is covered in
Pitfall 6.

## Step 2 — Secret Manager

The client ID is public (it ships in redirect URLs); the secret is not.

```bash
printf '%s' 'GOCSPX-...' | gcloud secrets create <service>-google-client-secret \
  --project=PROJECT --replication-policy=automatic --data-file=-

gcloud secrets add-iam-policy-binding <service>-google-client-secret --project=PROJECT \
  --member=serviceAccount:RUNTIME_SA@PROJECT.iam.gserviceaccount.com \
  --role=roles/secretmanager.secretAccessor
```

`printf '%s'`, never `echo` — see Pitfall 1.

The accessor binding is on the *secret*, granted to the *runtime service
account*, not to you. Being able to read the secret yourself proves nothing
about whether the service can.

## Step 3 — Configuration and startup guards

```python
GOOGLE_CLIENT_ID      = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET  = os.environ.get("GOOGLE_CLIENT_SECRET", "")
ALLOWED_GOOGLE_EMAILS = frozenset(
    e.strip().lower()
    for e in os.environ.get("ALLOWED_GOOGLE_EMAILS", "").split(",")
    if e.strip()
)

def _google_signin_enabled() -> bool:
    return bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET and ALLOWED_GOOGLE_EMAILS)
```

All three, or the feature stays off. That makes the code safe to deploy before
the Google client exists.

Then refuse to start on the dangerous half-configurations:

```python
if (GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET) and not ALLOWED_GOOGLE_EMAILS:
    raise SystemExit("...would admit any Google account")
if (GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET) and not (GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET):
    raise SystemExit("both or neither")
```

A configured Google client with an empty allowlist authenticates *any* Google
account on earth and authorizes it — strictly worse than the password form it
replaced. Crash instead.

On Cloud Run this guard doubles as verification: traffic only shifts to a
revision whose container came up, so "revision Ready" proves the config is
sane. Same trick works for `AUTH_TOKEN` itself.

## Step 4 — Hand off to Google

In `GET /oauth/authorize`, after the usual `response_type` / `redirect_uri` /
PKCE validation:

```python
pending = _encode_signed("gstate", {
    "cid": client_id, "uri": redirect_uri, "st": state,
    "cc": code_challenge, "ccm": code_challenge_method,
}, 600)
query = urllib.parse.urlencode({
    "client_id":     GOOGLE_CLIENT_ID,
    "redirect_uri":  f"{_server_url(request)}/oauth/google/callback",
    "response_type": "code",
    "scope":         "openid email",
    "state":         pending,
    "prompt":        "select_account",
})
return Response(302, headers={"Location": f"{_GOOGLE_AUTH_URL}?{query}"})
```

**The signed `state` is the important part.** The MCP client's grant details
have to survive a round trip through Google. Putting them in an HMAC-signed,
expiring blob that travels *through* Google's `state` parameter means no
server-side pending-login store — which matters on any autoscaled platform,
where the authorize and callback requests may hit different instances. See
Pitfall 5.

`prompt=select_account` avoids silently reusing a wrong Google session when
you're signed into several.

## Step 5 — The callback

```python
pending = _decode_signed("gstate", params.get("state", ""))   # 400 if None
email   = await asyncio.to_thread(_google_exchange_and_verify, code, redirect_uri)
if email not in ALLOWED_GOOGLE_EMAILS:                        # 403
    ...
our_code = _issue_auth_code(pending["cid"], pending["uri"], pending["cc"], pending["ccm"])
# 302 to pending["uri"] with our_code + pending["st"]
```

The exchange and verification:

```python
from google.oauth2 import id_token as google_id_token
from google.auth.transport import requests as google_requests

# POST to https://oauth2.googleapis.com/token with code, client_id,
# client_secret, redirect_uri, grant_type=authorization_code
claims = google_id_token.verify_oauth2_token(
    raw_id_token, google_requests.Request(), GOOGLE_CLIENT_ID,
)
if not claims.get("email_verified"):
    return None
return claims["email"].strip().lower()
```

Use `google-auth` rather than decoding the JWT yourself. It checks the RS256
signature against Google's rotating JWKS plus `iss`/`aud`/`exp`. OIDC does
permit trusting a token received directly over TLS from the token endpoint,
but the library is a few lines and removes a class of subtle mistakes.

`email_verified` is not optional — check it. Compare emails lowercased.

It's blocking (HTTP + RSA), so run it off the event loop.

## Step 6 — Disable the password form

```python
if _google_signin_enabled():
    return _notice_page("Sign in with Google", "...", 400)   # in the POST branch
```

Easy to forget, and it undoes the whole exercise: leaving the form live keeps
`AUTH_TOKEN` working as an interactive password that bypasses the allowlist.

## Step 7 — Deploy

```bash
--set-env-vars GOOGLE_CLIENT_ID=...apps.googleusercontent.com \
--set-env-vars ALLOWED_GOOGLE_EMAILS=you@gmail.com \
--set-secrets  GOOGLE_CLIENT_SECRET=<service>-google-client-secret:latest
```

Deploy to a no-traffic revision first. A missing or unreadable secret fails
revision creation, which is harmless when nothing is routed to it.

## Step 8 — Verify from request logs, not from the UI

A client-side error string tells you almost nothing. The server's access log
tells you exactly which stage failed. A healthy flow:

| Request | Status |
|---|---|
| `POST /mcp` | `401` (unauthenticated probe) |
| `GET /.well-known/oauth-protected-resource/mcp` | `200` |
| `POST /oauth/register` | `201` |
| `GET /oauth/authorize` | `302` (handoff to Google) |
| `GET /oauth/google/callback` | `302` (verified + allowlisted) |
| `POST /oauth/token` | `200` |
| `POST /mcp` | `200` / `202` |

Callback failures are diagnostic:

- `502` — token exchange with Google failed → wrong client secret (Pitfall 1)
- `403` — signed in fine, email not on the allowlist, or `email_verified` false
- `400` — bad/expired `state`; login took longer than the TTL

```bash
gcloud logging read \
  'resource.type="cloud_run_revision" AND resource.labels.service_name="SERVICE"
   AND httpRequest.requestUrl!=""' \
  --project PROJECT --limit 30 --freshness=1h \
  --format='table[no-heading](timestamp.date("%H:%M:%S"), httpRequest.requestMethod,
            httpRequest.status, httpRequest.requestUrl)'
```

This needs `roles/logging.viewer` on whatever identity runs it. Grant it before
you need it.

## Pitfalls

**1. Trailing newline in the client secret.** `echo` appends one; it becomes
part of the secret; every token exchange fails with `invalid_client`. Nothing
in that error hints at whitespace. Always `printf '%s'`.

**2. Redirect URI mismatch.** Exact string match. Register every hostname the
service answers on, or pin `PUBLIC_URL`.

**3. Empty allowlist.** Covered above, worth repeating: it authenticates the
whole world. Guard at startup.

**4. Deriving the redirect URI from the `Host` header.** Necessary on Cloud Run
(no fixed external-URL env var, several hostnames), but it means the URI
depends on how the client arrived. If a request comes in on an unregistered
hostname, Google rejects it. Same root cause as Pitfall 2.

**5. Server-side pending-login state.** Storing the in-flight grant in a
process dict breaks whenever authorize and callback land on different
instances, and the Google round trip widens that window to however long a human
takes to log in. Sign it into `state` instead. (This exact bug existed here for
auth codes and produced intermittent `invalid_grant` — invisible in local
single-process testing.)

**6. Sharing `AUTH_TOKEN` between services.** The relevant one for your second
service. `_sign(purpose, data)` keys the HMAC on `AUTH_TOKEN` and separates
domains only by a purpose string — *not* by service. Two services sharing an
`AUTH_TOKEN` will happily accept each other's access tokens and authorization
codes, because the signatures verify identically. A token minted by one is a
valid credential on the other.

Sharing the Google OAuth *client* is fine — that's just an identity provider
registration. Sharing `AUTH_TOKEN` silently merges two services' trust
boundaries. Either give each service its own, or add the service's own URL as
an `aud` claim in the signed payload and check it on verify.
