"""
Claude Notes MCP Server
FastMCP with Streamable HTTP transport (MCP spec 2025-03-26).
Notes are stored in a GitHub repo for persistence across deploys.
Includes a two-way Apple Reminders sync system (via Scriptable on iOS).
OAuth 2.0 authorization server with PKCE (RFC 7636) for MCP clients.
"""

import os
import json
import uuid
import hmac
import hashlib
import secrets
import base64
import time
import html as html_mod
import asyncio
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from github import Github, GithubException
from mcp.server.fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.types import ASGIApp, Receive, Scope, Send
from starlette.routing import Route, Mount
from starlette.requests import Request
from starlette.responses import Response, JSONResponse, HTMLResponse
import uvicorn

# ── Disable FastMCP's DNS-rebinding transport security ────────────────────────

from mcp.server.transport_security import (
    TransportSecurityMiddleware,
    TransportSecuritySettings,
)

_original_ts_init = TransportSecurityMiddleware.__init__

def _init_no_dns_rebinding(self, settings=None):
    _original_ts_init(
        self,
        TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )

TransportSecurityMiddleware.__init__ = _init_no_dns_rebinding

# ── Config ────────────────────────────────────────────────────────────────────

AUTH_TOKEN    = os.environ.get("AUTH_TOKEN", "")
GITHUB_TOKEN  = os.environ.get("GITHUB_TOKEN", "")
GITHUB_REPO   = os.environ.get("GITHUB_REPO", "")

# Cloud Run has no equivalent of Render's RENDER_EXTERNAL_URL — the service's
# hostname isn't known until after the first deploy, and one service answers on
# several of them (the base URL, a `preview---` tag URL, any custom domain). So
# the OAuth metadata below derives the base URL per-request from the Host header
# instead of a fixed value; PUBLIC_URL pins it explicitly if that's ever wrong.
PUBLIC_URL    = (os.environ.get("PUBLIC_URL", "")).rstrip("/")
FALLBACK_URL  = PUBLIC_URL or "http://localhost:8000"

# Google Sign-In. When all three are set, the human half of the OAuth flow — the
# form that asks for AUTH_TOKEN — is replaced by a Google login restricted to
# ALLOWED_GOOGLE_EMAILS. Everything the MCP client sees is unchanged: this server
# is still its authorization server, still issues its own PKCE-bound codes and
# bearer tokens. Only the step where a human proves who they are moves to Google.
#
# Note what this does and does not buy: the interactive path stops involving a
# shared secret, but AUTH_TOKEN remains a full-access bearer credential on the
# `?token=` path because Scriptable on iOS cannot do an interactive login.
GOOGLE_CLIENT_ID      = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET  = os.environ.get("GOOGLE_CLIENT_SECRET", "")
ALLOWED_GOOGLE_EMAILS = frozenset(
    e.strip().lower()
    for e in os.environ.get("ALLOWED_GOOGLE_EMAILS", "").split(",")
    if e.strip()
)


def _google_signin_enabled() -> bool:
    return bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET and ALLOWED_GOOGLE_EMAILS)


def _server_url(request: Request) -> str:
    """Base URL that clients should use to reach this server."""
    if PUBLIC_URL:
        return PUBLIC_URL
    host = request.headers.get("host")
    if not host:
        return FALLBACK_URL
    # Cloud Run terminates TLS at the edge and forwards over plain HTTP, so
    # request.url.scheme alone would advertise http:// URLs to OAuth clients.
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    return f"{proto}://{host}"

REMINDERS_PATH = "_system/reminders.json"

# ── OAuth constants ───────────────────────────────────────────────────────────

_ACCESS_TOKEN_TTL = 3600   # 1 hour
_AUTH_CODE_TTL    = 600    # 10 minutes

# Best-effort replay guard for authorization codes, keyed by the code's jti.
# Codes are stateless (see below), so single-use can't be enforced by deleting a
# stored row the way it used to be. This catches a replay that happens to land on
# the same instance; PKCE is what actually makes replay unexploitable, since an
# intercepted code is worthless without the client's code_verifier.
_used_auth_codes: dict[str, float] = {}

# ── Signed-token helpers ──────────────────────────────────────────────────────

def _sign(purpose: str, data: str) -> str:
    """Domain-separated HMAC-SHA256 over `data`.

    Access tokens and authorization codes are both signed with AUTH_TOKEN and
    share an envelope, so without the purpose prefix an authorization code would
    verify as a valid bearer token — it carries a signature and an unexpired
    `exp`, which is everything the old access-token check looked at.
    """
    return hmac.new(AUTH_TOKEN.encode(), f"{purpose}:{data}".encode(), hashlib.sha256).hexdigest()


def _encode_signed(purpose: str, payload: dict, ttl: int) -> str:
    """Pack a payload plus expiry into `base64url(json).hexsig`."""
    body = dict(payload, iat=int(time.time()), exp=int(time.time()) + ttl)
    raw  = json.dumps(body, separators=(",", ":")).encode()
    data = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    return f"{data}.{_sign(purpose, data)}"


def _decode_signed(purpose: str, token: str) -> dict | None:
    """Return the payload iff the signature matches `purpose` and it's unexpired."""
    if not AUTH_TOKEN:
        return None
    try:
        data, sig = token.rsplit(".", 1)
        if not hmac.compare_digest(sig, _sign(purpose, data)):
            return None
        padding = (4 - len(data) % 4) % 4
        payload = json.loads(base64.urlsafe_b64decode(data + "=" * padding))
    except Exception:
        return None
    if not isinstance(payload, dict) or payload.get("exp", 0) < int(time.time()):
        return None
    return payload

# ── OAuth token helpers ───────────────────────────────────────────────────────

def _issue_access_token(client_id: str) -> str:
    """Return an HMAC-SHA256-signed access token. Stateless — survives restarts."""
    return _encode_signed("access", {"sub": client_id}, _ACCESS_TOKEN_TTL)


def _verify_access_token(token: str) -> bool:
    """Return True if the token has a valid HMAC signature and is unexpired."""
    return _decode_signed("access", token) is not None


def _issue_auth_code(
    client_id: str,
    redirect_uri: str,
    code_challenge: str,
    code_challenge_method: str,
) -> str:
    """Return a signed authorization code carrying its own grant details.

    These used to live in a process-level dict, which quietly breaks on Cloud
    Run: /oauth/authorize and /oauth/token are separate requests, so with more
    than one instance the exchange can land somewhere that never saw the code.
    Signing the grant into the code itself removes the shared state entirely.
    """
    return _encode_signed("code", {
        "cid": client_id,
        "uri": redirect_uri,
        "cc":  code_challenge,
        "ccm": code_challenge_method,
        "jti": secrets.token_urlsafe(8),
    }, _AUTH_CODE_TTL)


def _consume_auth_code(code: str) -> dict | None:
    """Validate an authorization code and mark it used on this instance."""
    payload = _decode_signed("code", code)
    if payload is None:
        return None

    now = time.time()
    for jti, expiry in list(_used_auth_codes.items()):
        if expiry < now:
            del _used_auth_codes[jti]

    jti = payload.get("jti", "")
    if jti in _used_auth_codes:
        return None
    _used_auth_codes[jti] = payload.get("exp", now)
    return payload

# ── FastMCP ───────────────────────────────────────────────────────────────────

mcp = FastMCP("claude-notes")

# ── GitHub helpers ────────────────────────────────────────────────────────────

def _get_repo():
    return Github(GITHUB_TOKEN).get_repo(GITHUB_REPO)

def _safe_filename(filename: str) -> str | None:
    """Validate a user-facing filename.  Blocks path traversal AND the
    _system/ directory where internal data (reminders.json) lives."""
    name = filename.strip()
    if not name or "/" in name or "\\" in name or name.startswith("."):
        return None
    if name.startswith("_system"):
        return None
    return name

# ── Reminders storage helpers ────────────────────────────────────────────────

def _empty_reminders() -> dict:
    return {
        "version": 1,
        "last_sync_at": None,
        "reminders": {},
        "pending_completions": [],
        "pending_additions": [],
    }

def _read_reminders(repo=None) -> tuple[dict, str | None]:
    """Read _system/reminders.json.  Returns (data, sha).
    If the file doesn't exist yet returns (empty_structure, None)."""
    repo = repo or _get_repo()
    try:
        contents = repo.get_contents(REMINDERS_PATH)
        data = json.loads(contents.decoded_content.decode("utf-8"))
        return data, contents.sha
    except GithubException as e:
        if e.status == 404:
            return _empty_reminders(), None
        raise

def _write_reminders(data: dict, sha: str | None, repo=None) -> None:
    """Create or update _system/reminders.json on GitHub."""
    repo = repo or _get_repo()
    blob = json.dumps(data, indent=2, ensure_ascii=False)
    if sha:
        repo.update_file(REMINDERS_PATH, "Update reminders", blob, sha)
    else:
        repo.create_file(REMINDERS_PATH, "Create reminders", blob)

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

# ── Note file MCP tools ─────────────────────────────────────────────────────

@mcp.tool()
async def list_files() -> str:
    """List all your note files."""
    def _run():
        repo = _get_repo()
        contents = repo.get_contents("")
        files = sorted([c for c in contents if c.type == "file"], key=lambda x: x.name)
        if not files:
            return "No files yet."
        return "\n".join(f"{c.name}  ({c.size} bytes)" for c in files)
    return await asyncio.to_thread(_run)


@mcp.tool()
async def read_file(filename: str) -> str:
    """Read the contents of one of your note files."""
    name = _safe_filename(filename)
    if name is None:
        return "Error: invalid filename."
    def _run():
        try:
            return _get_repo().get_contents(name).decoded_content.decode("utf-8")
        except GithubException as e:
            if e.status == 404:
                return f"Error: '{name}' does not exist."
            raise
    return await asyncio.to_thread(_run)


@mcp.tool()
async def write_file(filename: str, content: str) -> str:
    """Create or fully overwrite a note file with new content."""
    name = _safe_filename(filename)
    if name is None:
        return "Error: invalid filename."
    def _run():
        repo = _get_repo()
        try:
            existing = repo.get_contents(name)
            repo.update_file(name, f"Update {name}", content, existing.sha)
        except GithubException as e:
            if e.status == 404:
                repo.create_file(name, f"Create {name}", content)
            else:
                raise
        return f"Written {len(content)} chars to '{name}'."
    return await asyncio.to_thread(_run)


@mcp.tool()
async def append_to_file(filename: str, content: str) -> str:
    """Append text to the end of a note file (creates it if it doesn't exist)."""
    name = _safe_filename(filename)
    if name is None:
        return "Error: invalid filename."
    def _run():
        repo = _get_repo()
        try:
            existing = repo.get_contents(name)
            current = existing.decoded_content.decode("utf-8")
            repo.update_file(name, f"Append to {name}", current + content, existing.sha)
        except GithubException as e:
            if e.status == 404:
                repo.create_file(name, f"Create {name}", content)
            else:
                raise
        return f"Appended to '{name}'."
    return await asyncio.to_thread(_run)


@mcp.tool()
async def delete_file(filename: str) -> str:
    """Delete a note file."""
    name = _safe_filename(filename)
    if name is None:
        return "Error: invalid filename."
    def _run():
        repo = _get_repo()
        try:
            existing = repo.get_contents(name)
            repo.delete_file(name, f"Delete {name}", existing.sha)
            return f"Deleted '{name}'."
        except GithubException as e:
            if e.status == 404:
                return f"Error: '{name}' does not exist."
            raise
    return await asyncio.to_thread(_run)

# ── Reminder MCP tools ───────────────────────────────────────────────────────

PRIORITY_LABELS = {0: "", 1: " [high priority]", 5: " [medium priority]", 9: " [low priority]"}


@mcp.tool()
async def list_reminders() -> str:
    """List all pending reminders from the Apple Reminders sync.
    Shows reminders grouped by list with due dates, priorities, and notes."""
    def _run():
        data, _ = _read_reminders()
        reminders = data.get("reminders", {})
        pending_adds = data.get("pending_additions", [])

        if not reminders and not pending_adds:
            return "No reminders synced yet. The Scriptable sync script needs to run at least once."

        # Collect all items: synced reminders + pending additions
        items = []
        for r in reminders.values():
            items.append({**r, "_pending": False})
        for pa in pending_adds:
            items.append({
                "identifier": pa["server_id"],
                "title": pa["title"],
                "notes": pa.get("notes", ""),
                "due_date": pa.get("due_date"),
                "priority": pa.get("priority", 0),
                "list_name": pa.get("list_name", "Reminders"),
                "is_overdue": False,
                "_pending": True,
            })

        # Group by list
        by_list: dict[str, list] = {}
        for item in items:
            ln = item.get("list_name", "Reminders")
            by_list.setdefault(ln, []).append(item)

        lines = []
        for list_name in sorted(by_list):
            group = by_list[list_name]
            # Sort: overdue first, then by due_date, then no-date last
            def sort_key(r):
                if r.get("is_overdue"):
                    return "0000"
                if r.get("due_date"):
                    return r["due_date"]
                return "9999"
            group.sort(key=sort_key)

            lines.append(f"## {list_name} ({len(group)} reminder{'s' if len(group) != 1 else ''})")
            for r in group:
                pri = PRIORITY_LABELS.get(r.get("priority", 0), "")
                due = ""
                if r.get("due_date"):
                    try:
                        dt = datetime.fromisoformat(r["due_date"])
                        due = f" -- due {dt.strftime('%b %-d')}"
                    except Exception:
                        due = f" -- due {r['due_date']}"
                if r.get("is_overdue"):
                    due += " (OVERDUE)"
                pending = "  [pending sync to Apple]" if r.get("_pending") else ""
                lines.append(f"- {r['title']}{due}{pri}{pending}")
                lines.append(f"  ID: {r['identifier']}")
                if r.get("notes"):
                    for nl in r["notes"].strip().split("\n"):
                        lines.append(f"  > {nl}")
            lines.append("")

        sync_time = data.get("last_sync_at", "never")
        lines.append(f"_Last synced with Apple: {sync_time}_")
        return "\n".join(lines)

    return await asyncio.to_thread(_run)


@mcp.tool()
async def add_reminder(
    title: str,
    notes: str = "",
    due_date: str = "",
    priority: int = 0,
    list_name: str = "Reminders",
) -> str:
    """Create a new reminder that will sync to Apple Reminders.
    priority: 0=none, 1=high, 5=medium, 9=low.
    due_date: ISO format (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS).
    list_name: the Apple Reminders list to add it to (default: Reminders)."""
    if priority not in (0, 1, 5, 9):
        return f"Error: priority must be 0 (none), 1 (high), 5 (medium), or 9 (low). Got {priority}."

    if due_date:
        try:
            datetime.fromisoformat(due_date)
        except ValueError:
            return f"Error: due_date '{due_date}' is not valid ISO 8601."

    def _run():
        for attempt in range(2):
            data, sha = _read_reminders()
            server_id = f"claude-{uuid.uuid4().hex[:8]}"
            data["pending_additions"].append({
                "server_id": server_id,
                "title": title,
                "notes": notes,
                "due_date": due_date or None,
                "priority": priority,
                "list_name": list_name,
                "created_at": _now_iso(),
            })
            try:
                _write_reminders(data, sha)
                return f"Reminder added: '{title}' (ID: {server_id}). It will appear in Apple Reminders after the next sync."
            except GithubException as e:
                if e.status == 409 and attempt == 0:
                    continue
                raise

    return await asyncio.to_thread(_run)


@mcp.tool()
async def complete_reminder(identifier: str) -> str:
    """Mark a reminder as completed.  If it came from Apple it will be
    completed there on the next sync.  If it was added by Claude and hasn't
    synced yet it's simply removed."""
    def _run():
        for attempt in range(2):
            data, sha = _read_reminders()

            # Case 1: reminder is in the synced dict (came from Apple)
            if identifier in data["reminders"]:
                title = data["reminders"].pop(identifier)["title"]
                data["pending_completions"].append({
                    "identifier": identifier,
                    "completed_at": _now_iso(),
                    "completed_by": "claude",
                })
                try:
                    _write_reminders(data, sha)
                    return f"Reminder '{title}' marked complete. It will be completed in Apple Reminders after the next sync."
                except GithubException as e:
                    if e.status == 409 and attempt == 0:
                        continue
                    raise

            # Case 2: it's a pending addition (not yet on Apple)
            for i, pa in enumerate(data["pending_additions"]):
                if pa["server_id"] == identifier:
                    title = pa["title"]
                    data["pending_additions"].pop(i)
                    try:
                        _write_reminders(data, sha)
                        return f"Reminder '{title}' removed (it hadn't synced to Apple yet)."
                    except GithubException as e:
                        if e.status == 409 and attempt == 0:
                            break  # retry outer loop
                        raise

            return f"Error: no reminder found with identifier '{identifier}'."

    return await asyncio.to_thread(_run)

# ── Auth middleware (pure ASGI — no buffering, SSE-safe) ─────────────────────

_PUBLIC_PATHS    = {"/health"}
_PUBLIC_PREFIXES = ("/.well-known/", "/oauth/")


class AuthMiddleware:
    """Accept either the static AUTH_TOKEN (legacy / Scriptable) or a
    valid HMAC-signed OAuth access token issued by /oauth/token."""

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")

        # Always let health check, well-known discovery, and OAuth endpoints through
        if path in _PUBLIC_PATHS or any(path.startswith(p) for p in _PUBLIC_PREFIXES):
            await self.app(scope, receive, send)
            return

        # No token configured -> refuse everything. This used to fall through to
        # open access, which is a bad failure mode for a service that is public
        # at the network layer: a missing or misdelivered AUTH_TOKEN silently
        # unauthenticates every note and reminder endpoint instead of failing
        # loudly. _require_auth_token() below normally stops the process before
        # this can be reached; this is the belt-and-braces half.
        if not AUTH_TOKEN:
            response = Response("Server misconfigured: AUTH_TOKEN is not set", status_code=503)
            await response(scope, receive, send)
            return

        request = Request(scope)
        token = (
            request.query_params.get("token", "")
            or request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
        )

        # Accept static token (Scriptable / legacy clients)
        if token and hmac.compare_digest(token, AUTH_TOKEN):
            await self.app(scope, receive, send)
            return

        # Accept HMAC-signed OAuth access token
        if token and _verify_access_token(token):
            await self.app(scope, receive, send)
            return

        response = Response("Unauthorized", status_code=401)
        await response(scope, receive, send)

# ── OAuth 2.0 endpoints ───────────────────────────────────────────────────────

_AUTHORIZE_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Authorize — Claude Notes</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; }}
    body {{ font-family: system-ui, -apple-system, sans-serif; margin: 0; padding: 40px 20px; background: #f5f5f5; }}
    .card {{ background: white; border-radius: 12px; padding: 32px; max-width: 420px; margin: 0 auto; box-shadow: 0 2px 8px rgba(0,0,0,.1); }}
    h1 {{ font-size: 1.2rem; margin: 0 0 8px; }}
    p {{ color: #555; font-size: 0.9rem; margin: 0 0 24px; line-height: 1.5; }}
    label {{ display: block; font-size: 0.85rem; font-weight: 600; margin-bottom: 6px; }}
    input[type=password] {{ display: block; width: 100%; padding: 10px 12px; font-size: 0.95rem; border: 1px solid #ddd; border-radius: 8px; outline: none; }}
    input[type=password]:focus {{ border-color: #0070f3; box-shadow: 0 0 0 3px rgba(0,112,243,.15); }}
    .error {{ color: #c0392b; font-size: 0.85rem; margin-top: 10px; }}
    button {{ margin-top: 16px; display: block; width: 100%; padding: 11px; background: #0070f3; color: white; border: none; border-radius: 8px; font-size: 0.95rem; font-weight: 600; cursor: pointer; }}
    button:hover {{ background: #0051cc; }}
    .client {{ font-weight: 600; color: #111; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Authorize Claude Notes</h1>
    <p>Enter your server token to allow <span class="client">{client_display}</span> to access your notes and reminders.</p>
    <form method="post" action="/oauth/authorize">
      <input type="hidden" name="client_id"             value="{client_id}">
      <input type="hidden" name="redirect_uri"          value="{redirect_uri}">
      <input type="hidden" name="state"                 value="{state}">
      <input type="hidden" name="code_challenge"        value="{code_challenge}">
      <input type="hidden" name="code_challenge_method" value="{code_challenge_method}">
      <label for="pw">Server token</label>
      <input type="password" id="pw" name="password" autofocus autocomplete="current-password">
      {error_html}
      <button type="submit">Authorize</button>
    </form>
  </div>
</body>
</html>
"""


def _render_auth_form(
    *,
    client_id: str,
    redirect_uri: str,
    state: str,
    code_challenge: str,
    code_challenge_method: str,
    error: str = "",
) -> str:
    client_display = html_mod.escape(client_id or "this application")
    error_html     = f'<p class="error">{html_mod.escape(error)}</p>' if error else ""
    return _AUTHORIZE_HTML.format(
        client_display        = client_display,
        client_id             = html_mod.escape(client_id),
        redirect_uri          = html_mod.escape(redirect_uri),
        state                 = html_mod.escape(state),
        code_challenge        = html_mod.escape(code_challenge),
        code_challenge_method = html_mod.escape(code_challenge_method),
        error_html            = error_html,
    )


_GOOGLE_AUTH_URL  = "https://accounts.google.com/o/oauth2/v2/auth"
_GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
_GOOGLE_STATE_TTL = 600    # 10 minutes to complete a Google login


def _google_redirect_uri(request: Request) -> str:
    """Must match a redirect URI registered on the Google OAuth client exactly."""
    return f"{_server_url(request)}/oauth/google/callback"


def _google_exchange_and_verify(code: str, redirect_uri: str) -> str | None:
    """Trade a Google auth code for an ID token; return the verified email.

    Blocking (urllib + RSA verification), so callers run it off the event loop.
    """
    from google.oauth2 import id_token as google_id_token
    from google.auth.transport import requests as google_requests

    body = urllib.parse.urlencode({
        "code":          code,
        "client_id":     GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri":  redirect_uri,
        "grant_type":    "authorization_code",
    }).encode()
    req = urllib.request.Request(
        _GOOGLE_TOKEN_URL, data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        payload = json.loads(resp.read().decode())

    raw = payload.get("id_token", "")
    if not raw:
        return None

    # Verifies the RSA signature against Google's JWKS plus iss/aud/exp. Doing
    # this rather than trusting the TLS channel keeps the check honest even if
    # the token ever arrives by another route.
    claims = google_id_token.verify_oauth2_token(
        raw, google_requests.Request(), GOOGLE_CLIENT_ID,
    )
    if not claims.get("email_verified"):
        return None
    return (claims.get("email") or "").strip().lower()


def _notice_page(title: str, detail: str, status: int) -> HTMLResponse:
    return HTMLResponse(
        f"<!DOCTYPE html><html><head><meta charset='utf-8'>"
        f"<meta name='viewport' content='width=device-width, initial-scale=1'>"
        f"<title>{html_mod.escape(title)} — Claude Notes</title></head>"
        f"<body style=\"font-family:system-ui,-apple-system,sans-serif;margin:0;"
        f"padding:40px 20px;background:#f5f5f5\">"
        f"<div style=\"background:#fff;border-radius:12px;padding:32px;max-width:420px;"
        f"margin:0 auto;box-shadow:0 2px 8px rgba(0,0,0,.1)\">"
        f"<h1 style='font-size:18px;margin:0 0 12px'>{html_mod.escape(title)}</h1>"
        f"<p style='color:#555;margin:0;line-height:1.5'>{html_mod.escape(detail)}</p>"
        f"</div></body></html>",
        status_code=status,
    )


async def oauth_authorize(request: Request) -> Response:
    """GET: start the login.  POST: validate the token form, issue an auth code.

    With Google Sign-In configured the GET hands off to Google and the POST form
    is disabled — leaving it live would keep AUTH_TOKEN working as an interactive
    password and quietly bypass the allowlist the Google path enforces.
    """
    if request.method == "GET":
        params                = request.query_params
        response_type         = params.get("response_type", "")
        client_id             = params.get("client_id", "")
        redirect_uri          = params.get("redirect_uri", "")
        state                 = params.get("state", "")
        code_challenge        = params.get("code_challenge", "")
        code_challenge_method = params.get("code_challenge_method", "S256")

        if response_type != "code":
            return Response("unsupported_response_type", status_code=400)
        if not redirect_uri:
            return Response("redirect_uri is required", status_code=400)
        if not code_challenge:
            return Response("PKCE code_challenge is required", status_code=400)
        if code_challenge_method != "S256":
            return Response("only S256 code_challenge_method is supported", status_code=400)

        if _google_signin_enabled():
            # The client's grant details ride through Google in the signed state
            # parameter and come back on the callback, so no server-side pending
            # store is needed — same reason auth codes are signed.
            pending = _encode_signed("gstate", {
                "cid": client_id,
                "uri": redirect_uri,
                "st":  state,
                "cc":  code_challenge,
                "ccm": code_challenge_method,
            }, _GOOGLE_STATE_TTL)
            query = urllib.parse.urlencode({
                "client_id":     GOOGLE_CLIENT_ID,
                "redirect_uri":  _google_redirect_uri(request),
                "response_type": "code",
                "scope":         "openid email",
                "state":         pending,
                "prompt":        "select_account",
            })
            return Response(status_code=302, headers={"Location": f"{_GOOGLE_AUTH_URL}?{query}"})

        return HTMLResponse(_render_auth_form(
            client_id=client_id,
            redirect_uri=redirect_uri,
            state=state,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
        ))

    if _google_signin_enabled():
        return _notice_page(
            "Sign in with Google",
            "This server authenticates through Google. Start the connector's "
            "sign-in again rather than submitting a token here.",
            400,
        )

    # POST — process the login form
    form                  = await request.form()
    password              = form.get("password", "")
    client_id             = form.get("client_id", "")
    redirect_uri          = form.get("redirect_uri", "")
    state                 = form.get("state", "")
    code_challenge        = form.get("code_challenge", "")
    code_challenge_method = form.get("code_challenge_method", "S256")

    def _form_error(msg: str) -> HTMLResponse:
        return HTMLResponse(
            _render_auth_form(
                client_id=client_id,
                redirect_uri=redirect_uri,
                state=state,
                code_challenge=code_challenge,
                code_challenge_method=code_challenge_method,
                error=msg,
            ),
            status_code=400,
        )

    if not redirect_uri:
        return _form_error("redirect_uri is required")
    if not code_challenge:
        return _form_error("code_challenge is required")
    if code_challenge_method != "S256":
        return _form_error("only S256 code_challenge_method is supported")

    if AUTH_TOKEN and not hmac.compare_digest(password, AUTH_TOKEN):
        return _form_error("Invalid token — please try again.")

    code = _issue_auth_code(client_id, redirect_uri, code_challenge, code_challenge_method)

    sep      = "&" if "?" in redirect_uri else "?"
    location = redirect_uri + sep + urllib.parse.urlencode({"code": code, "state": state})
    return Response(status_code=302, headers={"Location": location})


async def oauth_google_callback(request: Request) -> Response:
    """Where Google returns the human, mid-way through the MCP client's flow."""
    params = request.query_params

    if params.get("error"):
        return _notice_page("Sign-in cancelled", f"Google reported: {params['error']}", 400)

    pending = _decode_signed("gstate", params.get("state", ""))
    if pending is None:
        return _notice_page(
            "Sign-in expired",
            "That login link is no longer valid. Start the connector's sign-in again.",
            400,
        )

    code = params.get("code", "")
    if not code:
        return _notice_page("Sign-in failed", "Google did not return an authorization code.", 400)

    try:
        email = await asyncio.to_thread(
            _google_exchange_and_verify, code, _google_redirect_uri(request),
        )
    except Exception:
        return _notice_page(
            "Sign-in failed",
            "Could not verify the Google sign-in. Please try again.",
            502,
        )

    if not email:
        return _notice_page(
            "Sign-in failed",
            "Google did not return a verified email address for that account.",
            403,
        )
    if email not in ALLOWED_GOOGLE_EMAILS:
        return _notice_page(
            "Not authorized",
            f"{email} is not permitted to access this server.",
            403,
        )

    # Google vouched for an allowed human; hand the MCP client the code it has
    # been waiting for. Its PKCE challenge rode through in the signed state, so
    # the code stays bound to the client that started the flow.
    our_code = _issue_auth_code(
        pending.get("cid", ""), pending.get("uri", ""),
        pending.get("cc", ""),  pending.get("ccm", "S256"),
    )
    target   = pending.get("uri", "")
    sep      = "&" if "?" in target else "?"
    location = target + sep + urllib.parse.urlencode(
        {"code": our_code, "state": pending.get("st", "")}
    )
    return Response(status_code=302, headers={"Location": location})


async def oauth_token(request: Request) -> JSONResponse:
    """POST /oauth/token — exchange an authorization code for an access token."""
    content_type = request.headers.get("Content-Type", "")
    if "application/json" in content_type:
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "invalid_request"}, status_code=400)
        grant_type    = body.get("grant_type", "")
        code          = body.get("code", "")
        code_verifier = body.get("code_verifier", "")
        redirect_uri  = body.get("redirect_uri", "")
    else:
        form          = await request.form()
        grant_type    = form.get("grant_type", "")
        code          = form.get("code", "")
        code_verifier = form.get("code_verifier", "")
        redirect_uri  = form.get("redirect_uri", "")

    if grant_type != "authorization_code":
        return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)

    code_data = _consume_auth_code(code)
    if not code_data:
        return JSONResponse({"error": "invalid_grant", "error_description": "unknown or expired code"}, status_code=400)
    if code_data["uri"] != redirect_uri:
        return JSONResponse({"error": "invalid_grant", "error_description": "redirect_uri mismatch"}, status_code=400)

    # Verify PKCE S256: challenge == base64url(sha256(verifier))
    digest    = hashlib.sha256(code_verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).decode().rstrip("=")
    if not hmac.compare_digest(challenge, code_data["cc"]):
        return JSONResponse({"error": "invalid_grant", "error_description": "code_verifier mismatch"}, status_code=400)

    access_token = _issue_access_token(code_data["cid"])
    return JSONResponse({
        "access_token": access_token,
        "token_type":   "bearer",
        "expires_in":   _ACCESS_TOKEN_TTL,
    })


async def oauth_register(request: Request) -> JSONResponse:
    """POST /oauth/register — dynamic client registration (RFC 7591)."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid_request"}, status_code=400)

    # Nothing is stored: this is a public-client model with no client secret, and
    # the issued client_id was only ever echoed back — no code path validated an
    # incoming client_id against the registry, so keeping one just meant a second
    # per-instance dict that a scaled-out deploy would disagree about.
    client_id = f"client-{secrets.token_urlsafe(12)}"
    return JSONResponse({
        "client_id":                     client_id,
        "redirect_uris":                 body.get("redirect_uris", []),
        "token_endpoint_auth_method":    "none",
        "grant_types":                   ["authorization_code"],
        "response_types":                ["code"],
    }, status_code=201)

# ── Well-known / discovery endpoints ─────────────────────────────────────────

async def health(request: Request) -> Response:
    return Response("ok")


async def oauth_resource_metadata(request: Request) -> JSONResponse:
    """RFC 9728 — points MCP clients at this server's authorization server.

    Served both bare and with a resource path suffix, i.e.
    /.well-known/oauth-protected-resource/mcp. The suffixed form is what RFC
    9728 actually specifies for a resource that lives at a path, and it is the
    first URL a client configured with `<base>/mcp` requests; only the bare form
    existed before, so that probe 404'd.
    """
    base     = _server_url(request)
    suffix   = request.path_params.get("path", "").strip("/")
    resource = f"{base}/{suffix}" if suffix else base
    return JSONResponse({
        "resource":                  resource,
        "authorization_servers":     [base],
        "bearer_methods_supported":  ["header", "query"],
    })


async def oauth_server_metadata(request: Request) -> JSONResponse:
    """RFC 8414 — describes this server's OAuth 2.0 capabilities."""
    base = _server_url(request)
    return JSONResponse({
        "issuer":                                base,
        "authorization_endpoint":                f"{base}/oauth/authorize",
        "token_endpoint":                        f"{base}/oauth/token",
        "registration_endpoint":                 f"{base}/oauth/register",
        "response_types_supported":              ["code"],
        "grant_types_supported":                 ["authorization_code"],
        "code_challenge_methods_supported":      ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
    })

# ── REST endpoints ───────────────────────────────────────────────────────────

async def rest_write(request: Request) -> JSONResponse:
    """POST /write — simple file write for Apple Shortcuts / Scriptable."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid JSON body"}, status_code=400)
    filename = _safe_filename(body.get("filename", ""))
    content = body.get("content", "")
    if not filename:
        return JSONResponse({"error": "missing or invalid filename"}, status_code=400)
    def _run():
        repo = _get_repo()
        try:
            existing = repo.get_contents(filename)
            repo.update_file(filename, f"Update {filename}", content, existing.sha)
        except GithubException as e:
            if e.status == 404:
                repo.create_file(filename, f"Create {filename}", content)
            else:
                raise
        return f"Written {len(content)} chars to '{filename}'."
    result = await asyncio.to_thread(_run)
    return JSONResponse({"ok": True, "detail": result})

# ── Reminders REST sync endpoints ────────────────────────────────────────────

async def reminders_sync_get(request: Request) -> JSONResponse:
    """GET /reminders/sync — Scriptable fetches pending work from the server.
    Returns completions Claude made and reminders Claude added, so Scriptable
    can apply them on iOS before pushing the full current state back."""
    def _run():
        data, _ = _read_reminders()
        return {
            "pending_completions": data.get("pending_completions", []),
            "pending_additions":   data.get("pending_additions", []),
        }
    result = await asyncio.to_thread(_run)
    return JSONResponse(result)


async def reminders_sync_post(request: Request) -> JSONResponse:
    """POST /reminders/sync — Scriptable pushes the full state of Apple
    Reminders after processing completions and additions from the server.

    Body: {
      current_reminders: [{identifier, title, notes, ...}, ...],
      confirmed_completions: [identifier, ...],
      addition_id_mappings: {server_id: apple_id, ...}
    }
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid JSON"}, status_code=400)

    current_reminders     = body.get("current_reminders", [])
    confirmed_completions = set(body.get("confirmed_completions", []))
    addition_mappings     = body.get("addition_id_mappings", {})

    def _run():
        for attempt in range(2):
            data, sha = _read_reminders()

            # 1. Clear confirmed completions
            data["pending_completions"] = [
                pc for pc in data["pending_completions"]
                if pc["identifier"] not in confirmed_completions
            ]

            # 2. Clear confirmed additions
            confirmed_server_ids = set(addition_mappings.keys())
            data["pending_additions"] = [
                pa for pa in data["pending_additions"]
                if pa["server_id"] not in confirmed_server_ids
            ]

            # 3. Replace reminders with the fresh set from Apple
            new_reminders = {}
            for r in current_reminders:
                rid = r.get("identifier")
                if rid:
                    new_reminders[rid] = {
                        "identifier":             rid,
                        "title":                  r.get("title", ""),
                        "notes":                  r.get("notes", ""),
                        "due_date":               r.get("due_date"),
                        "due_date_includes_time": r.get("due_date_includes_time", True),
                        "priority":               r.get("priority", 0),
                        "list_name":              r.get("list_name", "Reminders"),
                        "is_completed":           False,
                        "is_overdue":             r.get("is_overdue", False),
                        "creation_date":          r.get("creation_date"),
                        "source":                 "apple",
                    }
            data["reminders"]    = new_reminders

            # 4. Record sync time
            data["last_sync_at"] = _now_iso()

            try:
                _write_reminders(data, sha)
                return {
                    "ok":                            True,
                    "reminder_count":                len(new_reminders),
                    "pending_completions_remaining": len(data["pending_completions"]),
                    "pending_additions_remaining":   len(data["pending_additions"]),
                }
            except GithubException as e:
                if e.status == 409 and attempt == 0:
                    continue
                raise

    result = await asyncio.to_thread(_run)
    return JSONResponse(result)


async def reminders_sync_handler(request: Request):
    """Route dispatcher for GET/POST /reminders/sync."""
    if request.method == "GET":
        return await reminders_sync_get(request)
    elif request.method == "POST":
        return await reminders_sync_post(request)

# ── App assembly ──────────────────────────────────────────────────────────────

mcp_app = mcp.streamable_http_app()

@asynccontextmanager
async def lifespan(app):
    async with mcp_app.router.lifespan_context(mcp_app):
        yield

app = Starlette(
    lifespan=lifespan,
    routes=[
        Route("/health",                                  endpoint=health),
        Route("/.well-known/oauth-protected-resource",           endpoint=oauth_resource_metadata),
        Route("/.well-known/oauth-protected-resource/{path:path}", endpoint=oauth_resource_metadata),
        Route("/.well-known/oauth-authorization-server",           endpoint=oauth_server_metadata),
        Route("/.well-known/oauth-authorization-server/{path:path}", endpoint=oauth_server_metadata),
        Route("/oauth/authorize",                         endpoint=oauth_authorize,       methods=["GET", "POST"]),
        Route("/oauth/google/callback",                    endpoint=oauth_google_callback,  methods=["GET"]),
        Route("/oauth/token",                             endpoint=oauth_token,            methods=["POST"]),
        Route("/oauth/register",                          endpoint=oauth_register,         methods=["POST"]),
        Route("/write",                                   endpoint=rest_write,             methods=["POST"]),
        Route("/reminders/sync",                          endpoint=reminders_sync_handler, methods=["GET", "POST"]),
        Mount("/",                                        app=mcp_app),
    ],
)
app.add_middleware(AuthMiddleware)


def _require_auth_token() -> None:
    """Refuse to start without AUTH_TOKEN.

    Cloud Run only shifts traffic to a revision whose container came up, so
    failing here means a deploy that lost the AUTH_TOKEN secret — a typo in the
    secret name, a revoked accessor binding — leaves the previous good revision
    serving instead of quietly standing up an unauthenticated one.
    """
    if not AUTH_TOKEN:
        raise SystemExit(
            "AUTH_TOKEN is not set — refusing to start.\n"
            "On Cloud Run it comes from the claude-notes-auth-token secret; "
            "locally, pass AUTH_TOKEN=dev."
        )

    # A Google client with no allowlist would let *any* Google account through,
    # which is worse than the password form it replaces. Half-configured is the
    # dangerous state, so refuse it rather than silently falling back.
    if (GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET) and not ALLOWED_GOOGLE_EMAILS:
        raise SystemExit(
            "GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET are set but "
            "ALLOWED_GOOGLE_EMAILS is empty — refusing to start, since that "
            "would admit any Google account. Set ALLOWED_GOOGLE_EMAILS to a "
            "comma-separated list, or unset the Google client config."
        )
    if (GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET) and not (GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET):
        raise SystemExit(
            "GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET must both be set, or neither."
        )


if __name__ == "__main__":
    _require_auth_token()
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
