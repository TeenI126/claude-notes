"""
Claude Notes MCP Server
FastMCP with Streamable HTTP transport (MCP spec 2025-03-26).
Notes are stored in a GitHub repo for persistence across Render deploys.
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
SERVER_URL    = os.environ.get("RENDER_EXTERNAL_URL", "http://localhost:8000")

REMINDERS_PATH = "_system/reminders.json"

# ── OAuth constants ───────────────────────────────────────────────────────────

_ACCESS_TOKEN_TTL = 3600   # 1 hour
_AUTH_CODE_TTL    = 600    # 10 minutes

# In-memory stores — cleared on restart; clients re-auth automatically
_auth_codes:         dict[str, dict] = {}
_registered_clients: dict[str, dict] = {}

# ── OAuth token helpers ───────────────────────────────────────────────────────

def _issue_access_token(client_id: str) -> str:
    """Return an HMAC-SHA256-signed access token. Stateless — survives restarts."""
    payload = json.dumps({
        "sub": client_id,
        "iat": int(time.time()),
        "exp": int(time.time()) + _ACCESS_TOKEN_TTL,
    }, separators=(",", ":"))
    data = base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")
    sig  = hmac.new(AUTH_TOKEN.encode(), data.encode(), hashlib.sha256).hexdigest()
    return f"{data}.{sig}"


def _verify_access_token(token: str) -> bool:
    """Return True if the token has a valid HMAC signature and is unexpired."""
    if not AUTH_TOKEN:
        return False
    try:
        data, sig = token.rsplit(".", 1)
        expected  = hmac.new(AUTH_TOKEN.encode(), data.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return False
        padding = (4 - len(data) % 4) % 4
        payload = json.loads(base64.urlsafe_b64decode(data + "=" * padding))
        return payload.get("exp", 0) >= int(time.time())
    except Exception:
        return False

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

        # No token configured -> open access
        if not AUTH_TOKEN:
            await self.app(scope, receive, send)
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


async def oauth_authorize(request: Request) -> Response:
    """GET: show login form.  POST: validate token, issue auth code, redirect."""
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

        return HTMLResponse(_render_auth_form(
            client_id=client_id,
            redirect_uri=redirect_uri,
            state=state,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
        ))

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

    code = secrets.token_urlsafe(32)
    _auth_codes[code] = {
        "client_id":             client_id,
        "redirect_uri":          redirect_uri,
        "code_challenge":        code_challenge,
        "code_challenge_method": code_challenge_method,
        "expires_at":            time.time() + _AUTH_CODE_TTL,
    }

    sep      = "&" if "?" in redirect_uri else "?"
    location = redirect_uri + sep + urllib.parse.urlencode({"code": code, "state": state})
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

    code_data = _auth_codes.pop(code, None)
    if not code_data:
        return JSONResponse({"error": "invalid_grant", "error_description": "unknown or expired code"}, status_code=400)
    if code_data["expires_at"] < time.time():
        return JSONResponse({"error": "invalid_grant", "error_description": "code expired"}, status_code=400)
    if code_data["redirect_uri"] != redirect_uri:
        return JSONResponse({"error": "invalid_grant", "error_description": "redirect_uri mismatch"}, status_code=400)

    # Verify PKCE S256: challenge == base64url(sha256(verifier))
    digest    = hashlib.sha256(code_verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).decode().rstrip("=")
    if not hmac.compare_digest(challenge, code_data["code_challenge"]):
        return JSONResponse({"error": "invalid_grant", "error_description": "code_verifier mismatch"}, status_code=400)

    access_token = _issue_access_token(code_data["client_id"])
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

    client_id = f"client-{secrets.token_urlsafe(12)}"
    _registered_clients[client_id] = {
        "redirect_uris": body.get("redirect_uris", []),
        "client_name":   body.get("client_name", ""),
        "registered_at": time.time(),
    }
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
    """RFC 9728 — points MCP clients at this server's authorization server."""
    return JSONResponse({
        "resource":                  SERVER_URL,
        "authorization_servers":     [SERVER_URL],
        "bearer_methods_supported":  ["header", "query"],
    })


async def oauth_server_metadata(request: Request) -> JSONResponse:
    """RFC 8414 — describes this server's OAuth 2.0 capabilities."""
    return JSONResponse({
        "issuer":                                SERVER_URL,
        "authorization_endpoint":                f"{SERVER_URL}/oauth/authorize",
        "token_endpoint":                        f"{SERVER_URL}/oauth/token",
        "registration_endpoint":                 f"{SERVER_URL}/oauth/register",
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
        Route("/.well-known/oauth-protected-resource",   endpoint=oauth_resource_metadata),
        Route("/.well-known/oauth-authorization-server", endpoint=oauth_server_metadata),
        Route("/oauth/authorize",                         endpoint=oauth_authorize,       methods=["GET", "POST"]),
        Route("/oauth/token",                             endpoint=oauth_token,            methods=["POST"]),
        Route("/oauth/register",                          endpoint=oauth_register,         methods=["POST"]),
        Route("/write",                                   endpoint=rest_write,             methods=["POST"]),
        Route("/reminders/sync",                          endpoint=reminders_sync_handler, methods=["GET", "POST"]),
        Mount("/",                                        app=mcp_app),
    ],
)
app.add_middleware(AuthMiddleware)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
