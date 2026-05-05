"""
Claude Notes MCP Server
FastMCP with Streamable HTTP transport (MCP spec 2025-03-26).
Notes are stored in a GitHub repo for persistence across Render deploys.
Includes a two-way Apple Reminders sync system (via Scriptable on iOS).
"""

import os
import json
import uuid
import asyncio
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from github import Github, GithubException
from mcp.server.fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.types import ASGIApp, Receive, Scope, Send
from starlette.routing import Route, Mount
from starlette.requests import Request
from starlette.responses import Response, JSONResponse
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

class AuthMiddleware:
    """Pure ASGI middleware so it doesn't interfere with SSE streaming."""

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")

        # Always allow health check and OAuth discovery through
        if path == "/health" or path.startswith("/.well-known"):
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

        if token != AUTH_TOKEN:
            response = Response("Unauthorized", status_code=401)
            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)

# ── REST endpoints ───────────────────────────────────────────────────────────

async def health(request: Request) -> Response:
    return Response("ok")

async def oauth_resource_metadata(request: Request) -> JSONResponse:
    return JSONResponse({
        "resource": SERVER_URL,
        "bearer_methods_supported": ["header", "query"],
    })

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
            "pending_additions": data.get("pending_additions", []),
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

    current_reminders = body.get("current_reminders", [])
    confirmed_completions = set(body.get("confirmed_completions", []))
    addition_mappings = body.get("addition_id_mappings", {})

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
                        "identifier": rid,
                        "title": r.get("title", ""),
                        "notes": r.get("notes", ""),
                        "due_date": r.get("due_date"),
                        "due_date_includes_time": r.get("due_date_includes_time", True),
                        "priority": r.get("priority", 0),
                        "list_name": r.get("list_name", "Reminders"),
                        "is_completed": False,
                        "is_overdue": r.get("is_overdue", False),
                        "creation_date": r.get("creation_date"),
                        "source": "apple",
                    }
            data["reminders"] = new_reminders

            # 4. Record sync time
            data["last_sync_at"] = _now_iso()

            try:
                _write_reminders(data, sha)
                return {
                    "ok": True,
                    "reminder_count": len(new_reminders),
                    "pending_completions_remaining": len(data["pending_completions"]),
                    "pending_additions_remaining": len(data["pending_additions"]),
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
        Route("/health", endpoint=health),
        Route("/.well-known/oauth-protected-resource", endpoint=oauth_resource_metadata),
        Route("/write", endpoint=rest_write, methods=["POST"]),
        Route("/reminders/sync", endpoint=reminders_sync_handler, methods=["GET", "POST"]),
        Mount("/", app=mcp_app),
    ],
)
app.add_middleware(AuthMiddleware)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
