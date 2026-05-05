"""
Claude Notes MCP Server
FastMCP with Streamable HTTP transport (MCP spec 2025-03-26).
Notes are stored in a GitHub repo for persistence across Render deploys.
"""

import os
import asyncio
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
# FastMCP wraps the streamable HTTP endpoint with TransportSecurityMiddleware
# configured for localhost-only access (allowed_hosts=["localhost:*"]).
# On Render the Host header is the public domain, which gets rejected as 421.
# Our AuthMiddleware already handles authentication, so we disable the
# DNS-rebinding check entirely by patching the middleware at import time.

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

AUTH_TOKEN   = os.environ.get("AUTH_TOKEN", "")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
GITHUB_REPO  = os.environ.get("GITHUB_REPO", "")
SERVER_URL   = os.environ.get("RENDER_EXTERNAL_URL", "http://localhost:8000")

# ── FastMCP ───────────────────────────────────────────────────────────────────

mcp = FastMCP("claude-notes")

# ── GitHub helpers ────────────────────────────────────────────────────────────

def _get_repo():
    return Github(GITHUB_TOKEN).get_repo(GITHUB_REPO)

def _safe_filename(filename: str) -> str | None:
    name = filename.strip()
    if not name or "/" in name or "\\" in name or name.startswith("."):
        return None
    return name

# ── Tools ─────────────────────────────────────────────────────────────────────

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

# ── Auth middleware (pure ASGI — no buffering, SSE-safe) ─────────────────────

class AuthMiddleware:
    """Pure ASGI middleware so it doesn't interfere with SSE streaming.
    BaseHTTPMiddleware buffers responses and breaks the MCP streamable-HTTP
    transport's SSE negotiation (causes 406 Not Acceptable)."""

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

        # No token configured → open access
        if not AUTH_TOKEN:
            await self.app(scope, receive, send)
            return

        # Extract token from query string or Authorization header
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

# ── App assembly ──────────────────────────────────────────────────────────────

async def health(request: Request) -> Response:
    return Response("ok")

async def oauth_resource_metadata(request: Request) -> JSONResponse:
    """Tell Claude this resource accepts bearer tokens directly.
    No authorization_servers — Claude will skip the OAuth flow and fall back
    to using the bearer token already present in the connector URL."""
    return JSONResponse({
        "resource": SERVER_URL,
        "bearer_methods_supported": ["header", "query"],
    })

async def rest_write(request: Request) -> JSONResponse:
    """Simple REST endpoint called by Apple Shortcuts to write a file.
    POST /write?token=YOUR_TOKEN
    Body: {"filename": "reminders.md", "content": "...markdown..."}
    """
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
        Mount("/", app=mcp_app),
    ]
)
app.add_middleware(AuthMiddleware)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
