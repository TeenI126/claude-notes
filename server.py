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
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.routing import Route, Mount
from starlette.requests import Request
from starlette.responses import Response, JSONResponse
import uvicorn

# ── Config ────────────────────────────────────────────────────────────────────

AUTH_TOKEN   = os.environ.get("AUTH_TOKEN", "")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
GITHUB_REPO  = os.environ.get("GITHUB_REPO", "")
SERVER_URL   = os.environ.get("RENDER_EXTERNAL_URL", "http://localhost:8000")

# ── FastMCP ───────────────────────────────────────────────────────────────────

mcp = FastMCP("claude-notes")

# ── Diagnose + patch FastMCP transport security ───────────────────────────────
# FastMCP's transport_security module rejects non-localhost Host headers.
# We print its source at startup so we can see exactly what it checks,
# then attempt to patch whatever allowed-hosts structure it exposes.

def _inspect_and_patch_transport_security() -> None:
    import inspect, urllib.parse
    server_host = urllib.parse.urlparse(SERVER_URL).netloc.split(":")[0]
    extra_hosts = {"localhost", "127.0.0.1", server_host}

    for module_path in (
        "mcp.server.transport_security",
        "mcp.server.fastmcp.transport_security",
    ):
        try:
            import importlib
            ts = importlib.import_module(module_path)
        except ImportError:
            continue

        print(f"\n=== {module_path} ({ts.__file__}) ===")
        try:
            print(inspect.getsource(ts))
        except Exception:
            try:
                with open(ts.__file__) as f:
                    print(f.read())
            except Exception as e:
                print(f"(could not read source: {e})")
        print("=== END ===\n")

        # Patch any frozenset/set of allowed hosts
        for attr in dir(ts):
            val = getattr(ts, attr, None)
            if isinstance(val, (frozenset, set)) and "localhost" in val or (
                isinstance(val, (frozenset, set)) and "127.0.0.1" in val
            ):
                setattr(ts, attr, type(val)(val | extra_hosts))
                print(f"Patched {module_path}.{attr}: added {extra_hosts}")

        # Patch any validate-style function to always return True
        for name, obj in inspect.getmembers(ts, inspect.isfunction):
            print(f"  fn: {name}")
        break  # stop after first successful import

_inspect_and_patch_transport_security()

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

# ── Auth middleware ───────────────────────────────────────────────────────────

def _set_host_localhost(request: Request) -> None:
    """Rewrite the Host header to 'localhost' so FastMCP's transport security
    check passes. FastMCP only whitelists localhost by default; for Render
    deployments the real host would otherwise trigger a 421."""
    request.scope["headers"] = [
        (k, b"localhost" if k.lower() == b"host" else v)
        for k, v in request.scope["headers"]
    ]


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        # Always allow health check, OAuth discovery, and registration through
        if path == "/health" or path.startswith("/.well-known") or path == "/register":
            return await call_next(request)
        if not AUTH_TOKEN:
            _set_host_localhost(request)
            return await call_next(request)
        token = (
            request.query_params.get("token", "")
            or request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
        )
        if token != AUTH_TOKEN:
            return Response("Unauthorized", status_code=401)
        _set_host_localhost(request)
        return await call_next(request)

# ── App assembly ──────────────────────────────────────────────────────────────

async def health(request: Request) -> Response:
    return Response("ok")

async def oauth_resource_metadata(request: Request) -> JSONResponse:
    """Tell Claude's connector this server uses simple bearer tokens."""
    return JSONResponse({
        "resource": SERVER_URL,
        "authorization_servers": [SERVER_URL],
        "bearer_methods_supported": ["header", "query"],
    })

async def oauth_auth_server_metadata(request: Request) -> JSONResponse:
    """Minimal auth server metadata — no token or authorization endpoint,
    so Claude gives up on OAuth and falls back to the bearer token it already has."""
    return JSONResponse({
        "issuer": SERVER_URL,
        "registration_endpoint": f"{SERVER_URL}/register",
    })

async def oauth_register(request: Request) -> JSONResponse:
    """Accept dynamic client registration so Claude doesn't get a hard error."""
    return JSONResponse({"client_id": "mcp-client", "client_id_issued_at": 0}, status_code=201)

mcp_app = mcp.streamable_http_app()

@asynccontextmanager
async def lifespan(app):
    # FastMCP's streamable_http_app has its own lifespan that initialises the
    # session manager's task group. We must run it here or every MCP request
    # will raise "Task group is not initialized".
    async with mcp_app.router.lifespan_context(mcp_app):
        yield

app = Starlette(
    lifespan=lifespan,
    routes=[
        Route("/health", endpoint=health),
        Route("/.well-known/oauth-protected-resource", endpoint=oauth_resource_metadata),
        Route("/.well-known/oauth-authorization-server", endpoint=oauth_auth_server_metadata),
        Route("/register", endpoint=oauth_register, methods=["POST"]),
        Mount("/", app=mcp_app),
    ]
)
app.add_middleware(AuthMiddleware)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
