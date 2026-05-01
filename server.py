"""
Claude Notes MCP Server
Reads and writes note files stored in a GitHub repo — survives all Render deploys.
"""

import os
import asyncio
from typing import Any

from github import Github, GithubException
from mcp.server import Server
from mcp.server.sse import SseServerTransport
from mcp.types import Tool, TextContent
from starlette.applications import Starlette
from starlette.routing import Route, Mount
from starlette.requests import Request
from starlette.responses import Response
import uvicorn

# ── Config ────────────────────────────────────────────────────────────────────

AUTH_TOKEN  = os.environ.get("AUTH_TOKEN", "")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
GITHUB_REPO  = os.environ.get("GITHUB_REPO", "")  # e.g. "username/claude-notes-data"

# ── GitHub helpers ────────────────────────────────────────────────────────────

def _get_repo():
    return Github(GITHUB_TOKEN).get_repo(GITHUB_REPO)

def _safe_filename(filename: str) -> str | None:
    name = filename.strip()
    if not name or "/" in name or "\\" in name or name.startswith("."):
        return None
    return name

# ── MCP Server ────────────────────────────────────────────────────────────────

app = Server("claude-notes")


def auth_check(token: str) -> bool:
    if not AUTH_TOKEN:
        return True
    return token == AUTH_TOKEN


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="list_files",
            description="List all your note files.",
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        Tool(
            name="read_file",
            description="Read the contents of one of your note files.",
            inputSchema={
                "type": "object",
                "properties": {
                    "filename": {"type": "string", "description": "Filename to read, e.g. 'jobs.md'"}
                },
                "required": ["filename"],
            },
        ),
        Tool(
            name="write_file",
            description="Create or fully overwrite a note file with new content.",
            inputSchema={
                "type": "object",
                "properties": {
                    "filename": {"type": "string", "description": "Filename to write, e.g. 'jobs.md'"},
                    "content":  {"type": "string", "description": "Full content to write to the file."},
                },
                "required": ["filename", "content"],
            },
        ),
        Tool(
            name="append_to_file",
            description="Append text to the end of a note file (creates it if it doesn't exist).",
            inputSchema={
                "type": "object",
                "properties": {
                    "filename": {"type": "string", "description": "Filename to append to, e.g. 'jobs.md'"},
                    "content":  {"type": "string", "description": "Text to append."},
                },
                "required": ["filename", "content"],
            },
        ),
        Tool(
            name="delete_file",
            description="Delete a note file.",
            inputSchema={
                "type": "object",
                "properties": {
                    "filename": {"type": "string", "description": "Filename to delete."}
                },
                "required": ["filename"],
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    try:
        if name == "list_files":
            def _list():
                repo = _get_repo()
                contents = repo.get_contents("")
                files = sorted([c for c in contents if c.type == "file"], key=lambda x: x.name)
                if not files:
                    return "No files yet."
                return "\n".join(f"{c.name}  ({c.size} bytes)" for c in files)
            return [TextContent(type="text", text=await asyncio.to_thread(_list))]

        elif name == "read_file":
            filename = _safe_filename(arguments["filename"])
            if filename is None:
                return [TextContent(type="text", text="Error: invalid filename.")]
            def _read():
                try:
                    return _get_repo().get_contents(filename).decoded_content.decode("utf-8")
                except GithubException as e:
                    if e.status == 404:
                        return f"Error: '{filename}' does not exist."
                    raise
            return [TextContent(type="text", text=await asyncio.to_thread(_read))]

        elif name == "write_file":
            filename = _safe_filename(arguments["filename"])
            if filename is None:
                return [TextContent(type="text", text="Error: invalid filename.")]
            content = arguments["content"]
            def _write():
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
            return [TextContent(type="text", text=await asyncio.to_thread(_write))]

        elif name == "append_to_file":
            filename = _safe_filename(arguments["filename"])
            if filename is None:
                return [TextContent(type="text", text="Error: invalid filename.")]
            content = arguments["content"]
            def _append():
                repo = _get_repo()
                try:
                    existing = repo.get_contents(filename)
                    current = existing.decoded_content.decode("utf-8")
                    repo.update_file(filename, f"Append to {filename}", current + content, existing.sha)
                except GithubException as e:
                    if e.status == 404:
                        repo.create_file(filename, f"Create {filename}", content)
                    else:
                        raise
                return f"Appended to '{filename}'."
            return [TextContent(type="text", text=await asyncio.to_thread(_append))]

        elif name == "delete_file":
            filename = _safe_filename(arguments["filename"])
            if filename is None:
                return [TextContent(type="text", text="Error: invalid filename.")]
            def _delete():
                try:
                    existing = _get_repo().get_contents(filename)
                    _get_repo().delete_file(filename, f"Delete {filename}", existing.sha)
                    return f"Deleted '{filename}'."
                except GithubException as e:
                    if e.status == 404:
                        return f"Error: '{filename}' does not exist."
                    raise
            return [TextContent(type="text", text=await asyncio.to_thread(_delete))]

        else:
            return [TextContent(type="text", text=f"Unknown tool: {name}")]

    except Exception as e:
        return [TextContent(type="text", text=f"Error: {e}")]


# ── Starlette / SSE wiring ────────────────────────────────────────────────────

sse = SseServerTransport("/messages/")


async def handle_sse(request: Request) -> Response:
    token = request.query_params.get("token", "") or request.headers.get("Authorization", "").removeprefix("Bearer ")
    if not auth_check(token):
        return Response("Unauthorized", status_code=401)
    async with sse.connect_sse(request.scope, request.receive, request._send) as streams:
        await app.run(streams[0], streams[1], app.create_initialization_options())
    return Response()


async def handle_messages(request: Request) -> Response:
    await sse.handle_post_message(request.scope, request.receive, request._send)
    return Response()


starlette_app = Starlette(
    routes=[
        Route("/sse", endpoint=handle_sse),
        Mount("/messages/", app=handle_messages),
        Route("/health", endpoint=lambda r: Response("ok")),
    ]
)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(starlette_app, host="0.0.0.0", port=port)
