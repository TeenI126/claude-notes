"""
Claude Notes MCP Server
A simple MCP server that lets Claude read and write text files on your behalf.
Deploy on Render (free tier) for cross-device access.
"""

import os
import json
import asyncio
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.sse import SseServerTransport
from mcp.types import (
    Tool,
    TextContent,
    CallToolResult,
)
from starlette.applications import Starlette
from starlette.routing import Route, Mount
from starlette.requests import Request
from starlette.responses import Response
import uvicorn

# ── Config ────────────────────────────────────────────────────────────────────

NOTES_DIR = Path(os.environ.get("NOTES_DIR", "/opt/render/project/src/notes"))
AUTH_TOKEN = os.environ.get("AUTH_TOKEN", "")  # Set this in Render env vars!

# ── Startup ───────────────────────────────────────────────────────────────────

NOTES_DIR.mkdir(parents=True, exist_ok=True)

# ── MCP Server ────────────────────────────────────────────────────────────────

app = Server("claude-notes")


def auth_check(token: str) -> bool:
    """Return True if auth is disabled or token matches."""
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
                    "filename": {
                        "type": "string",
                        "description": "Filename to read, e.g. 'jobs.md'",
                    }
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
                    "filename": {
                        "type": "string",
                        "description": "Filename to write, e.g. 'jobs.md'",
                    },
                    "content": {
                        "type": "string",
                        "description": "Full content to write to the file.",
                    },
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
                    "filename": {
                        "type": "string",
                        "description": "Filename to append to, e.g. 'jobs.md'",
                    },
                    "content": {
                        "type": "string",
                        "description": "Text to append.",
                    },
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
                    "filename": {
                        "type": "string",
                        "description": "Filename to delete.",
                    }
                },
                "required": ["filename"],
            },
        ),
    ]


def safe_path(filename: str) -> Path | None:
    """Resolve path and ensure it stays within NOTES_DIR."""
    # Strip any path separators to prevent traversal
    safe_name = Path(filename).name
    if not safe_name or safe_name.startswith("."):
        return None
    resolved = (NOTES_DIR / safe_name).resolve()
    if not str(resolved).startswith(str(NOTES_DIR.resolve())):
        return None
    return resolved


@app.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    try:
        if name == "list_files":
            files = sorted(NOTES_DIR.iterdir())
            if not files:
                return [TextContent(type="text", text="No files yet.")]
            listing = "\n".join(
                f"{f.name}  ({f.stat().st_size} bytes)" for f in files if f.is_file()
            )
            return [TextContent(type="text", text=listing)]

        elif name == "read_file":
            path = safe_path(arguments["filename"])
            if path is None:
                return [TextContent(type="text", text="Error: invalid filename.")]
            if not path.exists():
                return [TextContent(type="text", text=f"Error: '{arguments['filename']}' does not exist.")]
            return [TextContent(type="text", text=path.read_text(encoding="utf-8"))]

        elif name == "write_file":
            path = safe_path(arguments["filename"])
            if path is None:
                return [TextContent(type="text", text="Error: invalid filename.")]
            path.write_text(arguments["content"], encoding="utf-8")
            return [TextContent(type="text", text=f"Written {len(arguments['content'])} chars to '{arguments['filename']}'.")]

        elif name == "append_to_file":
            path = safe_path(arguments["filename"])
            if path is None:
                return [TextContent(type="text", text="Error: invalid filename.")]
            with path.open("a", encoding="utf-8") as f:
                f.write(arguments["content"])
            return [TextContent(type="text", text=f"Appended to '{arguments['filename']}'.")]

        elif name == "delete_file":
            path = safe_path(arguments["filename"])
            if path is None:
                return [TextContent(type="text", text="Error: invalid filename.")]
            if not path.exists():
                return [TextContent(type="text", text=f"Error: '{arguments['filename']}' does not exist.")]
            path.unlink()
            return [TextContent(type="text", text=f"Deleted '{arguments['filename']}'.")]

        else:
            return [TextContent(type="text", text=f"Unknown tool: {name}")]

    except Exception as e:
        return [TextContent(type="text", text=f"Error: {e}")]


# ── Starlette / SSE wiring ────────────────────────────────────────────────────

sse = SseServerTransport("/messages/")


async def handle_sse(request: Request) -> Response:
    # Optional token auth via query param or Authorization header
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
