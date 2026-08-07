# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Running locally

```bash
pip install -r requirements.txt
AUTH_TOKEN=dev GITHUB_TOKEN=ghp_... GITHUB_REPO=user/repo python server.py
```

The server starts on port 8000 by default (overridden by `PORT` env var). The MCP endpoint is mounted at `/mcp`, health check at `/health`.

## Architecture

This is a single-file FastMCP server (`server.py`) deployed on Google Cloud Run. There is no database — all notes and reminder state are stored as files in a **separate private GitHub repo** (configured via `GITHUB_REPO` env var). `PyGithub` is the only storage layer. Cloud Run containers are stateless and scale to zero, so nothing may be kept on local disk.

### Key design points

**Transport**: Streamable HTTP (MCP spec 2025-03-26) via `mcp.streamable_http_app()`, mounted under a Starlette app. DNS-rebinding protection is monkey-patched off at startup (required for the `*.run.app` domain).

**Auth**: `AuthMiddleware` (pure ASGI, SSE-safe) accepts two token types: (1) the static `AUTH_TOKEN` env var, passed as `?token=` or `Authorization: Bearer` — kept for Scriptable backward-compat; (2) HMAC-SHA256-signed OAuth access tokens issued by `/oauth/token`. `/health`, `/.well-known/*`, and `/oauth/*` are always public.

**OAuth flow** (RFC 6749 authorization code + PKCE, RFC 7636):
- `/.well-known/oauth-authorization-server` — RFC 8414 server metadata; tells clients where all endpoints are
- `/.well-known/oauth-protected-resource` — RFC 9728 resource metadata; points clients at this server as their authorization server
- `GET /oauth/authorize` — renders a login form asking for the server token; requires `response_type=code`, `code_challenge` (S256 only), `redirect_uri`
- `POST /oauth/authorize` — validates the password against `AUTH_TOKEN`, stores an auth code (10 min TTL) in memory, redirects to `redirect_uri?code=…&state=…`
- `POST /oauth/token` — validates the code + PKCE `code_verifier`, returns a stateless HMAC-signed access token (1 hr TTL); accepts both `application/json` and `application/x-www-form-urlencoded`
- `POST /oauth/register` — RFC 7591 dynamic client registration; issues a random `client_id` with no client secret (public client model)

**No shared server state.** Access tokens *and* authorization codes are HMAC-SHA256 signed with `AUTH_TOKEN` as the key, carrying their own payload and expiry, so nothing has to be stored between requests. This matters more on Cloud Run than it did on Render: scale-to-zero tears the process down routinely, and `--max-instances 3` means `/oauth/authorize` and `/oauth/token` — two separate requests — often don't hit the same instance at all. Auth codes previously lived in a process-level dict and broke in exactly that case.

Both are signed via `_sign(purpose, data)`, whose purpose prefix is load-bearing: the two token types share an envelope, so without domain separation an authorization code would satisfy the access-token check (valid signature, unexpired `exp`) and work as a bearer token.

Single-use enforcement of auth codes is therefore best-effort — `_used_auth_codes` only catches a replay landing on the same instance. PKCE is the real control, since an intercepted code is useless without the client's `code_verifier`. Strict cross-instance single-use would need shared storage (Firestore/Memorystore), which isn't worth a dependency here.

`test_oauth_flow.py` covers this: it starts two independent server processes and redeems on one a code issued by the other. Run it with `python test_oauth_flow.py` (stdlib only, no test framework).

**Reminders sync** is two-way between this server and Apple Reminders, brokered by `scriptable/sync-reminders.js` running in the iOS Scriptable app:
1. Scriptable GETs `/reminders/sync` → gets pending completions/additions queued by Claude
2. Scriptable applies them on device, then POSTs the full current reminder state back
3. Server overwrites `_system/reminders.json` in the GitHub repo with the fresh state

The reminders JSON file is the single source of truth; concurrent writes are handled with a simple 2-attempt retry on GitHub 409 conflicts.

**Filename safety**: `_safe_filename()` blocks path traversal, dotfiles, and the `_system/` prefix (reserved for internal state like `reminders.json`).

### Environment variables

| Variable | Purpose |
|---|---|
| `AUTH_TOKEN` | Static bearer token for all endpoints |
| `GITHUB_TOKEN` | PAT for reading/writing the notes data repo |
| `GITHUB_REPO` | `owner/repo` of the private data repository |
| `PUBLIC_URL` | Optional. Pins the base URL in the OAuth metadata responses. Leave unset on Cloud Run — the metadata endpoints derive it per-request from the `Host` header, so the base URL, the `preview---` tag URL, and any custom domain each advertise themselves correctly. |
| `PORT` | HTTP port. Cloud Run injects `8080`; defaults to 8000 locally. |

Cloud Run has no equivalent of Render's `RENDER_EXTERNAL_URL` (the hostname isn't known until the first deploy, and one service answers on several), which is why `_server_url()` reads the `Host` and `X-Forwarded-Proto` headers instead of a fixed env var.

### Deployment

Deployed to Cloud Run as service `claude-notes-prod` in `us-central1` (GCP project `a111-502600`), built from source with Google Buildpacks. `Procfile` supplies the start command, because Buildpacks' Python detector only auto-discovers `main.py`/`app.py` and this project's entrypoint is `server.py`. `.gcloudignore` controls what gets uploaded into the build context — note that it fully replaces `.gitignore` for that purpose.

`AUTH_TOKEN` and `GITHUB_TOKEN` are mounted from Secret Manager (`claude-notes-auth-token`, `claude-notes-github-token`); `GITHUB_REPO` is a plain env var. Deploys go to a `preview`-tagged revision with no traffic first, then a separate `--promote` step moves traffic.
