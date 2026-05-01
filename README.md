# Claude Notes MCP Server

A lightweight MCP server that gives Claude read/write access to a set of text files stored on Render. Works across all Claude clients (desktop, mobile, iPad) since it's hosted in the cloud.

## Tools exposed to Claude

| Tool | Description |
|---|---|
| `list_files` | List all your note files |
| `read_file` | Read a file's contents |
| `write_file` | Create or overwrite a file |
| `append_to_file` | Append text to a file |
| `delete_file` | Delete a file |

---

## Deployment (Render free tier)

### 1. Push to GitHub

Create a new GitHub repo and push this folder to it:

```bash
git init
git add .
git commit -m "Initial commit"
git remote add origin https://github.com/YOUR_USERNAME/claude-notes-mcp.git
git push -u origin main
```

### 2. Deploy on Render

1. Go to [render.com](https://render.com) and sign in
2. Click **New → Blueprint**
3. Connect your GitHub repo
4. Render will detect `render.yaml` and set everything up automatically
5. Click **Apply**

### 3. Get your AUTH_TOKEN

After deployment:
1. Go to your service in the Render dashboard
2. Click **Environment** tab
3. Copy the auto-generated `AUTH_TOKEN` value

### 4. Connect to Claude.ai

1. Go to **Claude.ai → Settings → Integrations**
2. Click **Add Integration**
3. Enter your server URL:
   ```
   https://claude-notes-mcp.onrender.com/sse?token=YOUR_AUTH_TOKEN
   ```
   (Replace the subdomain with your actual Render service name)

That's it — Claude can now read and write your notes from any device.

---

## Usage examples

Once connected, you can tell Claude things like:

- *"Create a file called jobs.md and start tracking my job applications"*
- *"Add an entry to jobs.md: Shopify, Data Scientist, applied May 1"*
- *"Read my jobs.md file"*
- *"Update the status of the Shopify application to 'interview scheduled'"*

---

## Notes

- Files are stored on Render's persistent disk (`/data/notes`)
- Free tier may have ~30s cold start if the server hasn't been used recently
- Only `.` prefixed filenames are blocked (for safety); everything else is allowed
- No directory traversal is possible — all files live flat in one folder
