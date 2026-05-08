# Claude Notes MCP Server

A lightweight MCP server that gives Claude read/write access to a set of text files stored on Render. Works across all Claude clients (desktop, mobile, iPad) since it's hosted in the cloud. Also has a reminders feature, that provides HTTP endpoints to sync to Apple devices via the Scriptable app (hence the .js files that do this).

---

## Tools exposed to Claude

### File tools

| Tool | Description |
|---|---|
| `list_files` | List all note files |
| `read_file` | Read the contents of a note file |
| `write_file` | Create or fully overwrite a note file |
| `append_to_file` | Append text to the end of a note file (creates it if it doesn't exist) |
| `delete_file` | Delete a note file |

### Reminders tools

| Tool | Description |
|---|---|
| `list_reminders` | List all pending reminders synced from Apple Reminders, grouped by list with due dates and priorities |
| `add_reminder` | Queue a new reminder to be created on your Apple devices on the next sync |
| `complete_reminder` | Mark a reminder as done — synced back to Apple on the next Scriptable run |

---

## Apple Reminders sync (Scriptable)

The server supports **two-way sync** with Apple Reminders via the [Scriptable](https://scriptable.app) iOS app.

### How it works

On each sync run the Scriptable script:
1. **Pulls** any completions or new reminders that Claude has queued on the server
2. **Applies** them on your Apple device (marks items complete, creates new reminders)
3. **Pushes** your full current reminder list back to the server so Claude always has an up-to-date view

### Setup

1. Install [Scriptable](https://apps.apple.com/app/scriptable/id1405459188) from the App Store (free)
2. Place `config.json` in your Scriptable iCloud folder with your auth token:
   ```json
   {
     "AUTH_TOKEN":   "your-server-auth-token",
     "GITHUB_TOKEN": "your-github-pat",
     "GITHUB_REPO":  "your-username/myclaude"
   }
   ```
3. Copy `scriptable/sync-reminders.js` into your Scriptable iCloud folder — it appears in the app automatically
4. To keep the script up to date, also copy `scriptable/update-scriptable-scripts.js` and run it whenever you want to pull the latest version from GitHub

By default the sync only includes the built-in **Reminders** list. Edit `ONLY_LISTS` at the top of the script to change this (`[]` syncs all lists).

### Automate it

In the **Shortcuts** app → **Automation** tab:
1. Tap **+** → **New Personal Automation**
2. Trigger: **Time of Day** → pick a time (e.g. 8:00 AM), Daily
3. Action: **Run Scriptable Script** → select `Sync Reminders to Claude`
4. Disable "Ask Before Running"

After each sync a notification confirms how many reminders were active, completed, and added.

---

## Usage examples

**Notes:**
- *"Create a file called jobs.md and start tracking my job applications"*
- *"Add an entry to jobs.md: Shopify, Data Scientist, applied May 1"*
- *"Read my jobs.md file"*
- *"Update the status of the Shopify application to 'interview scheduled'"*

**Reminders:**
- *"What reminders do I have?"*
- *"Add a reminder to call the dentist on Friday"*
- *"Mark the 'buy groceries' reminder as done"*
- *"Hey Claudsicle, add a reminder to get cheese."*

---

## Notes

- Notes and reminders are stored in a private GitHub repo — data persists across Render deploys
- Free tier may have a ~30 s cold start if the server hasn't been used recently
- Filenames starting with `.` or `_system` are blocked; everything else is allowed
- All files live flat in one folder — no directory traversal is possible
- `_system/reminders.json` is managed automatically; do not edit it manually
