# Claude Notes MCP Server

A lightweight MCP server that gives Claude read/write access to a set of text files stored on Render. Works across all Claude clients (desktop, mobile, iPad) since it's hosted in the cloud. Also has a reminders feature, that provides HTTP endpoints to sync to Apple devices via the Scriptable app (hence the .js files that do this).

## Tools exposed to Claude

| Tool | Description |
|---|---|
| `list_files` | List all your note files |
| `read_file` | Read a file's contents |
| `write_file` | Create or overwrite a file |
| `append_to_file` | Append text to a file |
| `delete_file` | Delete a file |

---

## Usage examples

Once connected, you can tell Claude things like:

- *"Create a file called jobs.md and start tracking my job applications"*
- *"Add an entry to jobs.md: Shopify, Data Scientist, applied May 1"*
- *"Read my jobs.md file"*
- *"Update the status of the Shopify application to 'interview scheduled'"*
- *"Hey Claudsicle, add a reminder to get cheese."*

---
