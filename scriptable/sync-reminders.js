// ── Sync Apple Reminders → Claude Notes ──────────────────────────────────────
// Paste this script into Scriptable (scriptable.app).
// To automate: Shortcuts app → Automation → Time of Day → Run Script (Scriptable).
//
// Requires: Scriptable iOS app (free), access to the claude-notes server.
// ─────────────────────────────────────────────────────────────────────────────

// ── Config ────────────────────────────────────────────────────────────────────

const SERVER_URL  = "https://myclaude-n8nn.onrender.com"   // no trailing slash
const AUTH_TOKEN  = "YOUR_AUTH_TOKEN_HERE"                  // from Render → Environment
const FILENAME    = "reminders.md"                          // file written to your notes repo
const NOTIFY      = true                                    // show iOS notification on success

// Filter to specific Reminder lists (leave empty to include ALL lists)
// Example: const ONLY_LISTS = ["Personal", "Work"]
const ONLY_LISTS  = []

// ── Fetch incomplete reminders ────────────────────────────────────────────────

let all = await Reminder.allIncomplete()

if (ONLY_LISTS.length > 0) {
  all = all.filter(r => ONLY_LISTS.includes(r.calendar.title))
}

// ── Group by list ─────────────────────────────────────────────────────────────

const byList = {}
for (const r of all) {
  const list = r.calendar.title
  if (!byList[list]) byList[list] = []
  byList[list].push(r)
}

// Sort reminders within each list: overdue first, then by due date, then no-date
function sortKey(r) {
  if (!r.dueDate) return "9999-12-31"
  return r.dueDate.toISOString()
}
for (const list of Object.values(byList)) {
  list.sort((a, b) => sortKey(a).localeCompare(sortKey(b)))
}

// ── Priority emoji ────────────────────────────────────────────────────────────
// Reminders priority: 1 = high, 5 = medium, 9 = low, 0 = none

function priorityBadge(p) {
  if (p === 1) return " 🔴"
  if (p === 5) return " 🟡"
  if (p === 9) return " 🔵"
  return ""
}

// ── Build markdown ────────────────────────────────────────────────────────────

const now = new Date().toLocaleString("en-US", { dateStyle: "medium", timeStyle: "short" })
const today = new Date(); today.setHours(0, 0, 0, 0)

const lines = ["# My Reminders", `_Synced: ${now}_`, ""]

for (const listName of Object.keys(byList).sort()) {
  lines.push(`## ${listName}`)

  for (const r of byList[listName]) {
    let dueStr = ""
    if (r.dueDate) {
      const d = new Date(r.dueDate); d.setHours(0, 0, 0, 0)
      const diff = Math.round((d - today) / 86400000)
      if (diff < 0)       dueStr = ` *(⚠️ overdue ${Math.abs(diff)}d)*`
      else if (diff === 0) dueStr = " *(due today)*"
      else if (diff === 1) dueStr = " *(due tomorrow)*"
      else                 dueStr = ` *(due ${r.dueDate.toLocaleDateString()})*`
    }

    const badge = priorityBadge(r.priority)
    lines.push(`- [ ] ${r.title}${dueStr}${badge}`)

    if (r.notes && r.notes.trim()) {
      // Indent notes as a blockquote under the item
      const noteLines = r.notes.trim().split("\n")
      for (const nl of noteLines) {
        lines.push(`  > ${nl}`)
      }
    }
  }

  lines.push("")
}

if (all.length === 0) {
  lines.push("_No incomplete reminders. 🎉_")
}

const content = lines.join("\n")

// ── POST to server ────────────────────────────────────────────────────────────

const req = new Request(`${SERVER_URL}/write?token=${encodeURIComponent(AUTH_TOKEN)}`)
req.method  = "POST"
req.headers = { "Content-Type": "application/json" }
req.body    = JSON.stringify({ filename: FILENAME, content })

let resp
try {
  resp = await req.loadJSON()
} catch (err) {
  console.error("Request failed:", err.message)
  throw new Error(`Could not reach server: ${err.message}`)
}

if (!resp.ok) {
  throw new Error(`Server error: ${JSON.stringify(resp)}`)
}

console.log(`✓ ${resp.detail}`)

// ── Notify ────────────────────────────────────────────────────────────────────

if (NOTIFY) {
  const n = new Notification()
  n.title  = "Reminders synced ✓"
  n.body   = `${all.length} reminder${all.length === 1 ? "" : "s"} → ${FILENAME}`
  await n.schedule()
}

Script.complete()
