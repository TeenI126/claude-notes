// ── Two-Way Apple Reminders ↔ Claude Sync ────────────────────────────────────
// Automate via: Shortcuts → Automation → Time of Day → Run Scriptable Script
//
// Reads AUTH_TOKEN from config.json in the Scriptable iCloud folder.
// ─────────────────────────────────────────────────────────────────────────────

// ── Config ───────────────────────────────────────────────────────────────────

const SERVER_URL = "https://myclaude-n8nn.onrender.com"
const NOTIFY     = true

// Filter to specific lists (empty = all lists)
const ONLY_LISTS = ["Reminders"]

// ─────────────────────────────────────────────────────────────────────────────

try {

// ── Load config ───────────────────────────────────────────────────────────────

const fm         = FileManager.iCloud()
const configPath = fm.joinPath(fm.documentsDirectory(), "config.json")

if (!fm.fileExists(configPath)) {
  throw new Error("config.json not found in the Scriptable iCloud folder.")
}

await fm.downloadFileFromiCloud(configPath)
const config     = JSON.parse(fm.readString(configPath))
const AUTH_TOKEN = config.AUTH_TOKEN

if (!AUTH_TOKEN || AUTH_TOKEN.startsWith("YOUR_")) {
  throw new Error("AUTH_TOKEN is not set in config.json")
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 1: Fetch pending work from the server
// ─────────────────────────────────────────────────────────────────────────────

const getReq = new Request(
  `${SERVER_URL}/reminders/sync?token=${encodeURIComponent(AUTH_TOKEN)}`
)
getReq.method = "GET"

let serverData
try {
  serverData = await getReq.loadJSON()
} catch (err) {
  throw new Error(`GET /reminders/sync failed: ${err.message}`)
}

const pendingCompletions = serverData.pending_completions || []
const pendingAdditions   = serverData.pending_additions   || []

console.log(
  `Server says: ${pendingCompletions.length} to complete, ` +
  `${pendingAdditions.length} to add`
)

// ─────────────────────────────────────────────────────────────────────────────
// Step 2: Process completions (Claude → Apple)
// ─────────────────────────────────────────────────────────────────────────────

const confirmedCompletions = []

if (pendingCompletions.length > 0) {
  const allReminders = await Reminder.allIncomplete()

  for (const pc of pendingCompletions) {
    const match = allReminders.find(r => r.identifier === pc.identifier)
    if (match) {
      match.isCompleted = true
      match.save()
      console.log(`Completed on Apple: ${match.title}`)
    } else {
      console.log(`Already completed/deleted on Apple: ${pc.identifier}`)
    }
    confirmedCompletions.push(pc.identifier)
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 3: Process additions (Claude → Apple)
// ─────────────────────────────────────────────────────────────────────────────

const additionIdMappings = {}

if (pendingAdditions.length > 0) {
  const calendars = await Calendar.forReminders()

  for (const pa of pendingAdditions) {
    const r = new Reminder()
    r.title = pa.title
    if (pa.notes) r.notes = pa.notes
    if (pa.due_date) {
      r.dueDate = new Date(pa.due_date)
      r.dueDateIncludesTime = pa.due_date.includes("T")
    }
    if (pa.priority != null) r.priority = pa.priority

    if (pa.list_name) {
      const target = calendars.find(c => c.title === pa.list_name)
      if (target) r.calendar = target
    }

    r.save()
    additionIdMappings[pa.server_id] = r.identifier
    console.log(`Created on Apple: ${pa.title} → ${r.identifier}`)
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 4: Collect current incomplete reminders from Apple
// ─────────────────────────────────────────────────────────────────────────────

let allIncomplete = await Reminder.allIncomplete()

if (ONLY_LISTS.length > 0) {
  allIncomplete = allIncomplete.filter(
    r => ONLY_LISTS.includes(r.calendar.title)
  )
}

const currentReminders = allIncomplete.map(r => ({
  identifier:             r.identifier,
  title:                  r.title,
  notes:                  r.notes || "",
  due_date:               r.dueDate ? r.dueDate.toISOString() : null,
  due_date_includes_time: r.dueDateIncludesTime,
  priority:               r.priority,
  list_name:              r.calendar.title,
  is_completed:           false,
  is_overdue:             r.isOverdue,
  creation_date:          r.creationDate ? r.creationDate.toISOString() : null,
}))

// ─────────────────────────────────────────────────────────────────────────────
// Step 5: Push everything back to the server
// ─────────────────────────────────────────────────────────────────────────────

const postReq = new Request(
  `${SERVER_URL}/reminders/sync?token=${encodeURIComponent(AUTH_TOKEN)}`
)
postReq.method  = "POST"
postReq.headers = { "Content-Type": "application/json" }
postReq.body    = JSON.stringify({
  current_reminders:      currentReminders,
  confirmed_completions:  confirmedCompletions,
  addition_id_mappings:   additionIdMappings,
})

let postResp
try {
  postResp = await postReq.loadJSON()
} catch (err) {
  throw new Error(`POST /reminders/sync failed: ${err.message}`)
}

if (!postResp.ok) {
  throw new Error(`Server error: ${JSON.stringify(postResp)}`)
}

const summary =
  `${postResp.reminder_count} active, ` +
  `${confirmedCompletions.length} completed, ` +
  `${Object.keys(additionIdMappings).length} added`

console.log(`Sync complete: ${summary}`)

// ─────────────────────────────────────────────────────────────────────────────
// Step 6: Notify on success
// ─────────────────────────────────────────────────────────────────────────────

if (NOTIFY) {
  const n  = new Notification()
  n.title  = "Reminders synced"
  n.body   = summary
  await n.schedule()
}

} catch (err) {
  console.error(`Sync failed: ${err.message}`)
  if (NOTIFY) {
    const n  = new Notification()
    n.title  = "Reminders sync failed"
    n.body   = err.message
    await n.schedule()
  }
}

// Always call Script.complete() so Shortcuts automation doesn't hang
Script.complete()
