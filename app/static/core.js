/** Look up a dashboard control by ID. */
export const $ = (id) => document.getElementById(id);
/** Maximum events retained in the browser timeline. */
export const MAX_TIMELINE_EVENTS = 200;
/** Search delay in milliseconds. */
export const SEARCH_DEBOUNCE_MS = 200;
const LIVE_POLL_MS = 3000;
/** Current server-backed dashboard data and selections. */
export const state = { events: [], incidents: [], rules: [], honeyworld: { captured_actions: [] }, scenarios: [], intent: null, selectedScenario: null, demo: 0, preview: "" };
let generation = 0, sequence = 0, awaitingReset = false, source, pollTimer, toastTimer, liveStarted = false;
let renderView = () => {};
let closeOpenDrawer = () => {};
let arenaIsPlaying = () => false;
/** Connect core state updates to the independent view modules. */
export function configureCore({ render, closeDrawer, isArenaPlaying }) {
  renderView = render;
  closeOpenDrawer = closeDrawer;
  arenaIsPlaying = isArenaPlaying;
}
/** Current reset generation for discarding stale responses. */
export const currentGeneration = () => generation;
/** Human-readable decisions. */
export const labels = { allow: "Allowed", block: "Blocked", quarantine: "Decoyed" };
const actionLabels = { read_file: "Read file", write_file: "Write file", run_command: "Run command", http_request: "Web request", github_action: "GitHub action" };
/** Human-readable action type. */
export const actionLabel = (value) => actionLabels[value] || String(value || "Action").replace(/_/g, " ");
const findings = {
  ignore_previous_instructions: "Content tried to override previous instructions.",
  disregard_previous_instructions: "Content tried to discard previous instructions.",
  override_system_prompt: "Content requested protected system instructions.",
  jailbreak_request: "Content attempted to bypass instructions.",
  untrusted_page_instruction: "An untrusted page issued instructions to the agent.",
  dotenv_access: "An environment file was accessed.",
  private_key_access: "A private key was accessed.",
  credential_path_access: "A credential file was accessed.",
  sensitive_file_access: "A sensitive file was accessed.",
  sensitive_data_access: "Sensitive data appeared in the action.",
  sensitive_keyword_mention: "The action mentions sensitive data.",
  secret_material: "A secret-like value was detected.",
  secret_to_network: "Sensitive data was directed toward a network destination.",
  shell_secret_exfiltration: "A shell command attempted to send a secret out.",
  action_not_in_intent: "This action is outside the permitted task.",
  target_outside_intent: "The target is outside the permitted paths.",
  target_explicitly_denied: "The target is explicitly denied.",
  network_not_in_intent: "Network access is not permitted.",
  invalid_target: "The target path is invalid.",
  known_quarantined_action: "A repeat of an earlier attack was blocked by a rule.",
  recursive_root_delete: "The command would recursively delete the root directory.",
  root_delete_with_override: "The command would delete the root directory.",
  filesystem_format: "The command would format a filesystem.",
  raw_disk_overwrite: "The command would overwrite a disk.",
  chmod_world_writable_root: "The command would expose root files to everyone.",
  fork_bomb: "The command would exhaust system resources.",
  system_shutdown: "The command would shut down the system.",
  force_push: "The command would force-push changes.",
  hard_reset_main: "The command would discard branch history.",
};
/** Create a text-only DOM element. */
export const node = (tag, value, className) => { const element = document.createElement(tag); if (value != null) element.textContent = String(value); if (className) element.className = className; return element; };
/** Update a control's text safely. */
export const text = (id, value) => { const element = $(id); if (element) element.textContent = String(value ?? ""); };
/** Format an event time. */
export const time = (value) => { const date = new Date(value); return value && !Number.isNaN(date.getTime()) ? date.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }) : "—"; };
/** Format the time since an event. */
export const relative = (value) => { const seconds = Math.max(0, Math.floor((Date.now() - new Date(value).getTime()) / 1000)); return Number.isFinite(seconds) ? (seconds < 60 ? `${seconds}s ago` : seconds < 3600 ? `${Math.floor(seconds / 60)}m ago` : `${Math.floor(seconds / 3600)}h ago`) : "Unknown time"; };
/** Present a detector finding without rendering untrusted HTML. */
export const humanFinding = (finding) => findings[finding.label] || `Detected ${String(finding.label || finding.category || "a risk").replace(/_/g, " ")}.`;
/** Explain a gateway event in product language. */
export function reason(event) {
  if (!event) return "No decision is available yet.";
  const labelsFound = (event.findings || []).map((item) => item.label);
  const has = (...labelsToFind) => labelsToFind.some((label) => labelsFound.includes(label));
  if (has("known_quarantined_action")) return `Blocked: this is a repeat of an earlier attack (rule ${event.immunity_rule_id || "on this gateway"}).`;
  if (event.decision === "allow") {
    if (!labelsFound.length) return "Part of the user's task.";
    return (event.findings || []).every((finding) => Number(finding.severity) <= 30) && Number(event.risk_score || 0) <= 30
      ? "Part of the user's task." : "Allowed, with a finding recorded for review.";
  }
  if (has("invalid_target")) return "The target path could not be accepted.";
  if (has("recursive_root_delete", "root_delete_with_override", "filesystem_format", "raw_disk_overwrite", "chmod_world_writable_root", "fork_bomb", "system_shutdown", "force_push", "hard_reset_main")) return "A destructive command was blocked before it could run.";
  if (event.decision === "block") {
    if (has("target_explicitly_denied")) return "This target was explicitly denied by the current intent.";
    if (has("target_outside_intent")) return `${event.action?.target || "This target"} is outside the allowed paths and was blocked.`;
    if (has("action_not_in_intent")) return "This action type is not permitted by the current intent.";
    if (has("network_not_in_intent")) return "The current intent does not permit network access.";
    return "Blocked by the current rules.";
  }
  if (has("shell_secret_exfiltration", "secret_to_network")) return "Sending data to an unknown site is not allowed.";
  if (has("sensitive_file_access", "dotenv_access", "sensitive_data_access")) return "Decoyed — the attacker got fake data.";
  if (has("ignore_previous_instructions", "disregard_previous_instructions", "override_system_prompt", "jailbreak_request", "untrusted_page_instruction")) return "Decoyed — the attacker got fake data.";
  return "Decoyed — the attacker got fake data.";
}
/** Build a decision badge. */
export function decisionBadge(decision) { return node("span", labels[decision] || "Unknown", `decision-label ${["allow", "block", "quarantine"].includes(decision) ? decision : ""}`); }
/** Display a transient status message. */
export function toast(message) { const element = $("toast"); element.textContent = message; element.hidden = false; window.clearTimeout(toastTimer); toastTimer = window.setTimeout(() => { element.hidden = true; }, 3000); }
/** Mark a button as busy and restore its label afterward. */
export function busy(button, active, value = "Working…") { if (!button) return; if (active) { button.dataset.originalLabel = button.textContent; button.textContent = value; button.disabled = true; button.setAttribute("aria-busy", "true"); } else { button.textContent = button.dataset.originalLabel || button.textContent; button.disabled = false; button.removeAttribute("aria-busy"); } }
function errorMessage(detail, fallback) {
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) return detail.map((item) => { const field = Array.isArray(item.loc) ? item.loc.filter((part) => part !== "body").join(".") : "Input"; return `${field}: ${item.msg || "Invalid value"}`; }).join("; ") || fallback;
  return fallback;
}
/** HTTP request error carrying the response status. */
export class RequestError extends Error { constructor(message, status) { super(message); this.status = status; } }
/** Product message for public demo throttling. */
export const rateLimitMessage = "Too many requests — wait a few seconds and press Replay";
/** Include the current session in a request URL. */
export function withSessionPath(path) {
  const match = String(location.search || "").match(/[?&]s=([^&]+)/);
  const session = match ? decodeURIComponent(match[1]) : "";
  if (!session || path.includes("s=")) return path;
  return `${path}${path.includes("?") ? "&" : "?"}s=${encodeURIComponent(session)}`;
}
/** Fetch and decode a JSON API response. */
export async function request(path, options = {}) {
  const response = await fetch(withSessionPath(path), { ...options, headers: { ...(options.body ? { "Content-Type": "application/json" } : {}), ...options.headers } });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new RequestError(errorMessage(data.detail, `Request failed (${response.status})`), response.status);
  return data;
}
function applyState(payload) {
  const next = payload?.state || payload || {};
  if (Array.isArray(next.events)) state.events = next.events.slice(-MAX_TIMELINE_EVENTS);
  if (Array.isArray(next.incidents)) state.incidents = next.incidents;
  if (Array.isArray(next.immunity_rules)) state.rules = next.immunity_rules;
  if (Array.isArray(next.honeyworld_captures)) state.honeyworld = { captured_actions: next.honeyworld_captures };
  else if (next.honeyworld) state.honeyworld = next.honeyworld;
}
/** Clear stale UI and data after a server reset. */
export function clearBoard() {
  generation++; sequence++; awaitingReset = true;
  state.events = []; state.incidents = []; state.rules = []; state.honeyworld = { captured_actions: [] };
  state.preview = ""; state.selectedScenario = null;
  closeOpenDrawer(); $("drawer-body").replaceChildren(); $("scenario-results-body").replaceChildren(); $("scenario-results").hidden = true;
  text("batch-summary", ""); text("test-result-summary", "No action evaluated."); $("test-result-summary").classList.remove("mismatch");
  text("test-result-reason", ""); $("test-result-findings").replaceChildren(); text("test-result-output", ""); text("action-status", "");
  text("incident-preview", "Select an attack above to preview its report."); renderView();
}
/** Reconcile the view with authoritative server state. */
export async function sync({ silent = false } = {}) { const version = generation, current = ++sequence; try { const payload = await request("/api/state"); if (version !== generation || current !== sequence) return false; const next = payload?.state || payload || {}; if (Array.isArray(next.events) && next.events.length < state.events.length) { clearBoard(); return sync({ silent }); } applyState(payload); awaitingReset = false; renderView(); text("connection-label", "Connected"); return true; } catch (error) { if (version === generation && current === sequence) { text("connection-label", "Reconnecting…"); if (!silent) toast(error.message); } return false; } }
/** Retain a unique event in newest-first display order. */
export function appendEvent(event) { if (!event?.id || state.events.some((item) => item.id === event.id)) return false; state.events.push(event); if (state.events.length > MAX_TIMELINE_EVENTS) state.events.splice(0, state.events.length - MAX_TIMELINE_EVENTS); return true; }
function streamEvent(message) { try { const event = JSON.parse(message.data); if (!awaitingReset && appendEvent(event)) renderView(); } catch { /* Polling reconciles malformed frames. */ } }
function streamReset(message) { try { const value = JSON.parse(message.data); if (!value || typeof value !== "object" || Array.isArray(value)) return; clearBoard(); sync({ silent: true }); } catch { /* Polling remains active. */ } }
function stopLiveUpdates() { if (pollTimer) { window.clearInterval?.(pollTimer); pollTimer = null; } if (source) { source.close(); source = null; } }
/** Start SSE and three-second polling, respecting document visibility. */
export function startLiveUpdates() {
  if (liveStarted) return;
  liveStarted = true;
  const visible = () => document.visibilityState !== "hidden";
  pollTimer = window.setInterval(() => { if (visible() && !arenaIsPlaying()) sync({ silent: true }); }, LIVE_POLL_MS);
  if (typeof EventSource === "undefined") return;
  try {
    source = new EventSource(withSessionPath("/api/stream"));
    source.onopen = () => text("connection-label", "Connected");
    source.addEventListener("audit_event", streamEvent);
    source.addEventListener("reset", streamReset);
    source.onmessage = streamEvent;
    source.onerror = () => { source.close(); source = null; text("connection-label", "Reconnecting…"); };
  } catch { text("connection-label", "Reconnecting…"); }
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "hidden") stopLiveUpdates();
    else { liveStarted = false; startLiveUpdates(); sync({ silent: true }); }
  });
}
