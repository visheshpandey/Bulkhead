import { $, state, node, text, time, relative, actionLabel, labels, decisionBadge, reason, humanFinding } from "./core.js";
import { openDrawer } from "./drawer.js";
import { renderRules, detailLink } from "./rules.js";
import { renderReports } from "./exports.js";
import { copyText } from "./drawer.js";

/** Refresh the decision and attack summary. */
export function renderSummary() {
  const today = new Date().toDateString();
  const todayCount = state.events.filter((item) => new Date(item.timestamp).toDateString() === today).length;
  const count = (decision) => state.events.filter((item) => item.decision === decision).length;
  const contained = count("block") + count("quarantine");
  const activeRules = state.rules.filter((rule) => rule.enabled !== false).length;
  text("event-count", `${state.events.length} event${state.events.length === 1 ? "" : "s"}`);
  text("summary-line", `${todayCount} decisions · ${count("allow")} allowed · ${count("block")} blocked · ${count("quarantine")} decoyed · ${activeRules} active rule${activeRules === 1 ? "" : "s"}`);
  text("summary-detail", `${contained} attacks stopped`);
  text("request-rate", state.events.filter((item) => Date.now() - new Date(item.timestamp).getTime() < 60000).length);
}
function filteredEvents() { const decision = $("decision-filter").value, action = $("action-filter").value, search = $("search-filter").value.trim().toLowerCase(); return [...state.events].reverse().filter((event) => (!decision || event.decision === decision) && (!action || event.action?.action_type === action) && (!search || [event.id, event.action?.target, event.action?.action_type, event.reason, event.agent_id].some((value) => String(value || "").toLowerCase().includes(search)))); }
/** Create an accessible copy button without interpolating HTML. */
export function copyButton(value, label) {
  const button = node("button", "⧉", "text-button meta");
  button.type = "button";
  button.setAttribute("aria-label", `Copy ${label}`);
  button.title = `Copy ${label}`;
  button.addEventListener("click", (event) => { event.stopPropagation(); copyText(value); });
  return button;
}
/** Render the filtered event timeline with keyboard row navigation. */
export function renderLog() {
  const body = $("log-body");
  const events = filteredEvents();
  const focusedEvent = document.activeElement?.dataset?.eventId;
  body.replaceChildren();
  $("activity-empty").hidden = events.length > 0;
  events.forEach((event, index) => {
    const row = node("tr");
    row.tabIndex = 0;
    row.dataset.eventId = event.id;
    row.setAttribute("aria-label", `Open event ${event.id}`);
    const stamp = node("time", time(event.timestamp));
    stamp.dateTime = event.timestamp || "";
    stamp.title = relative(event.timestamp);
    const timeCell = node("td");
    timeCell.append(stamp);
    const decisionCell = node("td");
    decisionCell.append(decisionBadge(event.decision));
    const target = event.action?.target || "—";
    const targetCell = node("td", target, "mono truncate");
    targetCell.title = target;
    const ruleCell = node("td");
    if (event.immunity_rule_id) {
      ruleCell.append(detailLink(event.immunity_rule_id, "rules"), copyButton(event.immunity_rule_id, "rule ID"));
    } else ruleCell.textContent = "—";
    row.append(timeCell, decisionCell, node("td", actionLabel(event.action?.action_type || "—")), targetCell, node("td", Number(event.risk_score || 0)), ruleCell);
    row.addEventListener("click", () => openDrawer(event, row));
    row.addEventListener("keydown", (key) => {
      if (key.key === "Enter") { key.preventDefault(); openDrawer(event, row); }
      if (key.key === "ArrowDown" || key.key === "ArrowUp") {
        key.preventDefault();
        body.children[index + (key.key === "ArrowDown" ? 1 : -1)]?.focus();
      }
    });
    body.append(row);
  });
  if (focusedEvent) [...body.children].find((row) => row.dataset.eventId === focusedEvent)?.focus();
}
function renderLatest() {
  const event = state.events[state.events.length - 1];
  const badge = $("latest-decision");
  badge.replaceChildren();
  if (event) badge.append(decisionBadge(event.decision)); else badge.textContent = "No decision yet";
  text("latest-risk", event ? `Risk ${Number(event.risk_score || 0)}` : "Risk —");
  text("latest-reason", event ? reason(event) : "Evaluate an action to see the gateway's decision.");
  text("latest-target", event?.action?.target || "—");
  text("latest-action", actionLabel(event?.action?.action_type || "—"));
  const list = $("finding-list");
  list.replaceChildren();
  (event?.findings || []).forEach((finding) => list.append(node("li", humanFinding(finding))));
  if (!list.children.length) list.append(node("li", "No threat findings."));
  $("flow-diagram").dataset.decision = event?.decision || "idle";
  const captures = state.honeyworld?.captured_actions || [];
  text("honey-summary", `${captures.length} attack${captures.length === 1 ? "" : "s"} sent to the decoy. Nothing real was touched.`);
  const captureList = $("capture-list");
  captureList.replaceChildren();
  captures.slice().reverse().slice(0, 5).forEach((capture) => captureList.append(node("li", `${actionLabel(capture.action_type)}: ${capture.target || "unknown target"}`)));
  const quarantined = [...state.events].reverse().find((item) => item.decision === "quarantine");
  $("containment-comparison").hidden = !quarantined;
  if (quarantined) {
    text("without-action", `Without interception, ${actionLabel(quarantined.action?.action_type)} would have targeted ${quarantined.action?.target || "the requested target"}. This is a counterfactual, not an observed execution.`);
    text("with-action", quarantined.honeyworld_result
      ? `Decoyed before real execution. Fake data was returned: ${JSON.stringify(quarantined.honeyworld_result)}`
      : "Decoyed before real execution; no fake-data receipt was recorded.");
  } else {
    text("without-action", "No decoyed attack to compare.");
    text("with-action", "Awaiting a decoyed decision.");
  }
}
/** Render all server-backed dashboard views. */
export function render() { renderSummary(); renderLog(); renderLatest(); renderRules(); renderReports(); }
