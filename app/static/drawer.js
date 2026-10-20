import { $, node, text, request, currentGeneration, toast, labels, reason, actionLabel, humanFinding } from "./core.js";
import { copyButton } from "./activity.js";
import { detailLink } from "./rules.js";

let drawerEvent, previousFocus;
/** Return the currently selected event for copying. */
export const selectedEvent = () => drawerEvent;
/** Copy user-visible data using the clipboard API. */
export async function copyText(value) { try { await navigator.clipboard.writeText(String(value)); toast("Copied to clipboard."); } catch { toast("Could not copy to clipboard."); } }
function detailSection(title, rows) {
  const section = node("section", null, "detail-section");
  section.append(node("h3", title));
  rows.forEach(([name, value]) => {
    const row = node("dl", null, "detail-row"), description = node("dd");
    if (value && typeof value === "object" && typeof value.appendChild === "function") description.append(value);
    else description.textContent = value ?? "Not supplied";
    row.append(node("dt", name), description);
    section.append(row);
  });
  return section;
}
function copyableValue(value, label) { if (!value) return "Not supplied"; const wrapper = node("span"); wrapper.append(node("span", value, "mono"), copyButton(value, label)); return wrapper; }
/** Open and load the accessible event detail drawer. */
export async function openDrawer(event, trigger) {
  if ($("event-drawer").hidden) previousFocus = trigger || document.activeElement;
  drawerEvent = event;
  const drawer = $("event-drawer"), shell = document.querySelector(".app-shell");
  $("drawer-body").replaceChildren(node("p", "Loading event details…"));
  drawer.hidden = false;
  drawer.classList.add("open");
  drawer.setAttribute("aria-modal", "true");
  drawer.setAttribute("aria-hidden", "false");
  $("drawer-backdrop").hidden = false;
  if (shell) { shell.inert = true; shell.setAttribute("aria-hidden", "true"); }
  text("drawer-title", `Event ${event.id}`);
  $("drawer-close").focus();
  const version = currentGeneration();
  try {
    const detail = await request(`/api/events/${encodeURIComponent(event.id)}`);
    if (version === currentGeneration() && drawerEvent?.id === event.id) renderDrawer(detail);
  } catch (error) {
    if (version === currentGeneration() && drawerEvent?.id === event.id) {
      renderDrawer(event);
      toast(`Full event details unavailable: ${error.message}`);
    }
  }
}
function renderDrawer(event) {
  drawerEvent = event;
  const body = $("drawer-body");
  body.replaceChildren();
  body.append(detailSection("Decision", [
    ["Event ID", copyableValue(event.id, "event ID")],
    ["Decision", labels[event.decision] || event.decision],
    ["Risk", event.risk_score],
    ["Reason", reason(event)],
    ["Timestamp", event.timestamp],
    ["Agent ID", event.agent_id ?? "Not supplied"],
  ]));
  body.append(detailSection("Action", [
    ["Type", actionLabel(event.action?.action_type)],
    ["Target", event.action?.target],
    ["Cleaned target", event.cleaned_target],
    ["Fingerprint", copyableValue(event.fingerprint, "fingerprint")],
    ["Attack", detailLink(event.incident_id, "exports")],
    ["Rule", detailLink(event.immunity_rule_id, "rules")],
  ]));
  const findingSection = detailSection("Findings", (event.findings || []).map((finding) => [
    "Finding", `${humanFinding(finding)} Evidence: ${finding.evidence || "—"}`,
  ]));
  if (!event.findings?.length) findingSection.append(node("p", "No threat findings."));
  body.append(findingSection);
  const receipt = node("section", null, "detail-section");
  receipt.append(node("h3", "Decoy (fake data) receipt"), node("pre", event.honeyworld_result
    ? JSON.stringify(event.honeyworld_result, null, 2) : "No receipt recorded.", "mono"));
  body.append(receipt);
  const raw = node("details", null, "detail-section");
  raw.append(node("summary", "Full event JSON"), node("pre", JSON.stringify(event, null, 2), "mono"));
  body.append(raw);
}
/** Close the drawer and restore the previous focus. */
export function closeDrawer() {
  const drawer = $("event-drawer");
  if (!drawer || drawer.hidden) return;
  drawer.hidden = true;
  drawer.classList.remove("open");
  drawer.setAttribute("aria-hidden", "true");
  $("drawer-backdrop").hidden = true;
  const shell = document.querySelector(".app-shell");
  if (shell) { shell.inert = false; shell.removeAttribute("aria-hidden"); }
  drawerEvent = null;
  if (previousFocus?.isConnected !== false) previousFocus?.focus?.();
}
/** Keep keyboard focus in the event drawer and close it on Escape. */
export function drawerKeys(event) {
  if ($("event-drawer").hidden) return;
  if (event.key === "Escape") { event.preventDefault(); closeDrawer(); return; }
  if (event.key !== "Tab") return;
  const controls = [...$("event-drawer").querySelectorAll('button:not([disabled]), a[href], summary, input:not([disabled]), [tabindex]:not([tabindex="-1"])')]
    .filter((item) => !item.hidden);
  if (!controls.length) return;
  const first = controls[0], last = controls[controls.length - 1];
  if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
  else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
}
