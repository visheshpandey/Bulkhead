import { $, state, node, text, time, relative, request, currentGeneration, sync, toast } from "./core.js";
import { copyButton, renderSummary } from "./activity.js";
import { closeDrawer } from "./drawer.js";
import { showPage } from "./app.js";
import { previewReport } from "./exports.js";

/** Render seven-column rules with accessible toggles and source links. */
export function renderRules() {
  const body = $("rules-list");
  const focusedId = document.activeElement?.dataset?.ruleId;
  text("rule-count", `${state.rules.length} rule${state.rules.length === 1 ? "" : "s"}`);
  $("rules-empty").hidden = !!state.rules.length;
  body.replaceChildren();
  state.rules.forEach((rule) => {
    const row = node("tr");
    const enabled = rule.enabled !== false;
    const name = node("td");
    name.append(node("span", rule.id, "mono"), copyButton(rule.id, "rule ID"));
    name.title = rule.description || "Rule blocks a repeat attack";
    const fingerprint = node("td");
    fingerprint.append(node("span", rule.fingerprint || "—", "mono"));
    if (rule.fingerprint) fingerprint.append(copyButton(rule.fingerprint, "fingerprint"));
    const sourceCell = node("td");
    sourceCell.append(detailLink(rule.source_incident_id, "exports"));
    const lastCell = node("td");
    if (rule.last_matched_at) {
      const last = node("time", time(rule.last_matched_at));
      last.dateTime = rule.last_matched_at;
      last.title = relative(rule.last_matched_at);
      lastCell.append(last);
    } else lastCell.textContent = "—";
    const status = node("td");
    const label = node("label");
    const checkbox = node("input");
    checkbox.type = "checkbox";
    checkbox.checked = enabled;
    checkbox.dataset.ruleId = rule.id;
    checkbox.setAttribute("aria-label", `Enable rule ${rule.id}`);
    checkbox.addEventListener("change", () => mutateRule(rule, checkbox));
    label.append(checkbox, node("span", enabled ? "Enabled" : "Disabled"));
    status.append(label);
    const actions = node("td");
    const remove = node("button", "Delete", "text-button");
    remove.type = "button";
    remove.setAttribute("aria-label", `Delete rule ${rule.id}`);
    remove.addEventListener("click", () => deleteRule(rule));
    actions.append(remove);
    row.append(name, fingerprint, sourceCell, node("td", rule.match_count || 0), lastCell, status, actions);
    body.append(row);
  });
  if (focusedId) [...body.querySelectorAll("input")].find((item) => item.dataset.ruleId === focusedId)?.focus();
}
/** Fetch the authoritative rule list. */
export async function refreshRules() { const version = currentGeneration(); const response = await request("/api/rules"); if (version === currentGeneration() && Array.isArray(response.rules)) { state.rules = response.rules; renderRules(); renderSummary(); } }
async function mutateRule(rule, checkbox) {
  const enabled = checkbox.checked, version = currentGeneration();
  const restoreFocus = document.activeElement === checkbox;
  rule.enabled = enabled;
  checkbox.parentNode.children[1].textContent = enabled ? "Enabled" : "Disabled";
  checkbox.disabled = true;
  renderSummary();
  try {
    await request(`/api/rules/${encodeURIComponent(rule.id)}`, { method: "PATCH", body: JSON.stringify({ enabled }) });
    if (version === currentGeneration()) {
      await sync({ silent: true });
      await refreshRules();
      if (restoreFocus) [...$("rules-list").querySelectorAll("input")]
        .find((input) => input.dataset.ruleId === rule.id)?.focus();
    }
  } catch (error) {
    if (version === currentGeneration()) {
      rule.enabled = !enabled;
      checkbox.checked = !enabled;
      checkbox.parentNode.children[1].textContent = enabled ? "Disabled" : "Enabled";
      checkbox.disabled = false;
      renderSummary();
      toast(error.message);
    }
  }
}
async function deleteRule(rule) { if (!window.confirm(`Delete rule ${rule.id}?`)) return; const version = currentGeneration(); try { await request(`/api/rules/${encodeURIComponent(rule.id)}`, { method: "DELETE" }); if (version === currentGeneration()) { await sync({ silent: true }); await refreshRules(); } } catch (error) { toast(error.message); } }
/** Link to a related report or rule, preserving the drawer navigation flow. */
export function detailLink(value, page) { if (!value) return "Not supplied"; const link = node("a", value, "mono"); link.href = `#${page}`; link.addEventListener("click", (event) => { event.stopPropagation(); closeDrawer(); showPage(page); if (page === "exports") { $("report-select").value = value; previewReport(); } }); return link; }
