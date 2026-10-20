import { $, state, text, toast, SEARCH_DEBOUNCE_MS, configureCore, sync, startLiveUpdates } from "./core.js";
import { render, renderLog } from "./activity.js";
import { refreshRules } from "./rules.js";
import { isArenaPlaying, playArena } from "./arena.js";
import { runLab, reportLab, labSamples } from "./lab.js";
import { setupIntegrate } from "./integrate.js";
import { showGuide } from "./guide.js";
import { nextDemo, exitDemo, runDemo, resetDemo, submitAction, loadDefaultIntent, loadScenarios, runAllScenarios, updateControls, fillAction, maliciousAction, canEvaluate } from "./evaluate.js";
import { exportFile, previewReport, download } from "./exports.js";
import { closeDrawer, drawerKeys, selectedEvent, copyText } from "./drawer.js";

configureCore({ render, closeDrawer, isArenaPlaying });

let searchTimer;
/** Navigate between dashboard pages without changing their wording or markup. */
export function showPage(page) { if (!["arena", "lab", "activity", "test", "rules", "integrate", "exports"].includes(page)) page = "arena"; for (const name of ["arena", "lab", "activity", "test", "rules", "integrate", "exports"]) { const section = $(`page-${name}`); if (section) { section.hidden = name !== page; section.classList.toggle("active", name === page); } } document.querySelectorAll("[data-page]").forEach((link) => { const active = link.dataset.page === page; link.classList.toggle("active", active); if (active) link.setAttribute("aria-current", "page"); else link.removeAttribute("aria-current"); }); if (page === "rules") refreshRules().catch((error) => toast(error.message)); if (page === "lab" && !$("lab-page").value) $("lab-page").value = labSamples.comment; $("main-content")?.focus?.({ preventScroll: true }); }
function setTheme(dark) {
  document.documentElement.dataset.theme = dark ? "dark" : "light";
  $("theme-toggle").setAttribute("aria-pressed", String(dark));
  $("theme-toggle").setAttribute("aria-label", dark ? "Switch to light theme" : "Switch to dark theme");
  text("theme-toggle", dark ? "Light mode" : "Dark mode");
  try { localStorage.setItem("bulkhead-theme", dark ? "dark" : "light"); }
  catch { /* Private browsing may deny storage. */ }
}
function bind() {
  document.querySelectorAll("[data-page]").forEach((link) => link.addEventListener("click", (event) => {
    event.preventDefault();
    const page = link.dataset.page;
    if (location.hash !== `#${page}`) location.hash = page;
    showPage(page);
  }));
  window.addEventListener("hashchange", () => showPage(location.hash.slice(1)));
  for (const id of ["decision-filter", "action-filter"])
    $(id).addEventListener("change", renderLog);
  $("search-filter").addEventListener("input", () => {
    window.clearTimeout(searchTimer);
    searchTimer = window.setTimeout(renderLog, SEARCH_DEBOUNCE_MS);
  });
  $("action-target").addEventListener("input", () => { const missing = !$("action-target").value.trim(); $("action-target").setAttribute("aria-invalid", String(missing)); if (!missing) text("action-target-error", ""); updateControls(); });
  $("action-payload").addEventListener("input", () => { $("action-payload").setAttribute("aria-invalid", "false"); text("action-payload-error", ""); });
  if ($("refresh-button")) $("refresh-button").addEventListener("click", () => sync());
  $("run-demo-button").addEventListener("click", () => document.querySelector("#page-arena") ? playArena() : runDemo());
  if ($("arena-watch")) $("arena-watch").addEventListener("click", () => { showPage("arena"); playArena(); });
  if ($("arena-replay")) $("arena-replay").addEventListener("click", () => playArena());
  if ($("arena-step")) $("arena-step").addEventListener("click", () => playArena(true, false));
  if ($("arena-try")) $("arena-try").addEventListener("click", () => showPage("lab"));
  if ($("arena-integrate")) $("arena-integrate").addEventListener("click", () => showPage("integrate"));
  if ($("technical-toggle")) $("technical-toggle").addEventListener("click", () => { const button = $("technical-toggle"); const expanded = button.getAttribute("aria-expanded") === "true"; button.setAttribute("aria-expanded", String(!expanded)); button.classList.toggle("technical-on", !expanded); document.querySelectorAll(".technical-detail").forEach((item) => { item.hidden = expanded; }); button.textContent = expanded ? "Show technical details" : "Hide technical details"; });
  if ($("lab-run")) $("lab-run").addEventListener("click", runLab);
  if ($("lab-report")) $("lab-report").addEventListener("click", reportLab);
  document.querySelectorAll("[data-sample]").forEach((button) => button.addEventListener("click", () => { $("lab-page").value = labSamples[button.dataset.sample]; text("lab-status", `${button.textContent} sample loaded.`); }));
  if ($("guide-button")) $("guide-button").addEventListener("click", () => showGuide(true));
  setupIntegrate();
  $("demo-next").addEventListener("click", nextDemo);
  $("demo-exit").addEventListener("click", exitDemo);
  $("reset-button").addEventListener("click", resetDemo);
  $("empty-demo-button").addEventListener("click", runDemo);
  $("action-form").addEventListener("submit", submitAction);
  $("default-intent").addEventListener("click", loadDefaultIntent);
  $("safe-fixture").addEventListener("click", () => { state.selectedScenario = null; fillAction({ action_type: "read_file", target: "/workspace/README.md" }); updateControls(); });
  $("malicious-fixture").addEventListener("click", () => { state.selectedScenario = null; fillAction(maliciousAction); updateControls(); });
  $("run-all-scenarios").addEventListener("click", runAllScenarios);
  $("export-audit").addEventListener("click", (event) => exportFile("/api/export?format=json", "bulkhead-audit.json", "application/json", event.currentTarget));
  $("export-csv").addEventListener("click", (event) => exportFile("/api/export?format=csv", "bulkhead-events.csv", "text/csv", event.currentTarget));
  $("export-rules").addEventListener("click", (event) => exportFile("/api/rules", "bulkhead-rules.json", "application/json", event.currentTarget));
  $("export-incidents").addEventListener("click", (event) => exportFile("/api/incidents", "bulkhead-incidents.json", "application/json", event.currentTarget));
  $("report-select").addEventListener("change", previewReport);
  $("download-report").addEventListener("click", () => { if (state.preview && $("report-select").value) download(`bulkhead-incident-${$("report-select").value}.md`, state.preview, "text/markdown"); });
  $("drawer-close").addEventListener("click", closeDrawer);
  $("drawer-close-secondary").addEventListener("click", closeDrawer);
  $("drawer-backdrop").addEventListener("click", closeDrawer);
  $("copy-event-json").addEventListener("click", () => { if (selectedEvent()) copyText(JSON.stringify(selectedEvent(), null, 2)); });
  document.addEventListener("keydown", (event) => {
    drawerKeys(event);
    if ((event.ctrlKey || event.metaKey) && event.key === "Enter"
        && $("page-test").hidden === false && $("event-drawer").hidden
        && canEvaluate() && $("action-target").value.trim()) {
      event.preventDefault();
      $("action-form").requestSubmit();
    }
  });
  const themeToggle = $("theme-toggle");
  const toggleTheme = () => setTheme(document.documentElement.dataset.theme !== "dark");
  themeToggle.onclick = toggleTheme;
}
bind();
let saved = "light";
try { saved = localStorage.getItem("bulkhead-theme") || "light"; }
catch { /* Storage is optional. */ }
setTheme(saved === "dark");
updateControls();
showPage(location.hash.slice(1));
render();
loadDefaultIntent();
loadScenarios();
sync();
startLiveUpdates();
window.setTimeout(() => { if ($("guide-tooltip")) showGuide(); }, 650);
