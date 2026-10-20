import { $ } from "./core.js";
import { copyText } from "./drawer.js";

/** Configure keyboard-accessible integration tabs and copy controls. */
export function setupIntegrate() {
  const tabs = [...document.querySelectorAll("[data-integrate-tab]")];
  const panes = [...document.querySelectorAll("[data-integrate-pane]")];
  tabs.forEach((button, index) => {
    const pane = panes.find((item) => item.dataset.integratePane === button.dataset.integrateTab);
    if (pane) { button.id ||= `integrate-tab-${button.dataset.integrateTab}`; button.setAttribute("role", "tab"); button.setAttribute("aria-controls", pane.id || `integrate-pane-${button.dataset.integrateTab}`); pane.id ||= button.getAttribute("aria-controls"); pane.setAttribute("role", "tabpanel"); pane.setAttribute("aria-labelledby", button.id); }
    button.tabIndex = index === 0 ? 0 : -1;
    button.addEventListener("click", () => {
      tabs.forEach((item) => { const selected = item === button; item.classList.toggle("active", selected); item.setAttribute("aria-selected", String(selected)); item.tabIndex = selected ? 0 : -1; });
      panes.forEach((item) => { item.hidden = item.dataset.integratePane !== button.dataset.integrateTab; });
    });
    button.addEventListener("keydown", (event) => {
      if (!["ArrowRight", "ArrowLeft", "Home", "End"].includes(event.key)) return;
      event.preventDefault();
      const target = event.key === "Home" ? tabs[0] : event.key === "End" ? tabs[tabs.length - 1] : tabs[(index + (event.key === "ArrowRight" ? 1 : -1) + tabs.length) % tabs.length];
      target.focus(); target.click();
    });
  });
  document.querySelectorAll("[data-copy-code]").forEach((button) => button.addEventListener("click", () => copyText($(button.dataset.copyCode).textContent)));
}
