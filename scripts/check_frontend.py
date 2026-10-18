"""Exercise the real frontend in isolated Chromium and save responsive screenshots.

Optional: install requirements-browser.lock and run `python -m playwright install
chromium` first. No live user database or external website is accessed.
"""

from __future__ import annotations

import os
import socket
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ["AIRLOCK_DB_PATH"] = ":memory:"
os.environ.pop("AIRLOCK_API_KEY", None)
os.environ["AIRLOCK_LLM_JUDGE"] = "0"

import uvicorn
from playwright.sync_api import expect, sync_playwright

from app.main import app


def check_layout(page) -> None:
    dimensions = page.evaluate("""() => ({
        viewport: innerWidth, document: document.documentElement.scrollWidth,
        fields: [...document.querySelectorAll('.app-page:not([hidden]) .field')]
          .filter(el => el.getClientRects().length)
          .map(el => ({left: el.getBoundingClientRect().left, right: el.getBoundingClientRect().right}))
    })""")
    assert dimensions["document"] <= dimensions["viewport"], dimensions
    assert all(field["left"] >= 0 and field["right"] <= dimensions["viewport"] + 1
               for field in dimensions["fields"]), dimensions


def exercise(page, output: Path) -> None:
    expect(page.locator("#intent-goal")).not_to_have_value("")
    expect(page.locator("#connection-label")).to_have_text("Connected")
    assert page.locator("html").get_attribute("data-theme") == "light"
    page.locator("#run-demo-button").click()
    decisions = ["allow", "quarantine", "block", "block"]
    for index, decision in enumerate(decisions, 1):
        if index > 1:
            page.locator("#demo-next").click()
        expect(page.locator("#demo-step")).to_contain_text(f"Step {index} of 4")
        expect(page.locator("#flow-diagram")).to_have_attribute("data-decision", decision)
        expect(page.locator("#log-body tr")).to_have_count(index)
    page.locator("#demo-exit").click()

    page.locator("#log-body tr").first.focus()
    page.keyboard.press("ArrowDown")
    assert page.locator("#log-body tr").nth(1).evaluate("el => el === document.activeElement")
    page.keyboard.press("Enter")
    expect(page.locator("#event-drawer")).to_be_visible()
    expect(page.locator("#event-drawer")).to_have_attribute("aria-hidden", "false")
    expect(page.locator("#drawer-body")).to_contain_text("Fingerprint")
    page.screenshot(path=str(output / "details-1440.png"))
    page.keyboard.press("Escape")

    page.locator('[data-page="test"]').click()
    page.locator("#run-all-scenarios").click()
    expect(page.locator("#batch-summary")).to_have_text("15 of 15 matched expected result.", timeout=20000)
    expect(page.locator("#scenario-results-body tr")).to_have_count(15)
    # Running the suite again must not fail on learned fingerprints.
    page.locator("#run-all-scenarios").click()
    expect(page.locator("#run-all-scenarios")).to_be_enabled(timeout=20000)
    expect(page.locator("#batch-summary")).to_have_text("15 of 15 matched expected result.")

    page.locator('[data-page="rules"]').click()
    checkbox = page.locator("#rules-list input").first
    checkbox.uncheck()
    expect(page.locator("#rules-list input").first).not_to_be_checked()
    expect(page.locator("#rules-list input").first).to_be_enabled()
    page.locator("#rules-list input").first.check()
    expect(page.locator("#rules-list input").first).to_be_checked()
    count = page.locator("#rules-list tr").count()
    page.once("dialog", lambda dialog: dialog.accept())
    page.locator("#rules-list tr").first.locator('button[aria-label^="Delete rule"]').click()
    expect(page.locator("#rules-list tr")).to_have_count(count - 1)

    page.locator('[data-page="exports"]').click()
    for button in ("export-audit", "export-csv", "export-rules", "export-incidents"):
        with page.expect_download() as download:
            page.locator(f"#{button}").click()
        assert download.value.failure() is None
    page.locator("#report-select").select_option(index=1)
    expect(page.locator("#incident-preview")).to_contain_text("# AIRLOCK Incident")
    with page.expect_download():
        page.locator("#download-report").click()

    for width in (1440, 1024, 375):
        page.set_viewport_size({"width": width, "height": 1000 if width > 400 else 812})
        for name in ("activity", "test", "rules", "exports"):
            page.locator(f'[data-page="{name}"]').click()
            check_layout(page)
            page.screenshot(path=str(output / f"{name}-{width}.png"), full_page=True)
        page.locator('[data-page="activity"]').click()
        page.locator("#theme-toggle").click()
        expect(page.locator("html")).to_have_attribute("data-theme", "dark")
        check_layout(page)
        page.screenshot(path=str(output / f"activity-dark-{width}.png"), full_page=True)
        page.locator("#theme-toggle").click()

    # A second client resets while this dashboard has an open drawer.
    page.locator("#log-body tr").first.click()
    expect(page.locator("#event-drawer")).to_be_visible()
    assert page.request.post("/api/reset-demo").ok
    expect(page.locator("#log-body tr")).to_have_count(0)
    expect(page.locator("#event-drawer")).not_to_be_visible()
    expect(page.locator("#latest-decision")).to_have_text("No decision yet")
    expect(page.locator("#rule-count")).to_have_text("0 rules")


def main() -> None:
    output = ROOT / "artifacts" / "frontend"
    output.mkdir(parents=True, exist_ok=True)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, log_level="warning"))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 10
        while not server.started:
            if time.monotonic() > deadline:
                raise TimeoutError("Isolated gateway did not start")
            time.sleep(.05)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            context = browser.new_context(base_url=f"http://127.0.0.1:{port}",
                                          viewport={"width": 1440, "height": 1000})
            page = context.new_page()
            errors: list[str] = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.on("console", lambda message: errors.append(message.text) if message.type == "error" else None)
            page.goto("/", wait_until="domcontentloaded")
            exercise(page, output)
            assert not errors, errors
            browser.close()
        print("Browser checks passed: 15/15 scenarios twice, four demo steps, rules, exports, reset.")
        print("No console errors or page overflow at 1440, 1024, or 375px. Screenshots: artifacts/frontend/")
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        listener.close()


if __name__ == "__main__":
    main()
