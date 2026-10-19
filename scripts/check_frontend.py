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
os.environ["BULKHEAD_DB_PATH"] = ":memory:"
os.environ.pop("BULKHEAD_API_KEY", None)
os.environ["BULKHEAD_LLM_JUDGE"] = "0"

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


def check_plain_visual_contract(page) -> None:
    effects = page.evaluate("""() => {
      const visible = [...document.querySelectorAll('*')].filter((el) => {
        const style = getComputedStyle(el);
        const rect = el.getBoundingClientRect();
        return rect.width > 0 && rect.height > 0 && style.display !== 'none' && style.visibility !== 'hidden';
      });
      const checks = visible.flatMap((el) => {
        const selectors = [el.matches('#page-arena.active *') ? '#page-arena.active *' : el.tagName.toLowerCase()];
        return [getComputedStyle(el), getComputedStyle(el, '::before'), getComputedStyle(el, '::after')]
          .map((style, index) => ({
            selector: selectors[0], pseudo: index === 1 ? '::before' : index === 2 ? '::after' : '',
            backgroundImage: style.backgroundImage,
            boxShadow: style.boxShadow,
            filter: style.filter,
          }));
      });
      return checks.filter((item) => item.backgroundImage.includes('gradient') ||
        item.boxShadow !== 'none' || item.filter !== 'none');
    }""")
    assert effects == [], effects[:10]


def exercise(page, output: Path, arena_statuses: list[int], *, public: bool = False) -> None:
    expect(page.locator("#connection-label")).to_have_text("Connected")
    assert page.locator("html").get_attribute("data-theme") == "light"
    page.locator("#arena-speed").select_option("2")
    for _ in range(3):
        before = len(arena_statuses)
        page.locator("#arena-watch").click()
        expect(page.locator("#arena-finish")).to_be_hidden()
        expect(page.locator("#arena-finish")).to_be_visible(timeout=30000)
        assert arena_statuses[before:before + 5] == [200] * 5
        expect(page.locator("#arena-with-steps .arena-step")).to_have_count(4)
        expect(page.locator("#arena-replay-result")).to_be_visible()

    if public:
        return

    page.locator('.main-nav > a[data-page="lab"]').click()
    page.locator('[data-sample="comment"]').click()
    page.locator("#lab-run").click()
    expect(page.locator("#lab-status")).to_contain_text("Blocked", timeout=10000)

    screenshots = ROOT / "docs" / "screenshots"
    screenshots.mkdir(parents=True, exist_ok=True)
    for width in (1280, 768, 414, 375):
        height = 1000 if width > 768 else 896 if width > 400 else 812
        page.set_viewport_size({"width": width, "height": height})
        names = ("arena", "lab", "integrate", "activity", "rules", "test", "exports")
        for name in names:
            page.evaluate("name => { location.hash = '#' + name; }", name)
            expect(page.locator(f"#page-{name}")).to_be_visible()
            check_layout(page)
            page.screenshot(path=str(output / f"{name}-{width}.png"), full_page=True)
            if name == "arena" and width in (1280, 768, 375):
                page.screenshot(path=str(screenshots / f"arena-{width}.png"), full_page=True)
        if width == 375:
            expect(page.locator(".menu-label")).to_be_visible()
        page.evaluate("location.hash = '#arena'")
        expect(page.locator("#page-arena")).to_be_visible()
        page.locator("#theme-toggle").click()
        expect(page.locator("html")).to_have_attribute("data-theme", "dark")
        check_layout(page)
        page.screenshot(path=str(output / f"arena-dark-{width}.png"), full_page=True)
        page.locator("#theme-toggle").click()

    for height in (666, 720):
        page.set_viewport_size({"width": 1280, "height": height})
        page.goto("/#arena", wait_until="networkidle")
        expect(page.locator("#page-arena")).to_be_visible()
        expect(page.locator("#connection-label")).to_have_text("Connected")
        check_plain_visual_contract(page)
        check_layout(page)
        assert page.evaluate("document.documentElement.scrollHeight") <= height
        page.locator("#arena-speed").select_option("2")
        page.locator("#arena-watch").click()
        expect(page.locator("#arena-finish")).to_be_visible(timeout=30000)
        expect(page.locator("#arena-with-steps .arena-step")).to_have_count(4)
        expect(page.locator("#arena-replay-result")).to_be_visible(timeout=30000)
        replay, with_flow, finish = page.evaluate("""() => [
          document.querySelector('#arena-replay-result').getBoundingClientRect().toJSON(),
          document.querySelector('.arena-flow-with').getBoundingClientRect().toJSON(),
          document.querySelector('#arena-finish').getBoundingClientRect().toJSON(),
        ]""")
        assert replay["height"] > 0 and replay["bottom"] <= with_flow["bottom"] + 1, (height, replay, with_flow)
        assert replay["bottom"] <= finish["top"] or replay["top"] >= finish["bottom"], (height, replay, finish)
        assert page.evaluate("document.documentElement.scrollHeight") <= height
    page.locator("#theme-toggle").click()
    check_plain_visual_contract(page)
    assert page.evaluate("document.documentElement.scrollHeight") <= 720
    page.locator("#theme-toggle").click()


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
            arena_statuses: list[int] = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.on("console", lambda message: errors.append(message.text) if message.type == "error" else None)
            page.on("response", lambda response: arena_statuses.append(response.status) if "/api/evaluate" in response.url else None)
            page.goto("/", wait_until="domcontentloaded")
            public = os.environ.get("BULKHEAD_PUBLIC_DEMO") == "1"
            exercise(page, output, arena_statuses, public=public)
            health = page.request.get("/healthz")
            assert health.status == 200 and health.json() == {"status": "ok", "service": "bulkhead"}
            if public:
                first_state = page.evaluate("fetch('/api/state').then(response => response.json())")
                isolated_context = browser.new_context(
                    base_url=f"http://127.0.0.1:{port}", viewport={"width": 1280, "height": 1000}
                )
                isolated_page = isolated_context.new_page()
                isolated_page.goto("/", wait_until="networkidle")
                isolated_state = isolated_page.evaluate("fetch('/api/state').then(response => response.json())")
                assert isolated_state["events"] == []
                isolated_page.locator("#arena-speed").select_option("2")
                isolated_page.locator("#arena-watch").click()
                expect(isolated_page.locator("#arena-finish")).to_be_visible(timeout=30000)
                current_state = page.evaluate("fetch('/api/state').then(response => response.json())")
                assert len(first_state["events"]) == len(current_state["events"])
                isolated_context.close()
            assert not errors, errors
            browser.close()
        print("Browser checks passed: three Arena plays with five 200 responses each, lab, and responsive pages.")
        print("No console errors or page overflow at 1280, 768, 414, or 375px. Screenshots: docs/screenshots/")
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        listener.close()


if __name__ == "__main__":
    main()
