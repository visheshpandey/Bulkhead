"""Capture the real Arena demo as a small, local-only 20-second GIF."""

from __future__ import annotations

import os
import socket
import sys
import threading
import time
from io import BytesIO
from pathlib import Path

from PIL import Image
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ["BULKHEAD_DB_PATH"] = ":memory:"
os.environ.pop("BULKHEAD_API_KEY", None)
os.environ["BULKHEAD_LLM_JUDGE"] = "0"

import uvicorn

from app.main import app


def main() -> None:
    """Capture the browser demo artifact."""
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
            time.sleep(0.05)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page(viewport={"width": 1280, "height": 720})
            page.goto(f"http://127.0.0.1:{port}/#arena", wait_until="networkidle")
            page.locator("#arena-speed").select_option("1")
            page.locator("#arena-watch").click()
            frames = []
            for _ in range(40):
                image = Image.open(BytesIO(page.screenshot())).convert("RGB")
                image.thumbnail((960, 540), Image.Resampling.LANCZOS)
                frames.append(image.quantize(colors=128, method=Image.Quantize.MEDIANCUT))
                time.sleep(0.5)
            output = ROOT / "docs" / "demo.gif"
            frames[0].save(output, save_all=True, append_images=frames[1:], duration=500, loop=0, optimize=True)
            browser.close()
            print(f"Wrote {output.relative_to(ROOT)} ({output.stat().st_size} bytes)")
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        listener.close()


if __name__ == "__main__":
    main()
