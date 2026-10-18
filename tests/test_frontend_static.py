"""Offline smoke checks for the vanilla dashboard contract."""

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
STATIC = ROOT / "app" / "static"


def test_dashboard_has_required_part_c_controls() -> None:
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    required_ids = (
        "event-drawer",
        "copy-event-json",
        "quarantine-comparison",
        "action-target-error",
        "export-audit",
        "export-incidents",
    )
    for element_id in required_ids:
        assert f'id="{element_id}"' in html


def test_dashboard_has_quarantine_counterfactual_copy() -> None:
    script = (STATIC / "app.js").read_text(encoding="utf-8")
    assert "Agent would have: read real .env → sent to evil.invalid" in script
    assert "AIRLOCK returned: FAKE_API_KEY=airlock-demo-key, network blocked" in script


def test_dashboard_renders_server_data_without_inner_html() -> None:
    script = (STATIC / "app.js").read_text(encoding="utf-8")
    assert "innerHTML" not in script
    assert "textContent" in script
    assert "replaceChildren" in script


def test_dashboard_uses_named_sse_and_api_backed_exports() -> None:
    script = (STATIC / "app.js").read_text(encoding="utf-8")
    assert 'addEventListener("audit_event"' in script
    assert 'startPolling()' in script
    assert '"/api/export?format=json"' in script
    assert '"/api/export?format=csv"' in script
    assert "/api/incidents/${encodeURIComponent(incident.id)}/report" in script


def test_dashboard_has_focus_and_loading_accessibility_hooks() -> None:
    script = (STATIC / "app.js").read_text(encoding="utf-8")
    styles = (STATIC / "styles.css").read_text(encoding="utf-8")
    assert 'event.key === "Escape"' in script
    assert 'event.key !== "Tab"' in script
    assert 'aria-busy' in script
    assert 'overflow-x: hidden' in styles


def test_dashboard_behavior_offline() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is not installed")
    subprocess.run(
        [node, "--test", "tests/frontend.behavior.test.cjs"],
        cwd=ROOT,
        check=True,
    )
