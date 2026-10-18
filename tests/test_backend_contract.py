import asyncio
import csv
import io
import json

import pytest
from fastapi.testclient import TestClient

from app.api.routes import live_event_stream
from app.core.policy import DEFAULT_INTENT
from app.main import app


@pytest.mark.parametrize("reset_path", ["/api/reset-demo", "/api/reset", "/api/demo", "/api/demo/run", "/api/run-demo"])
def test_live_stream_announces_every_reset_alias(reset_path: str) -> None:
    client = TestClient(app)
    client.post("/api/reset-demo")
    response = live_event_stream()
    iterator = response.body_iterator
    assert client.post(reset_path).status_code == 200

    async def read_frame() -> str:
        try:
            # The response wraps its sync generator in an async iterator.
            return await asyncio.wait_for(iterator.__anext__(), timeout=2)
        finally:
            await iterator.aclose()

    frame = asyncio.run(read_frame())
    assert frame.startswith("event: reset\ndata: ")
    assert json.loads(frame.split("data: ", 1)[1].strip()) == {}


def test_header_identity_is_distinct_from_compatibility_action_identity() -> None:
    client = TestClient(app)
    client.post("/api/reset-demo")
    payload = {"action": {"action_type": "read_file", "target": "/workspace/README.md", "agent_id": "spoof"}}
    header = client.post("/api/evaluate", headers={"X-Agent-Id": "real-agent"}, json=payload)
    missing = client.post("/api/evaluate", json=payload)
    assert header.status_code == missing.status_code == 200
    assert header.json()["event"]["agent_id"] == "real-agent"
    assert header.json()["event"]["action"]["agent_id"] == "real-agent"
    assert missing.json()["event"]["agent_id"] is None
    assert missing.json()["event"]["action"]["agent_id"] == "spoof"
    assert [event["agent_id"] for event in client.get("/api/events").json()["events"]] == ["real-agent", None]
    assert client.get("/api/stats").json()["by_agent"] == {"real-agent": 1, "null": 1}
    rows = list(csv.DictReader(io.StringIO(client.get("/api/export.csv").text)))
    assert [row["agent_id"] for row in rows] == ["real-agent", ""]
    assert client.post("/api/evaluate", headers={"X-Agent-Id": " "}, json=payload).status_code == 422


def test_default_intent_endpoint_and_missing_or_null_intent_agree() -> None:
    client = TestClient(app)
    expected = DEFAULT_INTENT.model_dump(mode="json")
    assert client.get("/api/default-intent").json() == expected
    for intent in (None, "missing"):
        payload = {"action_type": "write_file", "target": "/workspace/notes.txt"}
        if intent is None:
            payload["intent"] = None
        result = client.post("/api/evaluate", json=payload)
        assert result.status_code == 200
        assert result.json()["decision"] == "block"
        assert any(item["label"] == "action_not_in_intent" for item in result.json()["findings"])


def test_immunity_rule_toggle_false_then_true_changes_evaluation() -> None:
    client = TestClient(app)
    client.post("/api/reset-demo")
    attack = {"action_type": "read_file", "target": "/workspace/.env"}
    first = client.post("/api/evaluate", json=attack).json()
    assert first["decision"] == "quarantine"
    rule_id = first["immunity_rule"]["id"]
    assert client.patch(f"/api/rules/{rule_id}", json={"enabled": False}).json()["enabled"] is False
    assert client.post("/api/evaluate", json=attack).json()["decision"] == "quarantine"
    assert client.patch(f"/api/rules/{rule_id}", json={"enabled": True}).json()["enabled"] is True
    assert client.post("/api/evaluate", json=attack).json()["decision"] == "block"


def test_evaluate_after_api_reset_never_reuses_event_incident_or_rule_ids() -> None:
    client = TestClient(app)
    attack = {"action_type": "read_file", "target": "/workspace/.env"}
    allocated: dict[str, set[str]] = {"event": set(), "incident": set(), "immunity_rule": set()}
    for _ in range(3):
        assert client.post("/api/reset-demo").status_code == 200
        result = client.post("/api/evaluate", json=attack)
        assert result.status_code == 200
        assert result.json()["decision"] == "quarantine"
        for collection, seen in allocated.items():
            identifier = result.json()[collection]["id"]
            assert identifier not in seen
            seen.add(identifier)


@pytest.mark.parametrize("path", ["/api/demo", "/api/demo/run", "/api/run-demo"])
def test_demo_events_record_header_identity_or_null(path: str) -> None:
    client = TestClient(app)
    supplied = client.post(path, headers={"X-Agent-Id": "demo-caller"})
    assert supplied.status_code == 200
    assert [step["event"]["agent_id"] for step in supplied.json()["steps"]] == ["demo-caller"] * 3
    missing = client.post(path)
    assert [step["event"]["agent_id"] for step in missing.json()["steps"]] == [None] * 3
