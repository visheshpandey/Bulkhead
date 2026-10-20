"""Focused backend contract cases not covered by the broader API tests."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.audit.ledger import EventLedger
from app.main import app


def test_api_key_accepts_compatibility_and_bearer_headers(monkeypatch) -> None:
    monkeypatch.setenv("BULKHEAD_API_KEY", "quality-key")
    client = TestClient(app)
    payload = {"action_type": "read_file", "target": "/workspace/README.md"}
    for headers in (
        {"X-API-Key": "quality-key"},
        {"Authorization": "Bearer quality-key"},
    ):
        assert client.post("/api/evaluate", headers=headers, json=payload).status_code == 200


def test_quarantine_can_skip_decoy_execution_without_skipping_learning() -> None:
    client = TestClient(app)
    client.post("/api/reset-demo")
    payload = {
        "action_type": "read_file",
        "target": "/workspace/.env",
        "run_honeyworld": False,
    }
    result = client.post("/api/evaluate", json=payload)
    assert result.status_code == 200
    body = result.json()
    assert body["decision"] == "quarantine"
    assert body["honeyworld"] is None
    assert client.get("/api/state").json()["honeyworld_captures"] == []
    assert len(client.get("/api/rules").json()["rules"]) == 1


def test_ledger_rejects_invalid_pagination_bounds() -> None:
    ledger = EventLedger(":memory:")
    with pytest.raises(ValueError, match="offset"):
        ledger.events(offset=-1)
    with pytest.raises(ValueError, match="limit"):
        ledger.events(limit=0)
    with pytest.raises(ValueError, match="limit"):
        ledger.events(limit=501)


def test_rule_patch_requires_enabled_and_missing_rule_is_not_created() -> None:
    client = TestClient(app)
    client.post("/api/reset-demo")
    assert client.patch("/api/rules/missing", json={}).status_code == 422
    assert client.patch("/api/rules/missing", json={"enabled": True}).status_code == 404
    assert client.delete("/api/rules/missing").status_code == 404


def test_security_headers_are_present_on_api_responses() -> None:
    response = TestClient(app).get("/health")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert "default-src 'self'" in response.headers["content-security-policy"]
