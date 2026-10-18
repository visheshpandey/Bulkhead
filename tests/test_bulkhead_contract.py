from pathlib import Path

from fastapi.testclient import TestClient

from app.agents.client import BulkheadBlocked, BulkheadClient, bulkhead_guard
from app.audit.ledger import EventLedger
from app.core.config import setting
from app.main import app


def test_bulkhead_environment_and_names_are_canonical(monkeypatch) -> None:
    monkeypatch.setenv("BULKHEAD_HOST", "bulkhead-host")
    assert setting("HOST") == "bulkhead-host"
    assert BulkheadClient.__name__ == "BulkheadClient"
    assert BulkheadBlocked.__name__ == "BulkheadBlocked"
    assert bulkhead_guard.__name__ == "bulkhead_guard"


def test_bulkhead_api_key_requires_the_bulkhead_header(monkeypatch) -> None:
    monkeypatch.setenv("BULKHEAD_API_KEY", "bulkhead-key")
    client = TestClient(app)
    payload = {"action_type": "read_file", "target": "/workspace/README.md"}

    assert client.post("/api/evaluate", json=payload).status_code == 401
    assert client.post(
        "/api/evaluate", headers={"X-Bulkhead-Key": "bulkhead-key"}, json=payload
    ).status_code == 200


def test_default_database_path_is_bulkhead(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("BULKHEAD_DB_PATH", raising=False)

    ledger = EventLedger()
    assert Path(ledger.db_path) == Path("data/bulkhead.db")
    ledger.close()
