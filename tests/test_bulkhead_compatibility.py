from pathlib import Path

from fastapi.testclient import TestClient

from app.agents.client import (
    AirlockBlocked,
    AirlockClient,
    BulkheadBlocked,
    BulkheadClient,
    airlock_guard,
    bulkhead_guard,
)
from app.audit.ledger import EventLedger
from app.core.config import setting
from app.core.models import ActionType, AgentAction, Decision
from app.main import app


def test_bulkhead_environment_precedes_legacy_and_falls_back(monkeypatch) -> None:
    monkeypatch.setenv("AIRLOCK_HOST", "legacy-host")
    monkeypatch.setenv("BULKHEAD_HOST", "bulkhead-host")
    assert setting("HOST") == "bulkhead-host"

    monkeypatch.delenv("BULKHEAD_HOST")
    assert setting("HOST") == "legacy-host"


def test_new_client_names_and_deprecated_aliases_share_implementations() -> None:
    assert AirlockClient is BulkheadClient
    assert AirlockBlocked is BulkheadBlocked
    assert airlock_guard is bulkhead_guard


def test_legacy_api_key_environment_and_header_remain_supported(monkeypatch) -> None:
    monkeypatch.delenv("BULKHEAD_API_KEY", raising=False)
    monkeypatch.setenv("AIRLOCK_API_KEY", "legacy-key")
    client = TestClient(app)
    payload = {"action_type": "read_file", "target": "/workspace/README.md"}

    assert client.post("/api/evaluate", json=payload).status_code == 401
    assert client.post("/api/evaluate", headers={"X-Airlock-Key": "legacy-key"}, json=payload).status_code == 200


def test_database_default_and_legacy_migration_preserve_records(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("BULKHEAD_DB_PATH", raising=False)
    monkeypatch.delenv("AIRLOCK_DB_PATH", raising=False)

    default_ledger = EventLedger()
    assert Path(default_ledger.db_path) == Path("data/bulkhead.db")
    default_ledger.close()

    Path("data/bulkhead.db").unlink()
    legacy_ledger = EventLedger("data/airlock.db")
    event = legacy_ledger.record_event(
        action=AgentAction(action_type=ActionType.READ_FILE, target="/workspace/README.md"),
        decision=Decision.ALLOW,
        reason="legacy record",
        risk_score=0,
        findings=[],
    )
    legacy_ledger.close()

    migrated = EventLedger()
    assert Path(migrated.db_path) == Path("data/bulkhead.db")
    assert migrated.events()[0].id == event.id
    assert Path("data/airlock.db").exists()
    migrated.close()
