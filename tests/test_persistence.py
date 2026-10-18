from app.audit.ledger import EventLedger
from app.core.models import ActionType, AgentAction, Decision, ThreatCategory, ThreatFinding


def test_file_ledger_persists_all_audit_collections(tmp_path) -> None:
    database = tmp_path / "audit.db"
    ledger = EventLedger(str(database))
    finding = ThreatFinding(
        category=ThreatCategory.SECRET_EXFILTRATION,
        label="secret_to_network",
        evidence="fake secret",
        severity=95,
    )
    action = AgentAction(action_type=ActionType.READ_FILE, target="/workspace/.env")
    event = ledger.record_event(
        action=action,
        decision=Decision.QUARANTINE,
        reason="test quarantine",
        risk_score=95,
        findings=[finding],
    )
    incident = ledger.record_incident(action, [finding], event.id, "fingerprint")
    rule = ledger.generate_immunity_rule(incident, "fingerprint")
    ledger.record_capture(event.id, {"simulated": True, "network_called": False})

    reopened = EventLedger(str(database))
    assert reopened.events()[0].id == event.id
    assert reopened.incidents()[0].id == incident.id
    assert reopened.immunity_rules()[0].id == rule.id
    assert reopened.captures()[0]["event_id"] == event.id
    assert reopened._connection.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"


def test_memory_ledger_reset_preserves_original_ephemeral_behavior() -> None:
    ledger = EventLedger(":memory:")
    ledger.record_event(
        action=AgentAction(action_type=ActionType.READ_FILE, target="/workspace/README.md"),
        decision=Decision.ALLOW,
        reason="ok",
        risk_score=0,
        findings=[],
    )
    ledger.reset()
    assert ledger.events() == []


def test_reset_clears_durable_collections_and_restarts_ids(tmp_path) -> None:
    ledger = EventLedger(str(tmp_path / "reset.db"))
    ledger.record_event(
        action=AgentAction(action_type=ActionType.READ_FILE, target="/workspace/a"),
        decision=Decision.ALLOW,
        reason="ok",
        risk_score=0,
        findings=[],
    )
    ledger.reset()
    assert ledger.events() == []
    assert ledger.incidents() == []
    assert ledger.immunity_rules() == []
    assert ledger.captures() == []
    event = ledger.record_event(
        action=AgentAction(action_type=ActionType.READ_FILE, target="/workspace/b"),
        decision=Decision.ALLOW,
        reason="ok",
        risk_score=0,
        findings=[],
    )
    assert event.id == "evt-0001"
