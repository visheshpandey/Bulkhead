import pytest

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
        agent_id="persisted-header-agent",
    )
    incident = ledger.record_incident(action, [finding], event.id, "fingerprint")
    rule = ledger.generate_immunity_rule(incident, "fingerprint")
    ledger.record_capture(event.id, {"simulated": True, "network_called": False})

    reopened = EventLedger(str(database))
    assert reopened.events()[0].id == event.id
    assert reopened.events()[0].agent_id == "persisted-header-agent"
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


def test_reset_broadcast_does_not_depend_on_racy_queue_empty_check(monkeypatch) -> None:
    from app.audit.ledger import ResetMessage

    with EventLedger(":memory:") as ledger:
        subscriber = ledger.subscribe()
        # empty() is advisory: a concurrent stream may consume the item before
        # reset calls get_nowait(). Reset must handle Empty rather than trust it.
        monkeypatch.setattr(subscriber, "empty", lambda: False)
        ledger.reset()
        assert isinstance(subscriber.get_nowait(), ResetMessage)


def test_reset_clears_durable_collections_but_never_reuses_ids(tmp_path) -> None:
    ledger = EventLedger(str(tmp_path / "reset.db"))
    action = AgentAction(action_type=ActionType.READ_FILE, target="/workspace/a")
    old_event = ledger.record_event(
        action=action,
        decision=Decision.ALLOW,
        reason="ok",
        risk_score=0,
        findings=[],
    )
    old_incident = ledger.record_incident(action, [], old_event.id, "old")
    old_rule = ledger.generate_immunity_rule(old_incident, "old")
    ledger.reset()
    assert ledger.events() == []
    assert ledger.incidents() == []
    assert ledger.immunity_rules() == []
    assert ledger.captures() == []
    ledger.close()
    reopened = EventLedger(str(tmp_path / "reset.db"))
    event = reopened.record_event(
        action=action,
        decision=Decision.ALLOW,
        reason="ok",
        risk_score=0,
        findings=[],
    )
    incident = reopened.record_incident(action, [], event.id, "new")
    rule = reopened.generate_immunity_rule(incident, "new")
    assert (event.id, incident.id, rule.id) == ("evt-0002", "inc-0002", "immune-0002")
    assert (event.id, incident.id, rule.id) != (old_event.id, old_incident.id, old_rule.id)
    assert reopened.delete_rule(rule.id)
    reopened.close()
    again = EventLedger(str(tmp_path / "reset.db"))
    assert again.generate_immunity_rule(incident, "third").id == "immune-0003"
    again.close()


def test_existing_ledger_ids_migrate_to_persistent_counters(tmp_path) -> None:
    import sqlite3

    database = tmp_path / "legacy.db"
    action = AgentAction(action_type=ActionType.READ_FILE, target="/workspace/a")
    original = EventLedger(str(database))
    for index in range(3):
        old_event = original.record_event(
            action=action, decision=Decision.ALLOW, reason="ok", risk_score=0, findings=[]
        )
        old_incident = original.record_incident(action, [], old_event.id, str(index))
        original.generate_immunity_rule(old_incident, str(index))
    original.close()
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TABLE id_counters")
    ledger = EventLedger(str(database))
    event = ledger.record_event(action=action, decision=Decision.ALLOW, reason="ok", risk_score=0, findings=[])
    incident = ledger.record_incident(action, [], event.id, "fresh")
    rule = ledger.generate_immunity_rule(incident, "fresh")
    assert (event.id, incident.id, rule.id) == ("evt-0004", "inc-0004", "immune-0004")
    ledger.close()


def test_ledger_collections_support_parameterized_pagination(tmp_path) -> None:
    ledger = EventLedger(str(tmp_path / "pages.db"))
    action = AgentAction(action_type=ActionType.READ_FILE, target="/workspace/a")
    for index in range(3):
        ledger.record_event(
            action=action,
            decision=Decision.ALLOW,
            reason=str(index),
            risk_score=0,
            findings=[],
        )

    assert [event.reason for event in ledger.events(limit=2)] == ["0", "1"]
    assert [event.reason for event in ledger.events(limit=2, offset=2)] == ["2"]
    assert [event.reason for event in ledger.events()] == ["0", "1", "2"]
    with pytest.raises(ValueError):
        ledger.events(limit=0)
    ledger.close()
