"""Thread-safe SQLite-backed Black Box event ledger."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from queue import Empty, Queue
from threading import RLock
from typing import Any, Self

from app.core.config import database_path
from app.core.models import AgentAction, AuditEvent, Decision, ImmunityRule, Incident, ThreatFinding


@dataclass(frozen=True)
class ResetMessage:
    """A boundary between audit runs for live subscribers."""


LedgerMessage = AuditEvent | ResetMessage
RESET_MESSAGE = ResetMessage()


class EventLedger:
    def __init__(self, db_path: str | None = None) -> None:
        self._lock = RLock()
        self._subscribers: set[Queue[LedgerMessage]] = set()
        self.db_path = database_path(db_path)
        if self.db_path != ":memory:":
            Path(self.db_path).expanduser().parent.mkdir(parents=True, exist_ok=True)
        # One connection is deliberately retained for :memory: databases.
        self._connection = sqlite3.connect(self.db_path, check_same_thread=False, timeout=30)
        self._connection.row_factory = sqlite3.Row
        if self.db_path != ":memory:":
            self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA foreign_keys=ON")
        self._create_schema()

    def _create_schema(self) -> None:
        with self._connection:
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS incidents (
                    id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS immunity_rules (
                    id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    last_matched_at TEXT,
                    match_count INTEGER NOT NULL DEFAULT 0,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_rules_fingerprint
                    ON immunity_rules(fingerprint);
                CREATE TABLE IF NOT EXISTS honeyworld_captures (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT,
                    captured_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS id_counters (
                    collection TEXT PRIMARY KEY,
                    last_value INTEGER NOT NULL
                );
                """
            )
            # Migrate old ledgers based on all IDs still present. From this point
            # onward counters survive row deletion and reset.
            for table in ("events", "incidents", "immunity_rules"):
                prefix = {"events": "evt-", "incidents": "inc-", "immunity_rules": "immune-"}[table]
                ids = self._connection.execute(f"SELECT id FROM {table}").fetchall()
                highest = max((self._number(prefix, row[0]) for row in ids), default=0)
                self._connection.execute(
                    "INSERT INTO id_counters(collection, last_value) VALUES (?, ?) "
                    "ON CONFLICT(collection) DO UPDATE SET last_value = MAX(last_value, excluded.last_value)",
                    (table, highest),
                )

    def reset(self) -> None:
        with getattr(self, "_lock", RLock()):
            if not hasattr(self, "_connection"):
                return
            with self._connection:
                self._connection.execute("DELETE FROM events")
                self._connection.execute("DELETE FROM incidents")
                self._connection.execute("DELETE FROM immunity_rules")
                self._connection.execute("DELETE FROM honeyworld_captures")
            # A stream opened before a reset must not receive records from the
            # previous demo run after it reconnects.
            for subscriber in tuple(self._subscribers):
                while True:
                    try:
                        subscriber.get_nowait()
                    except Empty:
                        break
                subscriber.put_nowait(RESET_MESSAGE)

    def close(self) -> None:
        """Close the SQLite connection (useful for short-lived integrations)."""
        with self._lock:
            if getattr(self, "_connection", None) is not None:
                self._connection.close()
                self._connection = None

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    @staticmethod
    def _number(prefix: str, identifier: str) -> int:
        if not identifier.startswith(prefix) or not identifier[len(prefix):].isdigit():
            return 0
        try:
            return int(identifier[len(prefix):])
        except ValueError:
            return 0

    def _next_id(self, table: str, prefix: str) -> str:
        # Called inside the insert transaction: the first write obtains SQLite's
        # writer lock, so separate ledger connections cannot allocate the same ID.
        row = self._connection.execute(
            "UPDATE id_counters SET last_value = last_value + 1 "
            "WHERE collection = ? RETURNING last_value", (table,)
        ).fetchone()
        return f"{prefix}{row[0]:04d}"

    @staticmethod
    def _dump(model: Any) -> str:
        return model.model_dump_json()

    @staticmethod
    def _load(model: type[Any], payload: str) -> Any:
        return model.model_validate_json(payload)

    def record_event(
        self,
        *,
        action: AgentAction,
        decision: Decision,
        reason: str,
        risk_score: int,
        findings: list[ThreatFinding],
        immunity_rule_id: str | None = None,
        agent_id: str | None = None,
    ) -> AuditEvent:
        with self._lock:
            with self._connection:
                event = AuditEvent(
                    id=self._next_id("events", "evt-"),
                    agent_id=agent_id,
                    action=action,
                    decision=decision,
                    reason=reason,
                    risk_score=risk_score,
                    findings=findings,
                    immunity_rule_id=immunity_rule_id,
                )
                self._connection.execute(
                    "INSERT INTO events(id, timestamp, payload) VALUES (?, ?, ?)",
                    (event.id, event.timestamp.isoformat(), self._dump(event)),
                )
            for subscriber in tuple(self._subscribers):
                subscriber.put_nowait(event)
            return event

    def subscribe(self) -> Queue[LedgerMessage]:
        queue: Queue[LedgerMessage] = Queue()
        with self._lock:
            self._subscribers.add(queue)
        return queue

    def subscribe_with_snapshot(self) -> tuple[Queue[LedgerMessage], list[AuditEvent]]:
        with self._lock:
            subscriber = self.subscribe()
            return subscriber, self.events()

    def unsubscribe(self, queue: Queue[LedgerMessage]) -> None:
        with self._lock:
            self._subscribers.discard(queue)

    def record_incident(
        self, action: AgentAction, findings: list[ThreatFinding], event_id: str, fingerprint: str
    ) -> Incident:
        with self._lock:
            with self._connection:
                incident = Incident(
                    id=self._next_id("incidents", "inc-"),
                    action=action,
                    findings=findings,
                    event_id=event_id,
                    fingerprint=fingerprint,
                )
                self._connection.execute(
                    "INSERT INTO incidents(id, created_at, payload) VALUES (?, ?, ?)",
                    (incident.id, incident.created_at.isoformat(), self._dump(incident)),
                )
            return incident

    def generate_immunity_rule(self, incident: Incident, fingerprint: str) -> ImmunityRule:
        with self._lock:
            # A disabled rule still records the learned fingerprint. Reusing it
            # avoids an unbounded collection of duplicate rules when an operator
            # temporarily disables a rule and the same attack is retried.
            existing = self._connection.execute(
                "SELECT payload FROM immunity_rules WHERE fingerprint = ? "
                "ORDER BY created_at DESC LIMIT 1",
                (fingerprint,),
            ).fetchone()
            if existing:
                return self._load(ImmunityRule, existing[0])
            with self._connection:
                rule = ImmunityRule(
                    id=self._next_id("immunity_rules", "immune-"),
                    fingerprint=fingerprint,
                    source_incident_id=incident.id,
                    description=f"Block the quarantined action fingerprint {fingerprint}.",
                )
                self._connection.execute(
                    """INSERT INTO immunity_rules
                       (id, created_at, fingerprint, enabled, last_matched_at, match_count, payload)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (
                        rule.id,
                        rule.created_at.isoformat(),
                        rule.fingerprint,
                        int(rule.enabled),
                        None,
                        rule.match_count,
                        self._dump(rule),
                    ),
                )
            return rule

    def find_immunity(self, fingerprint: str) -> ImmunityRule | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT payload FROM immunity_rules WHERE fingerprint = ? AND enabled = 1 "
                "ORDER BY created_at DESC LIMIT 1",
                (fingerprint,),
            ).fetchone()
            return self._load(ImmunityRule, row[0]) if row else None

    def mark_rule_matched(self, rule_id: str) -> ImmunityRule | None:
        """Increment a rule's match count and persist its match timestamp."""
        with self._lock:
            rule = self.get_rule(rule_id)
            if rule is None:
                return None
            rule.match_count += 1
            rule.last_matched_at = datetime.now(UTC)
            with self._connection:
                self._connection.execute(
                    "UPDATE immunity_rules SET match_count = ?, last_matched_at = ?, payload = ? WHERE id = ?",
                    (rule.match_count, rule.last_matched_at.isoformat(), self._dump(rule), rule.id),
                )
            return rule

    def update_rule(self, rule_id: str, *, enabled: bool | None = None) -> ImmunityRule | None:
        with self._lock:
            rule = self.get_rule(rule_id)
            if rule is None:
                return None
            if enabled is not None:
                rule.enabled = enabled
            with self._connection:
                self._connection.execute(
                    "UPDATE immunity_rules SET enabled = ?, payload = ? WHERE id = ?",
                    (int(rule.enabled), self._dump(rule), rule.id),
                )
            return rule

    def delete_rule(self, rule_id: str) -> bool:
        with self._lock:
            with self._connection:
                cursor = self._connection.execute("DELETE FROM immunity_rules WHERE id = ?", (rule_id,))
            return cursor.rowcount > 0

    def get_event(self, event_id: str) -> AuditEvent | None:
        with self._lock:
            row = self._connection.execute("SELECT payload FROM events WHERE id = ?", (event_id,)).fetchone()
            return self._load(AuditEvent, row[0]) if row else None

    def get_incident(self, incident_id: str) -> Incident | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT payload FROM incidents WHERE id = ?", (incident_id,)
            ).fetchone()
            return self._load(Incident, row[0]) if row else None

    def get_rule(self, rule_id: str) -> ImmunityRule | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT payload FROM immunity_rules WHERE id = ?", (rule_id,)
            ).fetchone()
            return self._load(ImmunityRule, row[0]) if row else None

    def update_event(self, event: AuditEvent) -> AuditEvent:
        with self._lock, self._connection:
            self._connection.execute(
                "UPDATE events SET timestamp = ?, payload = ? WHERE id = ?",
                (event.timestamp.isoformat(), self._dump(event), event.id),
            )
        return event

    def update_incident(self, incident: Incident) -> Incident:
        with self._lock, self._connection:
            self._connection.execute(
                "UPDATE incidents SET created_at = ?, payload = ? WHERE id = ?",
                (incident.created_at.isoformat(), self._dump(incident), incident.id),
            )
        return incident

    def record_capture(self, event_id: str | None, capture: dict[str, Any]) -> dict[str, Any]:
        captured_at = datetime.now(UTC)
        with self._lock, self._connection:
            cursor = self._connection.execute(
                "INSERT INTO honeyworld_captures(event_id, captured_at, payload) VALUES (?, ?, ?)",
                (event_id, captured_at.isoformat(), json.dumps(capture, default=str)),
            )
            capture_id = cursor.lastrowid
        return {"id": capture_id, "event_id": event_id, "captured_at": captured_at, **capture}

    def captures(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT id, event_id, captured_at, payload FROM honeyworld_captures ORDER BY id"
            ).fetchall()
            return [
                {
                    "id": row[0],
                    "event_id": row[1],
                    "captured_at": row[2],
                    **json.loads(row[3]),
                }
                for row in rows
            ]

    def honeyworld_captures(self) -> list[dict[str, Any]]:
        """Explicitly named alias for callers working with HoneyWorld records."""
        return self.captures()

    def events(self) -> list[AuditEvent]:
        with self._lock:
            rows = self._connection.execute("SELECT payload FROM events ORDER BY rowid").fetchall()
            return [self._load(AuditEvent, row[0]) for row in rows]

    def incidents(self) -> list[Incident]:
        with self._lock:
            rows = self._connection.execute("SELECT payload FROM incidents ORDER BY rowid").fetchall()
            return [self._load(Incident, row[0]) for row in rows]

    def immunity_rules(self) -> list[ImmunityRule]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT payload FROM immunity_rules ORDER BY rowid"
            ).fetchall()
            return [self._load(ImmunityRule, row[0]) for row in rows]
