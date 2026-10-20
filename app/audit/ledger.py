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

from .schema import create_schema


@dataclass(frozen=True)
class ResetMessage:
    """A boundary between audit runs for live subscribers."""


LedgerMessage = AuditEvent | ResetMessage
RESET_MESSAGE = ResetMessage()
MAX_PAGE_SIZE = 500


class EventLedger:
    """Thread-safe SQLite repository for audit, incident, rule, and capture data."""

    def __init__(self, db_path: str | None = None) -> None:
        """Open the ledger database and initialize its schema."""
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
        create_schema(self._connection, self._number)

    def reset(self) -> None:
        """Clear records and notify live subscribers of the run boundary."""
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
                self._connection = None  # type: ignore[assignment]

    def __enter__(self) -> Self:
        """Return this ledger as a context-managed resource."""
        return self

    def __exit__(self, *_exc: object) -> None:
        """Close the ledger when leaving a context manager."""
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
        return str(model.model_dump_json())

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
        """Persist an action decision and publish it to live subscribers."""
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
        """Register a queue for new events and reset notifications."""
        queue: Queue[LedgerMessage] = Queue()
        with self._lock:
            self._subscribers.add(queue)
        return queue

    def subscribe_with_snapshot(self) -> tuple[Queue[LedgerMessage], list[AuditEvent]]:
        """Register before reading a snapshot so no event can be lost."""
        with self._lock:
            subscriber = self.subscribe()
            return subscriber, self.events()

    def unsubscribe(self, queue: Queue[LedgerMessage]) -> None:
        """Remove a live subscriber queue."""
        with self._lock:
            self._subscribers.discard(queue)

    def record_incident(
        self, action: AgentAction, findings: list[ThreatFinding], event_id: str, fingerprint: str
    ) -> Incident:
        """Persist an incident linked to an audit event."""
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
        """Reuse or learn a durable rule for an incident fingerprint."""
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
                return ImmunityRule.model_validate_json(existing[0])
            with self._connection:
                rule = ImmunityRule(
                    id=self._next_id("immunity_rules", "immune-"),
                    fingerprint=fingerprint,
                    source_incident_id=incident.id,
                    description=f"Rule blocks a repeat attack with fingerprint {fingerprint}.",
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
        """Find the newest enabled rule for a fingerprint."""
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
        """Change a persisted rule's enabled state."""
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
        """Delete a rule and report whether it existed."""
        with self._lock:
            with self._connection:
                cursor = self._connection.execute("DELETE FROM immunity_rules WHERE id = ?", (rule_id,))
            return cursor.rowcount > 0

    def get_event(self, event_id: str) -> AuditEvent | None:
        """Load one audit event by identifier."""
        with self._lock:
            row = self._connection.execute("SELECT payload FROM events WHERE id = ?", (event_id,)).fetchone()
            return self._load(AuditEvent, row[0]) if row else None

    def get_incident(self, incident_id: str) -> Incident | None:
        """Load one incident by identifier."""
        with self._lock:
            row = self._connection.execute(
                "SELECT payload FROM incidents WHERE id = ?", (incident_id,)
            ).fetchone()
            return self._load(Incident, row[0]) if row else None

    def get_rule(self, rule_id: str) -> ImmunityRule | None:
        """Load one immunity rule by identifier."""
        with self._lock:
            row = self._connection.execute(
                "SELECT payload FROM immunity_rules WHERE id = ?", (rule_id,)
            ).fetchone()
            return self._load(ImmunityRule, row[0]) if row else None

    def update_event(self, event: AuditEvent) -> AuditEvent:
        """Persist changes to an existing audit event."""
        with self._lock, self._connection:
            self._connection.execute(
                "UPDATE events SET timestamp = ?, payload = ? WHERE id = ?",
                (event.timestamp.isoformat(), self._dump(event), event.id),
            )
        return event

    def update_incident(self, incident: Incident) -> Incident:
        """Persist changes to an existing incident."""
        with self._lock, self._connection:
            self._connection.execute(
                "UPDATE incidents SET created_at = ?, payload = ? WHERE id = ?",
                (incident.created_at.isoformat(), self._dump(incident), incident.id),
            )
        return incident

    def record_capture(self, event_id: str | None, capture: dict[str, Any]) -> dict[str, Any]:
        """Store a decoy receipt linked to the originating event."""
        captured_at = datetime.now(UTC)
        with self._lock, self._connection:
            cursor = self._connection.execute(
                "INSERT INTO honeyworld_captures(event_id, captured_at, payload) VALUES (?, ?, ?)",
                (event_id, captured_at.isoformat(), json.dumps(capture, default=str)),
            )
            capture_id = cursor.lastrowid
        return {"id": capture_id, "event_id": event_id, "captured_at": captured_at, **capture}

    def captures(self, *, limit: int | None = None, offset: int = 0) -> list[dict[str, Any]]:
        """Return a page of HoneyWorld capture receipts."""
        limit, offset = self._page_args(limit, offset)
        with self._lock:
            query = "SELECT id, event_id, captured_at, payload FROM honeyworld_captures ORDER BY id"
            parameters: tuple[int, ...] = ()
            if limit is not None:
                query += " LIMIT ? OFFSET ?"
                parameters = (limit, offset)
            rows = self._connection.execute(query, parameters).fetchall()
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

    @staticmethod
    def _page_args(limit: int | None, offset: int) -> tuple[int | None, int]:
        """Validate a page request while preserving the unpaged API default."""
        if offset < 0:
            raise ValueError("offset must be non-negative")
        if limit is not None and not 1 <= limit <= MAX_PAGE_SIZE:
            raise ValueError(f"limit must be between 1 and {MAX_PAGE_SIZE}")
        return limit, offset

    def events(self, *, limit: int | None = None, offset: int = 0) -> list[AuditEvent]:
        """Return a page of audit events in insertion order."""
        limit, offset = self._page_args(limit, offset)
        with self._lock:
            query = "SELECT payload FROM events ORDER BY rowid"
            parameters: tuple[int, ...] = ()
            if limit is not None:
                query += " LIMIT ? OFFSET ?"
                parameters = (limit, offset)
            rows = self._connection.execute(query, parameters).fetchall()
            return [self._load(AuditEvent, row[0]) for row in rows]

    def incidents(self, *, limit: int | None = None, offset: int = 0) -> list[Incident]:
        """Return a page of incidents in insertion order."""
        limit, offset = self._page_args(limit, offset)
        with self._lock:
            query = "SELECT payload FROM incidents ORDER BY rowid"
            parameters: tuple[int, ...] = ()
            if limit is not None:
                query += " LIMIT ? OFFSET ?"
                parameters = (limit, offset)
            rows = self._connection.execute(query, parameters).fetchall()
            return [self._load(Incident, row[0]) for row in rows]

    def immunity_rules(self, *, limit: int | None = None, offset: int = 0) -> list[ImmunityRule]:
        """Return a page of immunity rules in insertion order."""
        limit, offset = self._page_args(limit, offset)
        with self._lock:
            query = "SELECT payload FROM immunity_rules ORDER BY rowid"
            parameters: tuple[int, ...] = ()
            if limit is not None:
                query += " LIMIT ? OFFSET ?"
                parameters = (limit, offset)
            rows = self._connection.execute(query, parameters).fetchall()
            return [self._load(ImmunityRule, row[0]) for row in rows]
