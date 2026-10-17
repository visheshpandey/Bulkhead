"""Thread-safe in-memory Black Box event ledger for the local demo."""

from __future__ import annotations

from threading import RLock

from app.core.models import AgentAction, AuditEvent, Decision, ImmunityRule, Incident, ThreatFinding


class EventLedger:
    def __init__(self) -> None:
        self._lock = RLock()
        self.reset()

    def reset(self) -> None:
        with getattr(self, "_lock", RLock()):
            self._events: list[AuditEvent] = []
            self._incidents: list[Incident] = []
            self._rules: list[ImmunityRule] = []
            self._event_number = 0
            self._incident_number = 0
            self._rule_number = 0

    def record_event(
        self,
        *,
        action: AgentAction,
        decision: Decision,
        reason: str,
        risk_score: int,
        findings: list[ThreatFinding],
        immunity_rule_id: str | None = None,
    ) -> AuditEvent:
        with self._lock:
            self._event_number += 1
            event = AuditEvent(
                id=f"evt-{self._event_number:04d}",
                action=action,
                decision=decision,
                reason=reason,
                risk_score=risk_score,
                findings=findings,
                immunity_rule_id=immunity_rule_id,
            )
            self._events.append(event)
            return event

    def record_incident(
        self, action: AgentAction, findings: list[ThreatFinding], event_id: str, fingerprint: str
    ) -> Incident:
        with self._lock:
            self._incident_number += 1
            incident = Incident(
                id=f"inc-{self._incident_number:04d}",
                action=action,
                findings=findings,
                event_id=event_id,
                fingerprint=fingerprint,
            )
            self._incidents.append(incident)
            return incident

    def generate_immunity_rule(self, incident: Incident, fingerprint: str) -> ImmunityRule:
        with self._lock:
            self._rule_number += 1
            rule = ImmunityRule(
                id=f"immune-{self._rule_number:04d}",
                fingerprint=fingerprint,
                source_incident_id=incident.id,
                description=f"Block the quarantined action fingerprint {fingerprint}.",
            )
            self._rules.append(rule)
            return rule

    def find_immunity(self, fingerprint: str) -> ImmunityRule | None:
        with self._lock:
            return next((rule for rule in self._rules if rule.fingerprint == fingerprint), None)

    def events(self) -> list[AuditEvent]:
        with self._lock:
            return list(self._events)

    def incidents(self) -> list[Incident]:
        with self._lock:
            return list(self._incidents)

    def immunity_rules(self) -> list[ImmunityRule]:
        with self._lock:
            return list(self._rules)
