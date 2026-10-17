"""Deterministic policy gateway tying intent, detections, audit, and HoneyWorld together."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from app.audit.ledger import EventLedger
from app.honeyworld.simulation import HoneyWorld

from .detectors import ThreatDetector
from .models import (
    ActionType,
    AgentAction,
    Decision,
    DecisionResult,
    ThreatCategory,
    ThreatFinding,
    UserIntent,
)


class PolicyGateway:
    def __init__(self, ledger: EventLedger | None = None, honeyworld: HoneyWorld | None = None) -> None:
        self.ledger = ledger or EventLedger()
        self.honeyworld = honeyworld or HoneyWorld()
        self.detector = ThreatDetector()

    @staticmethod
    def fingerprint(action: AgentAction) -> str:
        value = {
            "action_type": action.action_type,
            "target": action.target,
            "payload": action.payload,
            "content": action.content,
        }
        encoded = json.dumps(value, sort_keys=True, default=str, separators=(",", ":"))
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:16]

    def _intent_findings(self, action: AgentAction, intent: UserIntent) -> list[ThreatFinding]:
        findings: list[ThreatFinding] = []
        if intent.allowed_actions and action.action_type not in intent.allowed_actions:
            findings.append(
                ThreatFinding(
                    category=ThreatCategory.INTENT_VIOLATION,
                    label="action_not_in_intent",
                    evidence=str(action.action_type),
                    severity=70,
                )
            )
        if intent.allowed_targets and not any(action.target.startswith(prefix) for prefix in intent.allowed_targets):
            findings.append(
                ThreatFinding(
                    category=ThreatCategory.INTENT_VIOLATION,
                    label="target_outside_intent",
                    evidence=action.target[:160],
                    severity=70,
                )
            )
        if any(action.target.startswith(prefix) for prefix in intent.denied_targets):
            findings.append(
                ThreatFinding(
                    category=ThreatCategory.INTENT_VIOLATION,
                    label="target_explicitly_denied",
                    evidence=action.target[:160],
                    severity=90,
                )
            )
        if action.action_type == ActionType.HTTP_REQUEST and not intent.allow_network:
            findings.append(
                ThreatFinding(
                    category=ThreatCategory.INTENT_VIOLATION,
                    label="network_not_in_intent",
                    evidence=action.target[:160],
                    severity=75,
                )
            )
        return findings

    def evaluate(
        self,
        action: AgentAction,
        intent: UserIntent | None = None,
        *,
        run_honeyworld: bool = True,
    ) -> DecisionResult:
        intent = intent or UserIntent()
        fingerprint = self.fingerprint(action)
        existing_rule = self.ledger.find_immunity(fingerprint)
        findings = self.detector.inspect(action)
        findings.extend(self._intent_findings(action, intent))

        if existing_rule:
            existing_rule.match_count += 1
            findings = [
                ThreatFinding(
                    category=ThreatCategory.IMMUNITY_RULE,
                    label="known_quarantined_action",
                    evidence=existing_rule.description,
                    severity=100,
                )
            ]
            decision = Decision.BLOCK
            reason = "Blocked by an immunity rule generated from a prior quarantine."
            risk_score = 100
        elif any(f.category in {ThreatCategory.PROMPT_INJECTION, ThreatCategory.SECRET_EXFILTRATION} for f in findings):
            decision = Decision.QUARANTINE
            reason = "Suspicious action isolated in HoneyWorld for safe observation."
            risk_score = min(100, max(f.severity for f in findings))
        elif findings:
            decision = Decision.BLOCK
            reason = "Action is outside the supplied user intent."
            risk_score = min(100, max(f.severity for f in findings))
        else:
            decision = Decision.ALLOW
            reason = "Action matches the current user intent and no threat signals were found."
            risk_score = 0

        event = self.ledger.record_event(
            action=action,
            decision=decision,
            reason=reason,
            risk_score=risk_score,
            findings=findings,
            immunity_rule_id=existing_rule.id if existing_rule else None,
        )
        incident = None
        generated_rule = None
        honey_result: dict[str, Any] | None = None
        if decision == Decision.QUARANTINE:
            incident = self.ledger.record_incident(action, findings, event.id, fingerprint)
            generated_rule = self.ledger.generate_immunity_rule(incident, fingerprint)
            incident.immunity_rule_id = generated_rule.id
            event.incident_id = incident.id
            event.immunity_rule_id = generated_rule.id
            if run_honeyworld:
                honey_result = self.honeyworld.execute(action)
                event.honeyworld_result = honey_result
        return DecisionResult(
            decision=decision,
            allowed=decision == Decision.ALLOW,
            reason=reason,
            risk_score=risk_score,
            findings=findings,
            event=event,
            incident=incident,
            immunity_rule=generated_rule or existing_rule,
            honeyworld=honey_result,
        )

    def reset(self) -> None:
        self.ledger.reset()
        self.honeyworld.reset()

    def state(self) -> dict[str, Any]:
        events = self.ledger.events()
        incidents = self.ledger.incidents()
        rules = self.ledger.immunity_rules()
        return {
            "events": events,
            "incidents": incidents,
            "immunity_rules": rules,
            "counts": {
                "events": len(events),
                "incidents": len(incidents),
                "immunity_rules": len(rules),
            },
            "honeyworld": self.honeyworld.state(),
        }
