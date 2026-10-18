"""Deterministic policy gateway tying intent, detections, audit, and HoneyWorld together."""

from __future__ import annotations

import hashlib
import html
import json
import os
import re
import unicodedata
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import unquote

from app.audit.ledger import EventLedger
from app.honeyworld.simulation import HoneyWorld

from .detectors import ThreatDetector, normalize_posix_target
from .llm_judge import LLMJudge
from .models import (
    ActionType,
    AgentAction,
    Decision,
    DecisionResult,
    ThreatCategory,
    ThreatFinding,
    UserIntent,
)

DEFAULT_INTENT = UserIntent(
    goal="Read files from the local workspace only",
    allowed_actions=[ActionType.READ_FILE],
    allowed_targets=["/workspace/"],
    denied_targets=[],
    allow_network=False,
)


class PolicyGateway:
    def __init__(
        self,
        ledger: EventLedger | None = None,
        honeyworld: HoneyWorld | None = None,
        llm_judge: LLMJudge | None = None,
    ) -> None:
        self.ledger = ledger or EventLedger()
        self.honeyworld = honeyworld or HoneyWorld()
        self.detector = ThreatDetector()
        self.llm_judge = llm_judge or LLMJudge()

    @staticmethod
    def fingerprint(action: AgentAction) -> str:
        """Return a stable fingerprint tolerant of harmless formatting changes.

        Agent ids and metadata are deliberately excluded: they describe the caller,
        rather than the operation being protected.  Paths, object key order, URL
        casing, and whitespace are canonicalized before hashing.
        """
        findings = ThreatDetector().inspect(action)
        value = {
            "action_type": getattr(action.action_type, "value", action.action_type),
            "target": PolicyGateway._canonical_target(action.target),
            "finding_labels": sorted(finding.label for finding in findings),
            "content": PolicyGateway._canonical_string(action.content or ""),
            "payload": PolicyGateway._canonical_value(action.payload),
        }
        encoded = json.dumps(value, sort_keys=True, default=str, separators=(",", ":"))
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:16]

    @staticmethod
    def _canonical_string(value: str) -> str:
        # Canonicalize transport encoding, case, punctuation, and spacing, but do
        # not apply detector leetspeak substitutions: distinct payload values must
        # not collapse to one immunity fingerprint.
        value = html.unescape(unquote(unicodedata.normalize("NFKC", value))).casefold()
        value = re.sub(r"[^\w\s]+", " ", value, flags=re.UNICODE)
        return re.sub(r"\s+", " ", value).strip()

    @staticmethod
    def _canonical_target(value: str) -> str:
        try:
            target = normalize_posix_target(value)
        except ValueError:
            target = value.strip().replace("\\", "/")
        if "://" in target:
            return re.sub(r"\s+", "", target).casefold().rstrip("/")
        return target.rstrip("/") or ("/" if target.startswith("/") else "")

    @classmethod
    def _canonical_value(cls, value: Any) -> Any:
        if isinstance(value, dict):
            return {str(key).casefold(): cls._canonical_value(child) for key, child in sorted(value.items(), key=lambda item: str(item[0]).casefold())}
        if isinstance(value, (list, tuple)):
            return [cls._canonical_value(child) for child in value]
        if isinstance(value, str):
            return cls._canonical_string(value)
        return value

    def _intent_findings(self, action: AgentAction, intent: UserIntent) -> list[ThreatFinding]:
        findings: list[ThreatFinding] = []
        try:
            target = normalize_posix_target(action.target)
        except ValueError:
            target = action.target
            findings.append(
                ThreatFinding(
                    category=ThreatCategory.INTENT_VIOLATION,
                    label="invalid_target",
                    evidence=action.target[:160],
                    severity=100,
                )
            )

        if intent.allowed_actions and action.action_type not in intent.allowed_actions:
            findings.append(
                ThreatFinding(
                    category=ThreatCategory.INTENT_VIOLATION,
                    label="action_not_in_intent",
                    evidence=str(action.action_type),
                    severity=70,
                )
            )
        if intent.allowed_targets and not any(self._target_is_within(target, prefix) for prefix in intent.allowed_targets):
            findings.append(
                ThreatFinding(
                    category=ThreatCategory.INTENT_VIOLATION,
                    label="target_outside_intent",
                    evidence=action.target[:160],
                    severity=70,
                )
            )
        if any(self._target_is_within(target, prefix) for prefix in intent.denied_targets):
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

    @staticmethod
    def _target_is_within(target: str, allowed: str) -> bool:
        """Match a path itself or a complete folder, never a prefix lookalike."""
        try:
            target = normalize_posix_target(target)
            allowed = normalize_posix_target(allowed)
        except ValueError:
            return False
        if not allowed:
            return target == allowed
        if "://" in allowed or "://" in target:
            return target == allowed or target.startswith(allowed.rstrip("/") + "/")
        try:
            return PurePosixPath(target).is_relative_to(PurePosixPath(allowed))
        except (ValueError, TypeError):
            return False

    def evaluate(
        self,
        action: AgentAction,
        intent: UserIntent | None = None,
        *,
        run_honeyworld: bool = True,
    ) -> DecisionResult:
        intent = intent or DEFAULT_INTENT.model_copy(deep=True)
        fingerprint = self.fingerprint(action)
        existing_rule = self.ledger.find_immunity(fingerprint)
        findings = self.detector.inspect(action)
        findings.extend(self._intent_findings(action, intent))

        security_findings = [finding for finding in findings if finding.category != ThreatCategory.INTENT_VIOLATION]
        high_security_finding = any(finding.severity >= 70 for finding in security_findings)
        has_prompt_injection = any(finding.category == ThreatCategory.PROMPT_INJECTION for finding in security_findings)
        has_sensitive_file = any(finding.label == "sensitive_file_access" for finding in security_findings)
        has_keyword_network = any(finding.label == "secret_to_network" for finding in security_findings)

        if existing_rule:
            existing_rule = self.ledger.mark_rule_matched(existing_rule.id) or existing_rule
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
        elif any(f.category == ThreatCategory.DESTRUCTIVE_COMMAND for f in findings):
            decision = Decision.BLOCK
            reason = "Blocked because the command matches a destructive-operation policy."
            risk_score = min(100, max(f.severity for f in findings))
        elif has_prompt_injection or has_sensitive_file or has_keyword_network or high_security_finding:
            decision = Decision.QUARANTINE
            reason = "Suspicious action isolated in HoneyWorld for safe observation."
            risk_score = min(100, max(f.severity for f in findings))
        elif any(finding.category == ThreatCategory.INTENT_VIOLATION for finding in findings):
            decision = Decision.BLOCK
            reason = "Action is outside the supplied user intent."
            risk_score = min(100, max(f.severity for f in findings))
        else:
            decision = Decision.ALLOW
            reason = "Action matches the current user intent; low-severity keyword signals were recorded without blocking."
            risk_score = min(100, max((f.severity for f in findings), default=0))

        # The optional judge is explainability only.  It is intentionally gated
        # by an explicit environment flag and a deterministic borderline score;
        # it never changes the decision or invokes a network client by itself.
        if os.getenv("AIRLOCK_LLM_JUDGE") == "1" and 30 <= risk_score <= 69:
            judge_result = self.llm_judge.judge(action, intent, deterministic_risk=risk_score)
            if judge_result.rationale and not judge_result.rationale.startswith("Deterministic policy"):
                reason = f"{reason} Judge rationale: {judge_result.rationale}"

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
                self.ledger.record_capture(event.id, honey_result)
            self.ledger.update_incident(incident)
            self.ledger.update_event(event)
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
