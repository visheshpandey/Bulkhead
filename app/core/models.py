"""Typed inputs and outputs for the AIRLOCK policy gateway."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ActionType(str, Enum):
    READ_FILE = "read_file"
    WRITE_FILE = "write_file"
    RUN_COMMAND = "run_command"
    HTTP_REQUEST = "http_request"
    GITHUB_ACTION = "github_action"


class Decision(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    QUARANTINE = "quarantine"


class ThreatCategory(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    SECRET_EXFILTRATION = "secret_exfiltration"
    INTENT_VIOLATION = "intent_violation"
    IMMUNITY_RULE = "immunity_rule"


def utc_now() -> datetime:
    return datetime.now(UTC)


class AgentAction(BaseModel):
    """A tool call submitted to AIRLOCK, with no executable fields."""

    model_config = ConfigDict(use_enum_values=True)

    action_type: ActionType
    target: str = ""
    payload: dict[str, Any] = Field(default_factory=dict)
    content: str | None = None
    agent_id: str = "demo-agent"
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def accept_action_aliases(cls, value: Any) -> Any:
        if isinstance(value, dict):
            value = dict(value)
            if "action_type" not in value:
                value["action_type"] = value.get("action", value.get("type"))
        return value

    def searchable_text(self) -> str:
        """Return user-controlled action data for the detector to inspect."""
        parts = [self.target, self.content or ""]
        parts.extend(str(item) for item in self.payload.values())
        parts.extend(str(item) for item in self.metadata.values())
        return "\n".join(parts)


class UserIntent(BaseModel):
    """Optional user boundary for a group of agent actions."""

    model_config = ConfigDict(use_enum_values=True)

    goal: str = "Complete the user's requested task"
    allowed_actions: list[ActionType] | None = None
    allowed_targets: list[str] | None = None
    denied_targets: list[str] = Field(default_factory=list)
    allow_network: bool = True


class ThreatFinding(BaseModel):
    category: ThreatCategory
    label: str
    evidence: str
    severity: int = Field(ge=0, le=100)


class ImmunityRule(BaseModel):
    id: str
    fingerprint: str
    description: str
    source_incident_id: str
    created_at: datetime = Field(default_factory=utc_now)
    match_count: int = 0


class AuditEvent(BaseModel):
    id: str
    timestamp: datetime = Field(default_factory=utc_now)
    event_type: str = "policy_decision"
    action: AgentAction
    decision: Decision
    reason: str
    risk_score: int = Field(ge=0, le=100)
    findings: list[ThreatFinding] = Field(default_factory=list)
    incident_id: str | None = None
    immunity_rule_id: str | None = None
    honeyworld_result: dict[str, Any] | None = None


class Incident(BaseModel):
    id: str
    created_at: datetime = Field(default_factory=utc_now)
    status: str = "quarantined"
    action: AgentAction
    findings: list[ThreatFinding] = Field(default_factory=list)
    event_id: str
    fingerprint: str
    immunity_rule_id: str | None = None


class DecisionResult(BaseModel):
    decision: Decision
    allowed: bool
    reason: str
    risk_score: int = Field(ge=0, le=100)
    findings: list[ThreatFinding] = Field(default_factory=list)
    event: AuditEvent
    incident: Incident | None = None
    immunity_rule: ImmunityRule | None = None
    honeyworld: dict[str, Any] | None = None
