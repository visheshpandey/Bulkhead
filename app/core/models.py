"""Typed inputs and outputs for the AIRLOCK policy gateway."""

from __future__ import annotations

import json
import math
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


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
    DESTRUCTIVE_COMMAND = "destructive_command"
    IMMUNITY_RULE = "immunity_rule"


def utc_now() -> datetime:
    return datetime.now(UTC)


class AgentAction(BaseModel):
    """A tool call submitted to AIRLOCK, with no executable fields."""

    model_config = ConfigDict(use_enum_values=True, extra="forbid", validate_default=True)

    action_type: ActionType
    target: str = Field(default="", min_length=1, max_length=4096)
    payload: dict[str, Any] = Field(default_factory=dict)
    content: str | None = Field(default=None, max_length=200_000)
    agent_id: str = Field(default="demo-agent", min_length=1, max_length=256)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("target is required and must not be blank")
        if "\x00" in value or any(ord(character) < 32 for character in value):
            raise ValueError("target contains a control character")
        return value

    @field_validator("content")
    @classmethod
    def validate_content(cls, value: str | None) -> str | None:
        if value is not None and any(ord(character) < 32 and character not in "\t\n\r" for character in value):
            raise ValueError("content contains a control character")
        return value

    @field_validator("agent_id")
    @classmethod
    def validate_agent_id(cls, value: str) -> str:
        value = value.strip()
        if not value or any(ord(character) < 32 for character in value):
            raise ValueError("agent_id must be a non-blank printable string")
        return value

    @field_validator("payload", "metadata")
    @classmethod
    def validate_structured_input(cls, value: dict[str, Any]) -> dict[str, Any]:
        _validate_json_tree(value)
        if len(json.dumps(value, ensure_ascii=False, separators=(",", ":"))) > 200_000:
            raise ValueError("payload JSON must be at most 200 KB")
        return value

    @model_validator(mode="before")
    @classmethod
    def accept_action_aliases(cls, value: Any) -> Any:
        if isinstance(value, dict):
            value = dict(value)
            if "action_type" not in value:
                value["action_type"] = value.get("action", value.get("type"))
            value.pop("action", None)
            value.pop("type", None)
        return value

    def searchable_text(self) -> str:
        """Return user-controlled action data for the detector to inspect."""
        parts = [self.target, self.content or ""]
        parts.extend(_flatten_searchable(self.payload, "payload"))
        parts.extend(_flatten_searchable(self.metadata, "metadata"))
        return "\n".join(parts)


def _validate_json_tree(value: Any, *, depth: int = 0) -> None:
    """Reject values that cannot be safely handled by the deterministic gateway."""
    if depth > 12:
        raise ValueError("payload nesting is too deep")
    if isinstance(value, dict):
        if len(value) > 256:
            raise ValueError("payload has too many fields")
        for key, child in value.items():
            if not isinstance(key, str) or len(key) > 256 or any(ord(character) < 32 for character in key):
                raise ValueError("payload field names must be short strings")
            _validate_json_tree(child, depth=depth + 1)
    elif isinstance(value, (list, tuple)):
        if len(value) > 256:
            raise ValueError("payload list is too large")
        for child in value:
            _validate_json_tree(child, depth=depth + 1)
    elif isinstance(value, str):
        if len(value) > 200_000:
            raise ValueError("payload value is too large")
        if any(ord(character) < 32 and character not in "\t\n\r" for character in value):
            raise ValueError("payload contains a control character")
    elif isinstance(value, float) and not math.isfinite(value):
        raise ValueError("payload contains a non-finite number")
    elif value is not None and not isinstance(value, (bool, int, float)):
        raise ValueError("payload contains an unsupported value")


def _flatten_searchable(value: Any, path: str) -> list[str]:
    """Flatten keys and values so nested tool arguments cannot evade inspection."""
    if isinstance(value, dict):
        parts: list[str] = []
        for key, child in value.items():
            child_path = f"{path}.{key}"
            parts.append(child_path)
            parts.extend(_flatten_searchable(child, child_path))
        return parts
    if isinstance(value, (list, tuple)):
        parts = []
        for index, child in enumerate(value):
            parts.extend(_flatten_searchable(child, f"{path}[{index}]"))
        return parts
    return [f"{path}={value}"]


class UserIntent(BaseModel):
    """Optional user boundary for a group of agent actions."""

    model_config = ConfigDict(use_enum_values=True, extra="forbid")

    goal: str = "Complete the user's requested task"
    # A missing intent gets a deliberately small, local read-only baseline.  An
    # agent must receive an explicit broader intent before it can write, execute,
    # or access a target outside the demo workspace.
    allowed_actions: list[ActionType] | None = Field(default_factory=lambda: [ActionType.READ_FILE])
    allowed_targets: list[str] | None = Field(default_factory=lambda: ["/workspace/"])
    denied_targets: list[str] = Field(default_factory=list)
    allow_network: bool = False

    @field_validator("goal")
    @classmethod
    def validate_goal(cls, value: str) -> str:
        value = value.strip()
        if not value or len(value) > 20_000:
            raise ValueError("goal must be a non-empty, bounded string")
        return value

    @field_validator("allowed_targets", "denied_targets")
    @classmethod
    def validate_targets(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        if len(value) > 128:
            raise ValueError("too many intent targets")
        cleaned: list[str] = []
        for target in value:
            if not isinstance(target, str):
                raise TypeError("intent targets must be strings")
            target = target.strip()
            if not target or "\x00" in target or any(ord(character) < 32 for character in target):
                raise ValueError("intent target is invalid")
            if len(target) > 4096:
                raise ValueError("intent target is too long")
            cleaned.append(target)
        return cleaned


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
    enabled: bool = True
    last_matched_at: datetime | None = None


class AuditEvent(BaseModel):
    id: str
    agent_id: str | None = None
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
