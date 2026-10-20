"""HTTP request models for the Bulkhead dashboard API."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.core.models import ActionType, AgentAction, DecisionResult, UserIntent
from app.core.policy import DEFAULT_INTENT


class EvaluateRequest(BaseModel):
    """Accept either a complete action or legacy flat action fields."""

    model_config = ConfigDict(extra="forbid")

    action: AgentAction | None = None
    intent: UserIntent = Field(default_factory=lambda: DEFAULT_INTENT.model_copy(deep=True))
    run_honeyworld: bool = True
    action_type: ActionType | None = None
    type: ActionType | None = None
    target: str = ""
    payload: dict[str, Any] = Field(default_factory=dict)
    content: str | None = None
    agent_id: str = "demo-agent"
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def default_null_intent(cls, value: Any) -> Any:
        """Treat explicit null intent as the default read-only boundary."""
        if isinstance(value, dict) and value.get("intent", ...) is None:
            return {**value, "intent": DEFAULT_INTENT.model_copy(deep=True)}
        return value

    @model_validator(mode="after")
    def build_action(self) -> EvaluateRequest:
        """Construct a validated action from legacy flat fields when needed."""
        if self.action is None:
            selected_type = self.action_type or self.type
            if selected_type is None:
                raise ValueError("action or action_type is required")
            self.action = AgentAction(
                action_type=selected_type,
                target=self.target,
                payload=self.payload,
                content=self.content,
                agent_id=self.agent_id,
                metadata=self.metadata,
            )
        return self


class DemoResponse(BaseModel):
    """Result of the ordered three-step demo replay."""

    status: str
    steps: list[DecisionResult]
    state: dict[str, Any]


class RulePatch(BaseModel):
    """Partial update for a learned immunity rule."""

    enabled: bool | None = None


class ExportResponse(BaseModel):
    """JSON audit collections available for export."""

    events: list[dict[str, Any]] = Field(default_factory=list)
    incidents: list[dict[str, Any]] = Field(default_factory=list)
    immunity_rules: list[dict[str, Any]] = Field(default_factory=list)
    honeyworld_captures: list[dict[str, Any]] = Field(default_factory=list)


class LabRunRequest(BaseModel):
    """Submitted webpage text for the deterministic public lab."""

    model_config = ConfigDict(extra="forbid")

    page: str = Field(min_length=1, max_length=20_000)


class LabReportRequest(BaseModel):
    """Optional visitor feedback about a potential lab bypass."""

    model_config = ConfigDict(extra="forbid")

    page: str = Field(min_length=1, max_length=20_000)
    reason: str = Field(default="User reported a possible bypass", max_length=1_000)
