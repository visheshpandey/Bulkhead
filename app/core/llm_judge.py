"""Optional, local-only explainability hook for borderline policy decisions.

The policy engine is deterministic and authoritative.  When explicitly enabled
by ``BULKHEAD_LLM_JUDGE=1``, a caller may provide a model callable for a second
opinion on scores from 30 through 69.  No provider, HTTP client, or network
call is created by this module.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .models import AgentAction, UserIntent


class JudgeResult(BaseModel):
    """The intentionally small model response contract: ``{risk, rationale}``."""

    model_config = ConfigDict(extra="forbid")

    risk: int = Field(ge=0, le=100)
    rationale: str = Field(min_length=1, max_length=20_000)


class LLMJudge:
    """Validate an optional callable model without making external calls."""

    def __init__(self, model: Callable[[dict[str, Any]], Any] | None = None) -> None:
        self.model = model

    def judge(
        self,
        action: AgentAction,
        intent: UserIntent | None = None,
        *,
        deterministic_risk: int | None = None,
    ) -> JudgeResult:
        # PolicyGateway always supplies a deterministic score.  A direct caller
        # may omit it to use this class as a standalone contract adapter; that
        # does not weaken the gateway's borderline-only integration.
        if deterministic_risk is not None and not 30 <= deterministic_risk <= 69:
            return JudgeResult(
                risk=deterministic_risk,
                rationale="Deterministic policy did not require a borderline judge.",
            )
        if self.model is None:
            return JudgeResult(risk=deterministic_risk or 0, rationale="Deterministic policy remains authoritative; no judge configured.")

        prompt = {
            "action": action.model_dump(mode="json"),
            "intent": (intent or UserIntent()).model_dump(mode="json"),
            "risk": deterministic_risk,
        }
        try:
            result = self.model(prompt)
            return result if isinstance(result, JudgeResult) else JudgeResult.model_validate(result)
        except Exception as exc:  # noqa: BLE001 - a model failure must not affect policy
            return JudgeResult(
                risk=deterministic_risk,
                rationale=f"Judge unavailable ({type(exc).__name__}); deterministic policy remains authoritative.",
            )

    evaluate = judge


def judge_action(
    action: AgentAction,
    intent: UserIntent | None = None,
    model: Callable[[dict[str, Any]], Any] | None = None,
    *,
    deterministic_risk: int | None = None,
) -> JudgeResult:
    return LLMJudge(model).judge(action, intent, deterministic_risk=deterministic_risk)
