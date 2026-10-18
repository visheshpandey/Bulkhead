"""Small standard-library Bulkhead HTTP client for agent integrations."""

from __future__ import annotations

import json
from collections.abc import Callable
from functools import wraps
from http.client import HTTPResponse
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from app.core.models import ActionType, AgentAction, UserIntent


class BulkheadBlocked(RuntimeError):
    """Raised when Bulkhead refuses or quarantines a tool call."""

    def __init__(self, decision: dict[str, Any]) -> None:
        self.decision = decision
        super().__init__(decision.get("reason", "Bulkhead blocked the tool call"))


class BulkheadClient:
    """Submit tool-call descriptions to Bulkhead before executing them."""

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8000",
        *,
        api_key: str | None = None,
        agent_id: str = "demo-agent",
        timeout: float = 10.0,
        opener: Callable[..., HTTPResponse] = urlopen,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.agent_id = agent_id
        self.timeout = timeout
        self._opener = opener

    def evaluate(
        self,
        action: AgentAction | dict[str, Any] | None = None,
        intent: UserIntent | dict[str, Any] | None = None,
        *,
        action_type: ActionType | str | None = None,
        type: ActionType | str | None = None,
        target: str = "",
        payload: dict[str, Any] | None = None,
        content: str | None = None,
        metadata: dict[str, Any] | None = None,
        run_honeyworld: bool = True,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"run_honeyworld": run_honeyworld}
        if action is not None:
            body["action"] = action.model_dump(mode="json") if isinstance(action, AgentAction) else action
        else:
            body.update(
                {
                    "action_type": action_type or type,
                    "target": target,
                    "payload": payload or {},
                    "content": content,
                    "metadata": metadata or {},
                    "agent_id": self.agent_id,
                }
            )
        if intent is not None:
            body["intent"] = intent.model_dump(mode="json") if isinstance(intent, UserIntent) else intent
        return self._post("/api/evaluate", body)

    def guard(
        self,
        action: AgentAction | dict[str, Any],
        intent: UserIntent | dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Evaluate a complete action and raise for BLOCK or QUARANTINE."""
        result = self.evaluate(action=action, intent=intent)
        if result.get("decision") in {"block", "quarantine"}:
            raise BulkheadBlocked(result)
        return result

    # A concise alias is convenient in tool wrappers and keeps integrations readable.
    check = evaluate
    protect = evaluate

    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        headers = {"Content-Type": "application/json", "X-Agent-Id": self.agent_id}
        if self.api_key:
            headers["X-Bulkhead-Key"] = self.api_key
        request = Request(
            f"{self.base_url}{path}",
            data=json.dumps(body).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with self._opener(request, timeout=self.timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Bulkhead rejected request ({exc.code}): {detail}") from exc


def bulkhead_guard(
    client: BulkheadClient,
    *,
    action_type: ActionType | str,
    target: str | Callable[..., str] = "",
    content: str | Callable[..., str] | None = None,
    intent: UserIntent | dict[str, Any] | None = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorate a tool function so Bulkhead approves it before invocation."""

    def decorate(function: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(function)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            resolved_target = target(*args, **kwargs) if callable(target) else target
            resolved_content = content(*args, **kwargs) if callable(content) else content
            result = client.evaluate(
                action_type=action_type,
                target=resolved_target,
                content=resolved_content,
                intent=intent,
            )
            if not result.get("allowed", result.get("decision") == "allow"):
                raise PermissionError(result.get("reason", "Bulkhead blocked the tool call"))
            return function(*args, **kwargs)

        return wrapped

    return decorate


def guard_tool(
    client: BulkheadClient, action_type: ActionType | str, *, target: str = ""
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Convenience helper for the common fixed-target tool case."""
    return bulkhead_guard(client, action_type=action_type, target=target)


guard = bulkhead_guard
