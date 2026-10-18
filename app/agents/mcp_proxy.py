"""A no-I/O adapter for guarding Model Context Protocol tool calls.

The proxy only describes an MCP invocation to Bulkhead.  A caller supplies the
actual local ``invoke`` callback; it is called only after Bulkhead returns an
``allow`` decision.  This keeps the adapter safe to use in examples and tests:
it never opens an MCP connection or executes a submitted tool by itself.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from app.core.models import ActionType, UserIntent

from .client import BulkheadBlocked, BulkheadClient


class MCPProxy:
    """Guard MCP tool invocations before handing them to a supplied callback."""

    def __init__(
        self,
        client: BulkheadClient,
        invoke: Callable[[str, dict[str, Any]], Any] | None = None,
        *,
        action_type: ActionType | str = ActionType.RUN_COMMAND,
    ) -> None:
        self.client = client
        self.invoke = invoke
        self.action_type = action_type

    def evaluate(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        intent: UserIntent | dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return self.client.evaluate(
            action_type=self.action_type,
            target=f"mcp://{tool_name}",
            payload=arguments or {},
            intent=intent,
        )

    check = evaluate

    def call(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        intent: UserIntent | dict[str, Any] | None = None,
        *,
        invoke: Callable[[str, dict[str, Any]], Any] | None = None,
    ) -> Any:
        arguments = arguments or {}
        decision = self.evaluate(tool_name, arguments, intent)
        if decision.get("decision") != "allow":
            raise BulkheadBlocked(decision)
        callback = invoke or self.invoke
        if callback is None:
            return decision
        return callback(tool_name, arguments)

    call_tool = call
    invoke_tool = call


MCPToolProxy = MCPProxy
BulkheadMCPProxy = MCPProxy

__all__ = ["BulkheadMCPProxy", "MCPProxy", "MCPToolProxy"]
