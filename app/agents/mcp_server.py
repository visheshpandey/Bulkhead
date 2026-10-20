"""Minimal stdio MCP-style policy server for local agent integrations.

This adapter only evaluates descriptive tool calls. It never invokes a tool.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable, Iterable
from typing import Any

from app.core.models import AgentAction
from app.core.policy import PolicyGateway

MCP_TOOL = {
    "name": "bulkhead_evaluate",
    "description": "Ask Bulkhead whether a simulated agent action is safe to run.",
    "inputSchema": {
        "type": "object",
        "required": ["action_type", "target"],
        "properties": {"action_type": {"type": "string"}, "target": {"type": "string"}},
    },
}


class BulkheadMCPServer:
    """Handle the small JSON-RPC subset needed by coding-agent clients."""

    def __init__(self, evaluate: Callable[[AgentAction], Any]) -> None:
        """Store a policy evaluator for descriptive MCP tool requests."""
        self.evaluate = evaluate

    def handle(self, message: dict[str, Any]) -> dict[str, Any] | None:
        """Handle one supported JSON-RPC request or notification."""
        method = message.get("method")
        request_id = message.get("id")
        if method == "notifications/initialized":
            return None
        if method == "initialize":
            return {"jsonrpc": "2.0", "id": request_id, "result": {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}, "serverInfo": {"name": "bulkhead", "version": "0.1.0"}}}
        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": [MCP_TOOL]}}
        if method == "tools/call":
            arguments = message.get("params", {}).get("arguments", {})
            result = self.evaluate(AgentAction.model_validate(arguments))
            body = {"decision": result.decision.value, "allowed": result.allowed, "reason": result.reason, "event_id": result.event.id}
            return {"jsonrpc": "2.0", "id": request_id, "result": {"content": [{"type": "text", "text": json.dumps(body)}], "isError": not result.allowed}}
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": "Method not found"}}


def serve_stdio(server: BulkheadMCPServer, messages: Iterable[str] = sys.stdin) -> None:
    """Read one JSON-RPC request per line and write one response per line."""
    for line in messages:
        if not line.strip():
            continue
        response = server.handle(json.loads(line))
        if response is not None:
            print(json.dumps(response), flush=True)


def main() -> None:
    """Serve the local policy evaluator over standard input and output."""
    serve_stdio(BulkheadMCPServer(PolicyGateway().evaluate))


if __name__ == "__main__":
    main()
