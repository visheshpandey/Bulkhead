from app.agents.gateway_client import BulkheadGatewayClient, GatewayClient
from app.agents.mcp_proxy import MCPProxy
from app.agents.mcp_server import BulkheadMCPServer
from app.core.models import ActionType, AgentAction, Decision


def test_gateway_client_names_share_implementation() -> None:
    assert GatewayClient is BulkheadGatewayClient


class _StubClient:
    def __init__(self, decision: str = "allow") -> None:
        self.decision = decision
        self.calls: list[tuple[str, dict]] = []

    def evaluate(self, **kwargs):
        self.calls.append(kwargs)
        return {"decision": self.decision, "reason": "stub"}


def test_mcp_proxy_guards_before_invoke() -> None:
    client = _StubClient()
    invoked: list[tuple[str, dict]] = []
    proxy = MCPProxy(client, invoke=lambda name, args: invoked.append((name, args)))
    proxy.call("read_page", {"url": "synthetic://page"})
    assert invoked == [("read_page", {"url": "synthetic://page"})]
    assert client.calls[0]["target"] == "mcp://read_page"


def test_mcp_proxy_does_not_invoke_blocked_call() -> None:
    client = _StubClient(Decision.BLOCK.value)
    invoked: list[str] = []
    proxy = MCPProxy(client, invoke=lambda name, args: invoked.append(name))
    try:
        proxy.call("dangerous_tool", {})
    except RuntimeError as error:
        assert "stub" in str(error)
    else:
        raise AssertionError("blocked MCP call was invoked")
    assert invoked == []


def test_mcp_server_evaluates_tool_call_without_invoking_tools() -> None:
    evaluated: list[AgentAction] = []

    def evaluate(action: AgentAction):
        evaluated.append(action)
        return type(
            "Result",
            (),
            {"decision": Decision.ALLOW, "allowed": True, "reason": "safe", "event": type("Event", (), {"id": "evt-1"})()},
        )()

    response = BulkheadMCPServer(evaluate).handle(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"arguments": {"action_type": ActionType.READ_FILE, "target": "/workspace/README.md"}},
        }
    )
    assert evaluated[0].target == "/workspace/README.md"
    assert response["result"]["isError"] is False
