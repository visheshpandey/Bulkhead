from app.agents.gateway_client import AirlockGatewayClient, GatewayClient
from app.agents.mcp_proxy import MCPProxy
from app.core.models import Decision


def test_gateway_client_compatibility_names_share_implementation() -> None:
    assert GatewayClient is AirlockGatewayClient


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
