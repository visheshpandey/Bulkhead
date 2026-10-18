"""A deterministic, in-memory quarantine world containing fake secrets only."""

from __future__ import annotations

from typing import Any

from app.core.models import ActionType, AgentAction


class HoneyWorld:
    """Mock tool runtime. It never performs filesystem, network, or shell I/O."""

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self._files: dict[str, str] = {
            "/workspace/README.md": "HoneyWorld demo workspace",
            "/workspace/.env": "FAKE_API_KEY=bulkhead-demo-key\nFAKE_PASSWORD=not-a-real-password\n",
            "/home/agent/.ssh/id_rsa": "-----BEGIN FAKE PRIVATE KEY-----\nDECOY\n-----END FAKE PRIVATE KEY-----",
        }
        self._actions: list[dict[str, Any]] = []

    def execute(self, action: AgentAction) -> dict[str, Any]:
        """Simulate a quarantined action with fake data and return an observable receipt."""
        result: dict[str, Any] = {
            "simulated": True,
            "action_type": action.action_type,
            "target": action.target,
            "network_called": False,
            "shell_called": False,
        }
        if action.action_type == ActionType.READ_FILE:
            result["output"] = self._files.get(action.target, "[HoneyWorld] decoy file not found")
        elif action.action_type == ActionType.WRITE_FILE:
            self._files[action.target] = str(action.payload.get("content", action.content or ""))
            result["output"] = "[HoneyWorld] write captured in sandbox"
        elif action.action_type == ActionType.RUN_COMMAND:
            result["shell_called"] = False
            result["output"] = "[HoneyWorld] command captured; no process executed"
        elif action.action_type in {ActionType.HTTP_REQUEST, ActionType.GITHUB_ACTION}:
            result["output"] = "[HoneyWorld] external operation captured; no network called"
        self._actions.append(result)
        return result

    def state(self) -> dict[str, Any]:
        return {
            "active": True,
            "fake_secret_paths": ["/workspace/.env", "/home/agent/.ssh/id_rsa"],
            "captured_actions": list(self._actions),
        }
