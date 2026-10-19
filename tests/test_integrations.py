"""Subprocess checks for the copy-ready agent integration examples."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from threading import Thread

import pytest

from app.agents import BulkheadBlocked, BulkheadClient, bulkhead_guard


class _DecisionHandler(BaseHTTPRequestHandler):
    decision = "allow"

    def do_POST(self) -> None:
        length = int(self.headers["Content-Length"])
        self.server.last_payload = json.loads(self.rfile.read(length))  # type: ignore[attr-defined]
        body = {"decision": self.decision, "reason": "local integration test"}
        encoded = json.dumps(body).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, *_args: object) -> None:
        return


def _run_hook(decision: str, payload: dict) -> tuple[subprocess.CompletedProcess[str], HTTPServer]:
    handler = type("DecisionHandler", (_DecisionHandler,), {"decision": decision})
    server = HTTPServer(("127.0.0.1", 0), handler)
    Thread(target=server.serve_forever, daemon=True).start()
    env = os.environ.copy()
    env["BULKHEAD_URL"] = f"http://127.0.0.1:{server.server_port}/api/evaluate"
    result = subprocess.run(
        [sys.executable, "examples/hooks/pretooluse.py"],
        cwd=Path(__file__).parents[1],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        env=env,
        check=False,
    )
    return result, server


def test_hook_command_sends_json_and_returns_nonzero_for_decoyed_action() -> None:
    payload = {"action_type": "read_file", "target": "/workspace/.env", "payload": {}}
    allowed, server = _run_hook("allow", payload)
    try:
        assert allowed.returncode == 0, allowed.stderr
        assert server.last_payload == payload  # type: ignore[attr-defined]
    finally:
        server.shutdown()

    blocked, server = _run_hook("quarantine", payload)
    try:
        assert blocked.returncode == 1
        assert "local integration test" in blocked.stderr
    finally:
        server.shutdown()


def test_python_decorator_blocks_before_tool_invocation() -> None:
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return json.dumps({"decision": "block", "reason": "unsafe"}).encode()

    invoked: list[str] = []
    client = BulkheadClient(opener=lambda *_args, **_kwargs: Response())

    @bulkhead_guard(client, action_type="read_file", target=lambda path: path)
    def read_file(path: str) -> str:
        invoked.append(path)
        return "never reached"

    with pytest.raises(BulkheadBlocked, match="unsafe"):
        read_file("/workspace/.env")
    assert invoked == []


def test_installed_mcp_command_answers_json_rpc() -> None:
    executable = shutil.which("bulkhead-mcp")
    if executable is None:
        pytest.skip("bulkhead-mcp is available after editable package installation")
    messages = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"arguments": {"action_type": "read_file", "target": "/workspace/README.md"}},
        },
    ]
    env = os.environ.copy()
    env["BULKHEAD_DB_PATH"] = ":memory:"
    result = subprocess.run(
        [executable],
        input="\n".join(json.dumps(message) for message in messages) + "\n",
        text=True,
        capture_output=True,
        env=env,
        check=False,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    responses = [json.loads(line) for line in result.stdout.splitlines()]
    assert responses[0]["result"]["serverInfo"]["name"] == "bulkhead"
    assert responses[1]["result"]["tools"][0]["name"] == "bulkhead_evaluate"
    assert json.loads(responses[2]["result"]["content"][0]["text"])["decision"] == "allow"
