"""Coding-agent pre-tool hook: exit non-zero when Bulkhead blocks a call."""

from __future__ import annotations

import json
import os
import sys
from urllib.request import Request, urlopen


def main() -> int:
    payload = json.load(sys.stdin) if not sys.stdin.isatty() else json.loads(sys.argv[1])
    endpoint = os.environ.get("BULKHEAD_URL", "http://127.0.0.1:8000/api/evaluate")
    request = Request(endpoint, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}, method="POST")
    with urlopen(request, timeout=5) as response:
        result = json.load(response)
    if result.get("decision") in {"block", "quarantine"}:
        print(result.get("reason", "Bulkhead rejected the tool call"), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
