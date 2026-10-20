"""Small process-local evaluation rate limiter."""

from __future__ import annotations

import time
from collections import defaultdict, deque
from threading import RLock


class RateLimiter:
    """Sliding-window limiter for non-public agent evaluations."""

    def __init__(self, limit: int = 120, window_seconds: int = 60) -> None:
        """Configure the request count and window duration."""
        self.limit = limit
        self.window_seconds = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = RLock()

    def allow(self, agent_id: str) -> bool:
        """Consume one request when the agent remains below its limit."""
        now = time.monotonic()
        with self._lock:
            hits = self._hits[agent_id]
            while hits and now - hits[0] >= self.window_seconds:
                hits.popleft()
            if len(hits) >= self.limit:
                return False
            hits.append(now)
            return True

    def reset(self) -> None:
        """Clear all agent request windows."""
        with self._lock:
            self._hits.clear()
