"""Session state and request limits for the public Bulkhead demo."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from threading import RLock
from time import monotonic
from uuid import UUID, uuid4

from app.audit.ledger import EventLedger
from app.core.policy import PolicyGateway

PUBLIC_SESSION_COOKIE = "bulkhead_session"
PUBLIC_SESSION_TTL = timedelta(hours=2)
PUBLIC_SESSION_REQUEST_LIMIT = 120
PUBLIC_IP_REQUEST_LIMIT = 300
PUBLIC_REQUEST_WINDOW = 60.0
PUBLIC_MAX_CONTENT_BYTES = 20 * 1024
PUBLIC_RATE_LIMITED_PATHS = frozenset({
    ("POST", "/api/evaluate"),
    ("POST", "/api/lab/run"),
    ("POST", "/api/demo"),
    ("POST", "/api/reset-demo"),
})


@dataclass
class DemoSession:
    session_id: str
    gateway: PolicyGateway
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    last_seen: datetime = field(default_factory=lambda: datetime.now(UTC))
    lab_attempts: int = 0
    lab_stopped: int = 0
    lab_bypassed: int = 0
    notes: list[dict[str, str]] = field(default_factory=list)


@dataclass
class LabScore:
    attempts: int = 0
    stopped: int = 0
    bypassed: int = 0
    _lock: RLock = field(default_factory=RLock, repr=False)

    def record(self, *, stopped: bool) -> None:
        with self._lock:
            self.attempts += 1
            if stopped:
                self.stopped += 1
            else:
                self.bypassed += 1

    def reset(self) -> None:
        with self._lock:
            self.attempts = 0
            self.stopped = 0
            self.bypassed = 0

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return {"attempts": self.attempts, "stopped": self.stopped, "bypassed": self.bypassed}


class SessionStore:
    """In-memory, per-visitor gateways for the public sandbox."""

    def __init__(self, ttl: timedelta = PUBLIC_SESSION_TTL) -> None:
        self.ttl = ttl
        self._sessions: dict[str, DemoSession] = {}
        self._lock = RLock()

    @staticmethod
    def valid_id(value: str | None) -> bool:
        if not value:
            return False
        try:
            UUID(value)
        except (ValueError, TypeError, AttributeError):
            return False
        return True

    def get_or_create(self, session_id: str | None = None) -> DemoSession:
        now = datetime.now(UTC)
        with self._lock:
            session = self._sessions.get(session_id or "")
            if session is not None and now - session.last_seen < self.ttl:
                session.last_seen = now
                return session
            identifier = session_id if self.valid_id(session_id) else str(uuid4())
            session = DemoSession(identifier, PolicyGateway(ledger=EventLedger(":memory:")))
            self._sessions[identifier] = session
            return session

    def get(self, session_id: str | None) -> DemoSession | None:
        if not self.valid_id(session_id):
            return None
        now = datetime.now(UTC)
        with self._lock:
            session = self._sessions.get(session_id or "")
            if session is None or now - session.last_seen >= self.ttl:
                return None
            session.last_seen = now
            return session

    def cleanup(self) -> int:
        cutoff = datetime.now(UTC) - self.ttl
        removed: list[DemoSession] = []
        with self._lock:
            for identifier, session in list(self._sessions.items()):
                if session.last_seen < cutoff:
                    removed.append(self._sessions.pop(identifier))
        for session in removed:
            session.gateway.ledger.close()
        return len(removed)

    def reset(self, session_id: str | None) -> DemoSession:
        session = self.get_or_create(session_id)
        session.gateway.reset()
        session.lab_attempts = 0
        session.lab_stopped = 0
        session.lab_bypassed = 0
        session.notes.clear()
        return session

    def count(self) -> int:
        with self._lock:
            return len(self._sessions)


class RequestRateLimiter:
    """Fixed-window limiter with independent session and IP budgets."""

    def __init__(
        self,
        session_limit: int = PUBLIC_SESSION_REQUEST_LIMIT,
        ip_limit: int = PUBLIC_IP_REQUEST_LIMIT,
        window: float = PUBLIC_REQUEST_WINDOW,
    ) -> None:
        self.session_limit = session_limit
        self.ip_limit = ip_limit
        self.window = window
        self._hits: dict[str, tuple[float, int]] = {}
        self._lock = RLock()

    def allow(self, session_key: str, ip_key: str) -> bool:
        now = monotonic()
        with self._lock:
            entries: list[tuple[str, float, int]] = []
            for key, limit in ((session_key, self.session_limit), (ip_key, self.ip_limit)):
                started, count = self._hits.get(key, (now, 0))
                if now - started >= self.window:
                    started, count = now, 0
                if count >= limit:
                    return False
                entries.append((key, started, count))
            for key, started, count in entries:
                self._hits[key] = (started, count + 1)
            return True

    def clear(self) -> None:
        with self._lock:
            self._hits.clear()


sessions = SessionStore()
public_rate_limiter = RequestRateLimiter()
global_lab_score = LabScore()
