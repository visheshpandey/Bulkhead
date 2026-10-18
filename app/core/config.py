"""Environment configuration and SQLite path helpers."""

from __future__ import annotations

import os
from pathlib import Path


def setting(name: str, default: str | None = None) -> str | None:
    """Read a Bulkhead setting or return its default."""
    return os.environ.get(f"BULKHEAD_{name}", default)


def public_demo_enabled() -> bool:
    """Return whether the app is running in the public multi-user sandbox."""
    return setting("PUBLIC_DEMO", "0") == "1"


def database_path(explicit: str | None = None) -> str:
    """Resolve the ledger path, defaulting to the Bulkhead database."""
    if explicit is not None:
        return explicit

    configured = setting("DB_PATH")
    if configured:
        return configured

    return str(Path("./data/bulkhead.db"))
