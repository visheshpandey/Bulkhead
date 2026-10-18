"""Environment configuration and SQLite path compatibility helpers."""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path


def setting(name: str, default: str | None = None) -> str | None:
    """Read a setting with the Bulkhead variable taking precedence."""
    bulkhead_name = f"BULKHEAD_{name}"
    legacy_name = f"AIRLOCK_{name}"
    if bulkhead_name in os.environ:
        return os.environ[bulkhead_name]
    if legacy_name in os.environ:
        return os.environ[legacy_name]
    return default


def _migrate_legacy_database(destination: Path, source: Path) -> None:
    """Copy a legacy SQLite database, including any active WAL contents."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    source_connection = sqlite3.connect(source, timeout=30)
    destination_connection = sqlite3.connect(destination, timeout=30)
    try:
        source_connection.backup(destination_connection)
    finally:
        destination_connection.close()
        source_connection.close()


def database_path(explicit: str | None = None) -> str:
    """Resolve the ledger path and migrate the historical default if present."""
    if explicit is not None:
        return explicit

    configured = setting("DB_PATH")
    if configured:
        return configured

    destination = Path("./data/bulkhead.db")
    source = Path("./data/airlock.db")
    if not destination.exists() and source.exists():
        _migrate_legacy_database(destination, source)
    return str(destination)
