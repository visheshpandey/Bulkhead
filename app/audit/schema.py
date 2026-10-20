"""SQLite schema and durable identifier migration for the audit ledger."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable


def create_schema(connection: sqlite3.Connection, number: Callable[[str, str], int]) -> None:
    """Initialize ledger tables and migrate counters from retained row IDs."""
    with connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS immunity_rules (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                last_matched_at TEXT,
                match_count INTEGER NOT NULL DEFAULT 0,
                payload TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_rules_fingerprint
                ON immunity_rules(fingerprint);
            CREATE INDEX IF NOT EXISTS idx_events_timestamp
                ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_incidents_created_at
                ON incidents(created_at);
            CREATE TABLE IF NOT EXISTS honeyworld_captures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT,
                captured_at TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_captures_event_id
                ON honeyworld_captures(event_id);
            CREATE TABLE IF NOT EXISTS id_counters (
                collection TEXT PRIMARY KEY,
                last_value INTEGER NOT NULL
            );
            """
        )
        # Bootstrap counters from retained IDs only for older ledger databases.
        for table in ("events", "incidents", "immunity_rules"):
            prefix = {"events": "evt-", "incidents": "inc-", "immunity_rules": "immune-"}[table]
            ids = connection.execute(f"SELECT id FROM {table}").fetchall()
            highest = max((number(prefix, row[0]) for row in ids), default=0)
            connection.execute(
                "INSERT INTO id_counters(collection, last_value) VALUES (?, ?) "
                "ON CONFLICT(collection) DO UPDATE SET last_value = MAX(last_value, excluded.last_value)",
                (table, highest),
            )
