"""SQLite connection management. WAL + foreign keys set on every connection."""
from __future__ import annotations

import sqlite3
from importlib import resources
from pathlib import Path


def connect(db_path: str) -> sqlite3.Connection:
    """Open a connection with the pragmas bbv relies on.

    foreign_keys is per-connection, so it must be set here rather than in the
    schema script. WAL is persistent but we assert it anyway so a fresh db gets
    it before the first write.
    """
    path = Path(db_path)
    if path.parent and not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(path), isolation_level=None)  # autocommit; we manage txns
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    """Create tables if they do not exist (idempotent)."""
    ddl = resources.files("bbv").joinpath("schema.sql").read_text(encoding="utf-8")
    conn.executescript(ddl)
