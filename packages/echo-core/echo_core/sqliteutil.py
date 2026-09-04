"""SQLite file mode helper. Product DBs must be owner-only (0600)."""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any


def lock_sqlite_mode(path: Path) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


@contextmanager
def connect_private(path: Path, *, row_factory: Any = None) -> Iterator[sqlite3.Connection]:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    try:
        lock_sqlite_mode(path)
        if row_factory is not None:
            conn.row_factory = row_factory
        yield conn
    finally:
        conn.close()
