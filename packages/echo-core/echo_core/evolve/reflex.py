"""L1 reflex staging — candidates land as proposed, never applied."""

from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from echo_core.sqliteutil import lock_sqlite_mode

Kind = Literal["reflex", "memory", "skill_patch"]


@dataclass(frozen=True, slots=True)
class StagingItem:
    item_id: int
    owner: str
    kind: str
    body: str
    status: str
    created_at: float


class ReflexStaging:
    def __init__(self, state_dir: Path) -> None:
        self.db_path = Path(state_dir) / "evolution_staging.db"
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS staging (
                    item_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    owner TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    body TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at REAL NOT NULL
                )
                """
            )
            conn.commit()
        lock_sqlite_mode(self.db_path)

    def propose(self, owner: str, kind: Kind, body: str) -> StagingItem:
        now = time.time()
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute(
                "INSERT INTO staging(owner, kind, body, status, created_at) VALUES (?, ?, ?, ?, ?)",
                (owner, kind, body, "proposed", now),
            )
            conn.commit()
            item_id = int(cur.lastrowid or 0)
        return StagingItem(item_id, owner, kind, body, "proposed", now)


__all__ = ["ReflexStaging", "StagingItem"]
