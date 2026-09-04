"""L2 experience bank — three-stage consolidation + six-signal score.

Untrusted taint never enters the Deep write prompt (structural exclusion).
"""

from __future__ import annotations

import hashlib
import math
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

from echo_core.sqliteutil import lock_sqlite_mode
from echo_core.taint import USER_TURN, WEB_CONTENT

UNTRUSTED = WEB_CONTENT


@dataclass(frozen=True, slots=True)
class Experience:
    exp_id: str
    owner: str
    pattern_text: str
    action_hint: str
    success_count: int
    fail_count: int
    taint: int
    score: float
    created_at: float
    last_hit: float


def six_signal_score(
    *,
    relevance: float,
    frequency: float,
    query_diversity: float,
    recency: float,
    consolidation: float,
    conceptual_richness: float,
) -> float:
    return (
        0.30 * relevance
        + 0.24 * frequency
        + 0.15 * query_diversity
        + 0.15 * recency
        + 0.10 * consolidation
        + 0.06 * conceptual_richness
    )


def ebbinghaus_retention(age_seconds: float, strength: float) -> float:
    """R = e^(-t/S). Strength grows with successful recall."""

    if strength <= 0:
        return 0.0
    return math.exp(-max(0.0, age_seconds) / strength)


class ExperienceBank:
    def __init__(self, state_dir: Path) -> None:
        self.db_path = Path(state_dir) / "experience_bank.db"
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS experience (
                    exp_id TEXT PRIMARY KEY,
                    owner TEXT NOT NULL,
                    pattern_text TEXT NOT NULL,
                    action_hint TEXT NOT NULL,
                    success_count INTEGER NOT NULL,
                    fail_count INTEGER NOT NULL,
                    taint INTEGER NOT NULL,
                    score REAL NOT NULL,
                    created_at REAL NOT NULL,
                    last_hit REAL NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE VIRTUAL TABLE IF NOT EXISTS experience_fts USING fts5(pattern_text, action_hint)"
            )
            conn.commit()
        lock_sqlite_mode(self.db_path)

    def consolidate_deep(
        self,
        owner: str,
        pattern_text: str,
        action_hint: str,
        *,
        taint: int,
        signals: dict[str, float],
        min_score: float = 0.55,
        min_recall: int = 1,
        min_unique_queries: int = 1,
    ) -> Experience | None:
        if taint & UNTRUSTED:
            return None
        if taint != USER_TURN:
            return None
        score = six_signal_score(
            relevance=float(signals.get("relevance", 0)),
            frequency=float(signals.get("frequency", 0)),
            query_diversity=float(signals.get("query_diversity", 0)),
            recency=float(signals.get("recency", 0)),
            consolidation=float(signals.get("consolidation", 0)),
            conceptual_richness=float(signals.get("conceptual_richness", 0)),
        )
        if (
            score < min_score
            or int(signals.get("recall_count", 0)) < min_recall
            or int(signals.get("unique_queries", 0)) < min_unique_queries
        ):
            return None
        now = time.time()
        exp_id = hashlib.sha256(f"{owner}:{pattern_text}".encode()).hexdigest()
        exp = Experience(
            exp_id,
            owner,
            pattern_text,
            action_hint,
            1,
            0,
            taint,
            score,
            now,
            now,
        )
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO experience
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    exp.exp_id,
                    exp.owner,
                    exp.pattern_text,
                    exp.action_hint,
                    exp.success_count,
                    exp.fail_count,
                    exp.taint,
                    exp.score,
                    exp.created_at,
                    exp.last_hit,
                ),
            )
            conn.execute(
                "INSERT INTO experience_fts(pattern_text, action_hint) VALUES (?, ?)",
                (pattern_text, action_hint),
            )
            conn.commit()
        return exp

    def search(self, owner: str, query: str, *, k: int = 5) -> list[Experience]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """
                SELECT e.* FROM experience e
                JOIN experience_fts f ON e.pattern_text = f.pattern_text
                WHERE e.owner = ? AND experience_fts MATCH ?
                LIMIT ?
                """,
                (owner, query, k),
            ).fetchall()
        return [
            Experience(
                str(r["exp_id"]),
                str(r["owner"]),
                str(r["pattern_text"]),
                str(r["action_hint"]),
                int(r["success_count"]),
                int(r["fail_count"]),
                int(r["taint"]),
                float(r["score"]),
                float(r["created_at"]),
                float(r["last_hit"]),
            )
            for r in rows
        ]


__all__ = [
    "Experience",
    "ExperienceBank",
    "ebbinghaus_retention",
    "six_signal_score",
]
