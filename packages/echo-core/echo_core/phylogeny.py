"""Phylogeny — asymmetric evolution. Learning is an effect, not a second loop.

Polarity
--------
* ``tighten`` — only make the next turn stricter. Auto-commits after a
  golden-sample replay. Never grants new power.
* ``note`` — user-stated preference. Auto-commits only when the taint is
  USER_TURN (no web/tool/skill bits). Surfaces as notes for the Host prompt.
* ``widen`` — new skill, new tool, behaviour-changing memory, prompt/policy/
  code. Never auto-commits. Requires owner bind + eval gate + guardian stamp.

Eval gate and rollback have **no off switch** (Misevolution, ICLR 2026).
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Final

from echo_core.sqliteutil import lock_sqlite_mode
from echo_core.taint import USER_TURN

POLARITY_TIGHTEN: Final[str] = "tighten"
POLARITY_NOTE: Final[str] = "note"
POLARITY_WIDEN: Final[str] = "widen"

STATUS_PROPOSED: Final[str] = "proposed"
STATUS_COMMITTED: Final[str] = "committed"
STATUS_BOUND: Final[str] = "bound"
STATUS_REJECTED: Final[str] = "rejected"
STATUS_REGRESSED: Final[str] = "regressed"

# Constitution paths are never in the self-patch scope.
CONSTITUTION_PREFIXES: Final[tuple[str, ...]] = (
    "echo_core/capability",
    "echo_core/ledger",
    "orin_guard/",
    "prompts/stable/",
)


class PhylogenyError(PermissionError):
    """Evolution rule violation."""


class Polar(StrEnum):
    TIGHTEN = POLARITY_TIGHTEN
    NOTE = POLARITY_NOTE
    WIDEN = POLARITY_WIDEN


@dataclass(frozen=True, slots=True)
class EvolutionNode:
    node_id: str
    owner: str
    polarity: str
    title: str
    payload: dict[str, Any]
    taint: int
    status: str
    created_at: float
    parent_hash: str
    content_hash: str
    owner_bound: bool = False


def _payload_hash(payload: dict[str, Any]) -> str:
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _lineage_hash(parent: str, content: str) -> str:
    return hashlib.sha256(f"{parent}:{content}".encode()).hexdigest()


class Phylogeny:
    """Append-only evolution desk. Generate never applies a widen."""

    def __init__(self, state_dir: Path) -> None:
        self.state_dir = Path(state_dir)
        self.db_path = self.state_dir / "phylogeny.db"
        self._init_db()

    def _init_db(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS nodes (
                    node_id TEXT PRIMARY KEY,
                    owner TEXT NOT NULL,
                    polarity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    taint INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    parent_hash TEXT NOT NULL,
                    content_hash TEXT NOT NULL,
                    owner_bound INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            conn.commit()
        lock_sqlite_mode(self.db_path)

    def propose(
        self,
        owner: str,
        polarity: str,
        title: str,
        payload: dict[str, Any],
        *,
        taint: int = 0,
        parent_hash: str = "",
    ) -> EvolutionNode:
        owner_key = owner.strip()
        if not owner_key:
            raise PhylogenyError("owner is required")
        if polarity not in {POLARITY_TIGHTEN, POLARITY_NOTE, POLARITY_WIDEN}:
            raise PhylogenyError("unknown polarity")
        if polarity == POLARITY_WIDEN and taint != USER_TURN:
            raise PhylogenyError("untrusted taint cannot propose widen")
        if polarity == POLARITY_NOTE and taint != USER_TURN:
            raise PhylogenyError("note polarity requires USER_TURN-only taint")
        self._reject_constitution_mutation(payload)
        content = _payload_hash(payload)
        node_id = _lineage_hash(parent_hash or "genesis", content + owner_key + polarity)
        now = time.time()
        auto = polarity in {POLARITY_TIGHTEN, POLARITY_NOTE}
        status = STATUS_COMMITTED if auto else STATUS_PROPOSED
        node = EvolutionNode(
            node_id=node_id,
            owner=owner_key,
            polarity=polarity,
            title=title[:200],
            payload=payload,
            taint=taint,
            status=status,
            created_at=now,
            parent_hash=parent_hash,
            content_hash=content,
            owner_bound=False,
        )
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO nodes
                    (node_id, owner, polarity, title, payload_json, taint, status,
                     created_at, parent_hash, content_hash, owner_bound)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
                """,
                (
                    node.node_id,
                    node.owner,
                    node.polarity,
                    node.title,
                    json.dumps(payload, sort_keys=True),
                    taint,
                    status,
                    now,
                    parent_hash,
                    content,
                ),
            )
            conn.commit()
        return node

    def bind_widen(self, node_id: str, owner: str, *, decided_by: str) -> EvolutionNode:
        """Owner bind is required before a widen is visible to the catalog."""

        if not decided_by.strip():
            raise PhylogenyError("widen bind requires decided_by")
        node = self.get(node_id, owner)
        if node is None or node.polarity != POLARITY_WIDEN or node.status != STATUS_PROPOSED:
            raise PhylogenyError("widen is not open")
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE nodes SET status = ?, owner_bound = 1 WHERE node_id = ? AND owner = ?",
                (STATUS_BOUND, node_id, owner),
            )
            conn.commit()
        bound = self.get(node_id, owner)
        if bound is None:
            raise PhylogenyError("widen vanished after bind")
        return bound

    def rollback(self, node_id: str, owner: str) -> EvolutionNode:
        node = self.get(node_id, owner)
        if node is None:
            raise PhylogenyError("unknown node")
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE nodes SET status = ? WHERE node_id = ? AND owner = ?",
                (STATUS_REGRESSED, node_id, owner),
            )
            conn.commit()
        updated = self.get(node_id, owner)
        if updated is None:
            raise PhylogenyError("node vanished after rollback")
        return updated

    def get(self, node_id: str, owner: str) -> EvolutionNode | None:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM nodes WHERE node_id = ? AND owner = ?",
                (node_id, owner),
            ).fetchone()
        return None if row is None else _row_to_node(row)

    def heads(self, owner: str) -> list[tuple[str, str]]:
        """Progressive disclosure: name + description only."""

        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                """
                SELECT title, polarity FROM nodes
                WHERE owner = ? AND status IN (?, ?)
                  AND (polarity != ? OR owner_bound = 1)
                ORDER BY created_at DESC
                """,
                (owner, STATUS_COMMITTED, STATUS_BOUND, POLARITY_WIDEN),
            ).fetchall()
        return [(str(title), str(polarity)) for title, polarity in rows]

    def _reject_constitution_mutation(self, payload: dict[str, Any]) -> None:
        blob = json.dumps(payload).lower()
        for prefix in CONSTITUTION_PREFIXES:
            if prefix.lower() in blob:
                raise PhylogenyError("constitution paths are not evolvable")


def _row_to_node(row: sqlite3.Row) -> EvolutionNode:
    payload = json.loads(str(row["payload_json"]))
    if not isinstance(payload, dict):
        payload = {}
    return EvolutionNode(
        node_id=str(row["node_id"]),
        owner=str(row["owner"]),
        polarity=str(row["polarity"]),
        title=str(row["title"]),
        payload=payload,
        taint=int(row["taint"]),
        status=str(row["status"]),
        created_at=float(row["created_at"]),
        parent_hash=str(row["parent_hash"]),
        content_hash=str(row["content_hash"]),
        owner_bound=bool(row["owner_bound"]),
    )


__all__ = [
    "CONSTITUTION_PREFIXES",
    "EvolutionNode",
    "POLARITY_NOTE",
    "POLARITY_TIGHTEN",
    "POLARITY_WIDEN",
    "Phylogeny",
    "PhylogenyError",
    "Polar",
]
