"""Curator — archive, never delete. Append-only JSONL + tar.gz snapshots."""

from __future__ import annotations

import hashlib
import json
import tarfile
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class CuratorEvent:
    actor: str
    skill_id: str
    before: str
    after: str
    ts: float


class Curator:
    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.archive = self.root / ".archive"
        self.ledger = self.root / "curator.jsonl"
        self.snapshots = self.root / "snapshots"
        self.archive.mkdir(parents=True, exist_ok=True)
        self.snapshots.mkdir(parents=True, exist_ok=True)

    def snapshot(self, skill_path: Path) -> Path:
        ts = int(time.time())
        dest = self.snapshots / f"{skill_path.stem}-{ts}.tar.gz"
        with tarfile.open(dest, "w:gz") as tar:
            tar.add(skill_path, arcname=skill_path.name)
        return dest

    def archive_skill(self, skill_path: Path, *, actor: str) -> Path:
        """Worst case is archive. Never unlink the source of truth."""

        self.snapshot(skill_path)
        dest = self.archive / skill_path.name
        dest.write_bytes(skill_path.read_bytes())
        before = hashlib.sha256(skill_path.read_bytes()).hexdigest()
        after = hashlib.sha256(dest.read_bytes()).hexdigest()
        event = {
            "actor": actor,
            "skill_id": skill_path.stem,
            "before": before,
            "after": after,
            "ts": time.time(),
            "kind": "archive",
        }
        with self.ledger.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, sort_keys=True) + "\n")
        return dest

    def rollback_last(self) -> dict[str, object] | None:
        if not self.ledger.exists():
            return None
        lines = self.ledger.read_text(encoding="utf-8").splitlines()
        if not lines:
            return None
        last = json.loads(lines[-1])
        skill_id = str(last["skill_id"])
        archived = self.archive / f"{skill_id}.skill.json"
        live = self.root / f"{skill_id}.skill.json"
        if archived.exists():
            live.write_bytes(archived.read_bytes())
        return last if isinstance(last, dict) else None


__all__ = ["Curator", "CuratorEvent"]
