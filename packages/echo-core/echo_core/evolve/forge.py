"""L3 skill forge — community birth, never auto-promote to trusted."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path


class TrustBirth(StrEnum):
    COMMUNITY = "community"


class ForgeDenied(PermissionError):
    """Skill failed the admit pipeline."""


@dataclass(frozen=True, slots=True)
class ForgedSkill:
    skill_id: str
    owner: str
    body_hash: str
    trust: str
    uses: int


class SkillForge:
    def __init__(self, skills_dir: Path) -> None:
        self.skills_dir = Path(skills_dir)
        self.skills_dir.mkdir(parents=True, exist_ok=True)
        self._index: dict[str, ForgedSkill] = {}

    def admit(self, owner: str, body: str, *, verified_runs: int) -> ForgedSkill:
        if verified_runs < 3:
            raise ForgeDenied("skill must pass at least 3 related tasks")
        digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
        skill_id = digest[:16]
        record = ForgedSkill(skill_id, owner, digest, TrustBirth.COMMUNITY.value, 0)
        path = self.skills_dir / f"{skill_id}.skill.json"
        path.write_text(
            json.dumps(
                {
                    "skill_id": skill_id,
                    "owner": owner,
                    "body_hash": digest,
                    "trust": record.trust,
                },
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        sig = self.skills_dir / f"{skill_id}.hash"
        sig.write_text(digest + "\n", encoding="utf-8")
        self._index[skill_id] = record
        return record

    def promote(self, skill_id: str) -> None:
        raise ForgeDenied("forged skills are born community and never auto-promote")

    def first_seen_remaining(self, skill_id: str, *, isolation_uses: int = 10) -> int:
        record = self._index.get(skill_id)
        if record is None:
            raise ForgeDenied("unknown skill")
        return max(0, isolation_uses - record.uses)


__all__ = ["ForgeDenied", "ForgedSkill", "SkillForge", "TrustBirth"]
