"""Skill forge bridge — community birth, never auto-promote to trusted."""

from __future__ import annotations

from pathlib import Path

from echo_core.evolve.forge import ForgeDenied, ForgedSkill, SkillForge


def admit_forged_skill(skills_dir: Path, owner: str, body: str, *, verified_runs: int) -> ForgedSkill:
    return SkillForge(skills_dir).admit(owner, body, verified_runs=verified_runs)


def refuse_auto_promote(skill_id: str, skills_dir: Path) -> None:
    forge = SkillForge(skills_dir)
    try:
        forge.promote(skill_id)
    except ForgeDenied:
        raise
    raise ForgeDenied("forged skills are born community and never auto-promote")
