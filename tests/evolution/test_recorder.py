"""PhylogenyRecorder must not launder untrusted taint into USER_TURN."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from echo_core.taint import USER_TURN, WEB_CONTENT

from js.evolution.recorder import PhylogenyRecorder


def test_recorder_skips_note_and_widen_without_user_turn(tmp_path: Path) -> None:
    rec = PhylogenyRecorder(tmp_path)
    rec.record_turn(
        SimpleNamespace(
            owner="o",
            success=True,
            taint=0,
            user_preference="remember this",
            widen_title="",
        )
    )
    rec.record_turn(
        SimpleNamespace(
            owner="o",
            success=True,
            taint=WEB_CONTENT,
            user_preference="",
            widen_title="new skill",
        )
    )
    assert rec._phy.heads("o") == []


def test_recorder_notes_only_user_turn(tmp_path: Path) -> None:
    rec = PhylogenyRecorder(tmp_path)
    rec.record_turn(
        SimpleNamespace(
            owner="o",
            success=True,
            taint=USER_TURN,
            user_preference="dark mode",
            widen_title="",
        )
    )
    assert rec._phy.heads("o") == [("dark mode", "note")]
