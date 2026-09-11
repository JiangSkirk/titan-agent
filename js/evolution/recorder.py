"""TurnOutcomeRecorder — learning signals after a turn, never a second Exec path."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from echo_core.phylogeny import POLARITY_NOTE, POLARITY_TIGHTEN, POLARITY_WIDEN, Phylogeny
from echo_core.taint import USER_TURN


class PhylogenyRecorder:
    """Maps turn outcomes onto tighten / note / widen. Widen stays proposed."""

    def __init__(self, state_dir: Path) -> None:
        self._phy = Phylogeny(Path(state_dir) / "echo-core")

    def record_turn(self, score: Any) -> None:
        owner = str(getattr(score, "owner", "") or "")
        if not owner:
            return
        success = bool(getattr(score, "success", False))
        taint = int(getattr(score, "taint", 0) or 0)
        tools_failed = bool(getattr(score, "tools_failed", False))
        should_have_denied = bool(getattr(score, "should_have_denied", False))
        if tools_failed or should_have_denied:
            self._phy.propose(
                owner,
                POLARITY_TIGHTEN,
                "tighten after tool/deny miss",
                {"kind": "tighten", "success": success},
                taint=USER_TURN,
            )
            return
        preference = str(getattr(score, "user_preference", "") or "")
        if preference:
            if taint != USER_TURN:
                return
            self._phy.propose(
                owner,
                POLARITY_NOTE,
                preference[:200],
                {"kind": "note", "text": preference[:500]},
                taint=taint,
            )
            return
        widen_title = str(getattr(score, "widen_title", "") or "")
        if widen_title:
            if taint != USER_TURN:
                return
            self._phy.propose(
                owner,
                POLARITY_WIDEN,
                widen_title[:200],
                {"kind": "widen", "title": widen_title[:200]},
                taint=taint,
            )

    def record_tool(self, score: Any) -> None:
        self.record_turn(score)
