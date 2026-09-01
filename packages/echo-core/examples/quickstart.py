#!/usr/bin/env python3
"""Standalone echo-core quickstart. No js-agent required."""

from __future__ import annotations

from pathlib import Path

from echo_core import ECHO_3_ARCHITECTURE, NullGuardian, Phylogeny
from echo_core.taint import USER_TURN


def main() -> None:
    print("architecture", ECHO_3_ARCHITECTURE)
    guardian = NullGuardian()
    try:
        guardian.stamp(
            owner="demo",
            session="s",
            run="r",
            effect_class="tool",
            grants=frozenset(),
            budget=1,
        )
    except Exception as exc:
        print("null guardian fail-closed:", type(exc).__name__)
    phy = Phylogeny(Path.home() / ".echo-core" / "demo")
    node = phy.propose(
        "demo-owner",
        "tighten",
        "deny a previously missed path",
        {"kind": "tighten"},
        taint=USER_TURN,
    )
    print("tighten auto-committed:", node.status)


if __name__ == "__main__":
    main()
