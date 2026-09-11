"""Owner-private state root. Never writes into js-agent directories."""

from __future__ import annotations

from pathlib import Path


def orin_guard_home() -> Path:
    return Path.home() / ".orin-guard"
