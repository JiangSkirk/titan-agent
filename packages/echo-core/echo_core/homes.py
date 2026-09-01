"""Owner-private state root for echo-core. Never writes into js-agent directories."""

from __future__ import annotations

from pathlib import Path


def echo_core_home() -> Path:
    return Path.home() / ".echo-core"
