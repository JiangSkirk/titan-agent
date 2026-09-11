"""Minimal vs Echo same-model scaffold (DeepSeek V4 lock).

Offline / nightly fixture path for harness comparison. This module is
**importable and collectable by CI** but is not a silent merge blocker:
live provider calls stay opt-in behind ``--live`` (not enabled here).

Both modes lock the same DeepSeek V4 family. Echo mode still executes tools
only through the D1 EffectAuthority chain; Minimal mode disables tool
advertisement (CHAT_ONLY-style) without reviving ambient exec.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final

from echo_core.deepseek_v4_protocol import (
    DEEPSEEK_V4_MODEL_IDS,
    DEFAULT_EDIT_PROTOCOL,
    SAME_MODEL_FAMILY,
    default_tool_surface,
    protocol_manifest,
    require_deepseek_v4_model,
    require_default_edit_protocol,
)

BENCH_ID: Final[str] = "bench_echo_vs_minimal_same_model"
DEFAULT_MODEL_ID: Final[str] = "deepseek-v4-flash"
DOC_PATH: Final[str] = "docs/echo/DEEPSEEK_V4_TOOL_EDIT_PROTOCOL.md"


class HarnessMode(StrEnum):
    MINIMAL = "minimal"
    ECHO = "echo"


@dataclass(frozen=True, slots=True)
class SameModelFixture:
    """Dry-run fixture describing one Minimal-vs-Echo comparison cell."""

    bench_id: str
    mode: HarnessMode
    model_id: str
    edit_protocol: str
    advertised_tools: frozenset[str]
    d1_required: bool
    network: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "bench_id": self.bench_id,
            "mode": self.mode.value,
            "model_id": self.model_id,
            "edit_protocol": self.edit_protocol,
            "advertised_tools": sorted(self.advertised_tools),
            "d1_required": self.d1_required,
            "network": self.network,
            "same_model_family": SAME_MODEL_FAMILY,
        }


def build_fixture(
    mode: HarnessMode,
    *,
    model_id: str = DEFAULT_MODEL_ID,
    allow_exec_tools: bool = False,
) -> SameModelFixture:
    """Build an offline fixture for ``mode`` on the locked V4 model."""

    locked = require_deepseek_v4_model(model_id)
    protocol = require_default_edit_protocol(DEFAULT_EDIT_PROTOCOL)
    if mode is HarnessMode.MINIMAL:
        # Minimal: no tool advertisement; still no ambient escape.
        tools: frozenset[str] = frozenset()
        d1_required = True  # CHAT_ONLY / model path still fail-closed under D1
    else:
        tools = default_tool_surface(allow_exec_tools=allow_exec_tools)
        d1_required = True
    return SameModelFixture(
        bench_id=BENCH_ID,
        mode=mode,
        model_id=locked,
        edit_protocol=protocol.value,
        advertised_tools=tools,
        d1_required=d1_required,
        network=False,
    )


def dry_run_matrix(*, model_id: str = DEFAULT_MODEL_ID) -> list[dict[str, Any]]:
    """Return Minimal + Echo dry-run cells for CI import/collect."""

    return [
        build_fixture(HarnessMode.MINIMAL, model_id=model_id).to_dict(),
        build_fixture(HarnessMode.ECHO, model_id=model_id).to_dict(),
    ]


def scaffold_summary() -> dict[str, Any]:
    """Machine-readable summary for docs and unit smoke."""

    return {
        "bench_id": BENCH_ID,
        "doc": DOC_PATH,
        "same_model_family": SAME_MODEL_FAMILY,
        "locked_models": sorted(DEEPSEEK_V4_MODEL_IDS),
        "default_model_id": DEFAULT_MODEL_ID,
        "modes": [HarnessMode.MINIMAL.value, HarnessMode.ECHO.value],
        "merge_blocker": False,
        "network_by_default": False,
        "protocol": protocol_manifest(),
        "dry_run": dry_run_matrix(),
    }


def main() -> None:
    import json
    import sys

    print(json.dumps(scaffold_summary(), indent=2, sort_keys=True))
    sys.exit(0)


if __name__ == "__main__":
    main()
