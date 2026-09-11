"""Import/collect smoke for Minimal vs Echo same-model scaffold."""

from __future__ import annotations

from echo_core.deepseek_v4_protocol import DEFAULT_EDIT_PROTOCOL, SAME_MODEL_FAMILY

from benchmarks.bench_echo_vs_minimal_same_model import (
    BENCH_ID,
    DEFAULT_MODEL_ID,
    HarnessMode,
    build_fixture,
    dry_run_matrix,
    scaffold_summary,
)


def test_scaffold_importable_and_offline() -> None:
    summary = scaffold_summary()
    assert summary["bench_id"] == BENCH_ID
    assert summary["same_model_family"] == SAME_MODEL_FAMILY
    assert summary["merge_blocker"] is False
    assert summary["network_by_default"] is False
    assert summary["default_model_id"] == DEFAULT_MODEL_ID
    assert set(summary["modes"]) == {"minimal", "echo"}


def test_dry_run_matrix_same_model_lock() -> None:
    cells = dry_run_matrix()
    assert len(cells) == 2
    assert {c["mode"] for c in cells} == {"minimal", "echo"}
    assert all(c["model_id"] == DEFAULT_MODEL_ID for c in cells)
    assert all(c["edit_protocol"] == DEFAULT_EDIT_PROTOCOL.value for c in cells)
    assert all(c["d1_required"] is True for c in cells)
    assert all(c["network"] is False for c in cells)
    minimal = next(c for c in cells if c["mode"] == "minimal")
    echo = next(c for c in cells if c["mode"] == "echo")
    assert minimal["advertised_tools"] == []
    assert "file_edit" in echo["advertised_tools"]
    assert "shell" not in echo["advertised_tools"]


def test_build_fixture_modes() -> None:
    minimal = build_fixture(HarnessMode.MINIMAL)
    echo = build_fixture(HarnessMode.ECHO, allow_exec_tools=True)
    assert minimal.advertised_tools == frozenset()
    assert {"shell", "python"} <= echo.advertised_tools
