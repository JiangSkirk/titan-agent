"""Stage B (v0.3.3.1) product defaults: orin.enabled ∧ orin.enforce.

Hard gate dated 2026-10-01 — both defaults must stay true in the same PR.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from echo_core.effect_authority import BootDenied, require_boot_ok

from js.config import JSSettings, OrinConfig
from js.echo.effect_authority_host import build_host_effect_authority
from js.orin.stage_c import product_enforce_enabled

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_stage_b_orin_enabled_default_true() -> None:
    """Hard gate 2026-10-01: product defaults orin.enabled ∧ orin.enforce are true."""

    assert OrinConfig.model_fields["enabled"].default is True
    assert OrinConfig.model_fields["enforce"].default is True
    config = OrinConfig()
    assert config.enabled is True
    assert config.enforce is True
    settings = JSSettings(
        workspace=Path("/tmp/js-stage-b-ws"),
        state_dir=Path("/tmp/js-stage-b-st"),
        providers=[],
    )
    assert settings.orin.enabled is True
    assert settings.orin.enforce is True
    # Bare D1 enforce is not Stage C product-route enforce.
    assert product_enforce_enabled(config) is False


def test_enabled_without_enforce_still_boot_fails_only(tmp_path: Path) -> None:
    """Illegal combo fails at boot (EffectAuthority), not settings parse."""

    config = OrinConfig(enabled=True, enforce=False)
    assert config.enabled is True
    assert config.enforce is False
    with pytest.raises(BootDenied, match="enabled without enforce"):
        require_boot_ok(enabled=config.enabled, enforce=config.enforce)
    with pytest.raises(BootDenied, match="enabled without enforce"):
        build_host_effect_authority(
            state_dir=tmp_path,
            enabled=True,
            enforce=False,
        )


def test_no_second_turn_loop_in_membrane() -> None:
    """Membrane / D1 gate must not grow a parallel run_echo_turn surface."""

    targets = (
        REPO_ROOT / "js" / "orind" / "membrane.py",
        REPO_ROOT / "packages" / "echo-core" / "echo_core" / "effect_authority.py",
    )
    offenders: list[str] = []
    for path in targets:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name == "run_echo_turn":
                    offenders.append(f"{path.relative_to(REPO_ROOT)}:{node.name}")
            if isinstance(node, ast.Call):
                func = node.func
                name = getattr(func, "id", None) or getattr(func, "attr", None)
                if name == "run_echo_turn":
                    offenders.append(f"{path.relative_to(REPO_ROOT)}:call")
        assert "run_echo_turn" not in source
    assert offenders == []
