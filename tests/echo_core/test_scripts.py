"""Governance scripts for the extracted packages."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_import_firewall_passes() -> None:
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "import_firewall.py")],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_self_dev_audit_echo_core_passes() -> None:
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "self_dev_audit.py"),
            "--src",
            "packages/echo-core/echo_core",
            "--package",
            "echo_core",
            "--notices",
            "packages/echo-core/THIRD_PARTY_NOTICES.md",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "自研比例" in result.stdout


def test_release_supply_chain_fails_closed_without_sbom(tmp_path: Path) -> None:
    wheel = tmp_path / "echo_core-3.0.0-py3-none-any.whl"
    wheel.write_bytes(b"wheel")
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "release_supply_chain.py"),
            "--dist",
            str(tmp_path),
            "--require-sbom",
            "--require-provenance",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert "SBOM missing" in result.stderr
    assert "SLSA provenance missing" in result.stderr
