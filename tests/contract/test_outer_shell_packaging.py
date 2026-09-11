"""Outer-shell packaging cut #3 boundary contracts.

Docs/packaging surface only — does not execute desktop builds or touch
packages/orin-* / GateKernel.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_outer_shell_release_doc_and_tag_semantics() -> None:
    doc = (REPO_ROOT / "docs" / "release" / "JS_AGENT_OUTER.md").read_text(
        encoding="utf-8"
    )
    lowered = doc.lower()
    assert "js-agent-outer-2026.09" in doc
    assert "cut #3" in lowered
    assert "republish" in lowered
    assert "0.1.0" in doc
    assert "0.1.5" in doc


def test_outer_shell_paths_exist_and_orin_packages_untouched_by_doc() -> None:
    for rel in (
        "desktop/build_driver.py",
        "desktop/sidecar/host.py",
        "desktop/src-tauri/tauri.conf.json",
        "js/web/local_host.py",
        "scripts/release_smoke.py",
        "scripts/verify_installed_artifact.py",
        "scripts/run_desktop_build_gate.py",
        "LICENSE",
        "docs/release/JS_AGENT_OUTER.md",
        "docs/orin-oss-boundary.md",
    ):
        assert (REPO_ROOT / rel).is_file(), rel

    boundary = (REPO_ROOT / "docs" / "orin-oss-boundary.md").read_text(encoding="utf-8")
    assert "Outer shell" in boundary
    assert "js-agent-outer-2026.09" in boundary


def test_host_sdist_explicitly_includes_gitignore_and_license() -> None:
    data = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    include = data["tool"]["hatch"]["build"]["targets"]["sdist"]["include"]
    assert "/.gitignore" in include
    assert "/LICENSE" in include
    # Desktop / kernel trees stay out of Host sdist include globs.
    joined = "\n".join(include)
    assert "desktop" not in joined
    assert "packages/" not in joined
    assert "orin" not in joined


def test_version_dual_track_host_vs_desktop() -> None:
    project = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert project["project"]["version"] == "0.1.5"

    driver = (REPO_ROOT / "desktop" / "build_driver.py").read_text(encoding="utf-8")
    assert 'PRODUCT_VERSION = "0.1.0"' in driver

    tauri = tomllib.loads(
        (REPO_ROOT / "desktop" / "src-tauri" / "Cargo.toml").read_text(encoding="utf-8")
    )
    assert tauri["package"]["version"] == "0.1.0"

    license_text = (REPO_ROOT / "LICENSE").read_text(encoding="utf-8")
    assert "Copyright (c) 2026 JS Team" in license_text


def test_sidecar_freeze_contract_requires_full_kernel_triad() -> None:
    """Architecture gate: freeze must collect echo_core + orin_proto + orin_guard.

    Freezing only ``echo_core`` (omitting Orin peers) is a reject. Host must
    not edit ``packages/orin-*`` sources — only consume them in the freeze.
    """
    from desktop import build_driver

    assert build_driver.SIDECAR_KERNEL_TRIAD_MODULES == (
        "echo_core",
        "orin_proto",
        "orin_guard",
    )
    assert [name for _rel, name in build_driver.SIDECAR_KERNEL_PACKAGE_ROOTS] == [
        "echo_core",
        "orin_proto",
        "orin_guard",
    ]

    flags = build_driver.sidecar_kernel_pyinstaller_flags()
    hidden = {
        flags[i + 1] for i, part in enumerate(flags) if part == "--hidden-import"
    }
    collected = {
        flags[i + 1] for i, part in enumerate(flags) if part == "--collect-submodules"
    }
    triad = set(build_driver.SIDECAR_KERNEL_TRIAD_MODULES)
    assert triad <= hidden, f"hidden-import missing triad peers: {triad - hidden}"
    assert triad <= collected, f"collect-submodules missing triad peers: {triad - collected}"
    # echo_core-only freeze must remain a reject.
    assert {"orin_proto", "orin_guard"} <= hidden
    assert {"orin_proto", "orin_guard"} <= collected
    assert "echo_core.primitives" in hidden

    driver_src = (REPO_ROOT / "desktop" / "build_driver.py").read_text(encoding="utf-8")
    assert "sidecar_kernel_pyinstaller_flags()" in driver_src
    assert "orin_proto" in driver_src and "orin_guard" in driver_src
