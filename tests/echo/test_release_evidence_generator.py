from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import scripts.generate_release_evidence as release_evidence
from scripts.generate_release_evidence import (
    PackageEvidence,
    _existing_generated_at,
    _license_metadata,
    _normalize_command_output,
    _spdx_license_value,
    render_license_scan,
)


def _package(name: str, license_text: str) -> PackageEvidence:
    return PackageEvidence(
        name=name,
        version="1.0",
        source="registry",
        license_text=license_text,
        classifiers=(),
        hashes=(),
    )


def test_license_scan_separates_strong_weak_and_unknown_licenses() -> None:
    report = render_license_scan(
        [
            _package("strong", "AGPL-3.0-only"),
            _package("weak", "LGPL-3.0-only"),
            _package("file-level", "MPL-2.0"),
            _package("unknown", "NOASSERTION"),
        ],
        "2026-07-11T00:00:00Z",
    )

    assert "Strong copyleft markers: strong (AGPL-3.0-only)" in report
    assert "Weak/file-level reciprocal markers:" in report
    assert "weak (LGPL-3.0-only)" in report
    assert "file-level (MPL-2.0)" in report
    assert "Unknown license metadata: `unknown`" in report


def test_check_mode_reuses_the_existing_sbom_timestamp(tmp_path: Path) -> None:
    sbom = tmp_path / "SBOM.spdx.json"
    sbom.write_text(
        json.dumps({"creationInfo": {"created": "2026-07-11T00:00:00Z"}}),
        encoding="utf-8",
    )

    assert _existing_generated_at(sbom) == "2026-07-11T00:00:00Z"


def test_release_smoke_evidence_removes_nondeterministic_log_noise() -> None:
    raw = "\n".join(
        [
            "临时测试目录: /tmp/titan-release-smoke-random",
            "[检查] package",
            "  [OK] package",
            "2026-07-11 20:43:50 [info] random runtime log",
            "  [OK] web/model",
            "发布烟测通过。",
        ]
    )

    normalized = _normalize_command_output("release_smoke", raw)

    assert "random runtime log" not in normalized
    assert "titan-release-smoke-random" not in normalized
    assert normalized.splitlines() == [
        "[检查] package",
        "[OK] package",
        "[OK] web/model",
        "发布烟测通过。",
    ]


def test_command_evidence_uses_a_temporary_ledger_outside_the_repository(
    monkeypatch,
) -> None:
    captured: dict[str, list[str]] = {}

    def fake_run(command: list[str], *, evidence_name: str = "") -> str:
        captured[evidence_name] = command
        return "$ fake\nexit=0\nok"

    monkeypatch.setattr(release_evidence, "_run_capture", fake_run)

    release_evidence.collect_command_evidence()

    command = captured["echo_ledger_smoke"]
    state_dir = Path(command[command.index("--state-dir") + 1]).resolve()
    assert not state_dir.is_relative_to(release_evidence.ROOT.resolve())


def test_spdx_value_maps_known_license_classifiers() -> None:
    assert _spdx_license_value("License :: OSI Approved :: MIT License") == "MIT"
    assert (
        _spdx_license_value("License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)")
        == "MPL-2.0"
    )


def test_license_metadata_rejects_an_installed_version_that_differs_from_lock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    installed = SimpleNamespace(
        version="2.0",
        metadata={"License-Expression": "MIT"},
    )
    monkeypatch.setattr(release_evidence.metadata, "distribution", lambda _name: installed)

    assert _license_metadata("example", "1.0") == ("NOASSERTION", ())


def test_lockfile_evidence_rejects_an_empty_package_set(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    lockfile = tmp_path / "uv.lock"
    lockfile.write_text("version = 1\n", encoding="utf-8")
    monkeypatch.setattr(release_evidence, "LOCKFILE", lockfile)
    monkeypatch.setattr(release_evidence, "CARGO_LOCK", tmp_path / "missing-cargo")
    monkeypatch.setattr(release_evidence, "PNPM_LOCK", tmp_path / "missing-pnpm")

    with pytest.raises(ValueError, match="no packages"):
        release_evidence.read_lock_packages()


def test_lockfile_evidence_accepts_any_complete_nonempty_package_graph(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    lockfile = tmp_path / "uv.lock"
    lockfile.write_text(
        '[[package]]\nname = "example-root"\nversion = "1.0"\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(release_evidence, "LOCKFILE", lockfile)
    monkeypatch.setattr(release_evidence, "CARGO_LOCK", tmp_path / "missing-cargo")
    monkeypatch.setattr(release_evidence, "PNPM_LOCK", tmp_path / "missing-pnpm")

    packages = release_evidence.read_lock_packages()

    assert [(package.name, package.version) for package in packages] == [
        ("example-root", "1.0")
    ]


def test_lockfile_evidence_rejects_a_missing_declared_dependency(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    lockfile = tmp_path / "uv.lock"
    lockfile.write_text(
        '[[package]]\nname = "js-agent"\nversion = "0.1.5"\n'
        'dependencies = [{ name = "missing-transitive" }]\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(release_evidence, "LOCKFILE", lockfile)
    monkeypatch.setattr(release_evidence, "CARGO_LOCK", tmp_path / "missing-cargo")
    monkeypatch.setattr(release_evidence, "PNPM_LOCK", tmp_path / "missing-pnpm")

    with pytest.raises(ValueError, match="missing-transitive"):
        release_evidence.read_lock_packages()


def _assert_spdx_schema(spdx: dict[str, Any]) -> None:
    for key in (
        "spdxVersion",
        "dataLicense",
        "SPDXID",
        "name",
        "documentNamespace",
        "creationInfo",
        "packages",
        "relationships",
    ):
        assert key in spdx
    assert spdx["spdxVersion"] == "SPDX-2.3"
    assert spdx["SPDXID"] == "SPDXRef-DOCUMENT"
    assert isinstance(spdx["packages"], list) and spdx["packages"]
    created = spdx["creationInfo"]["created"]
    assert isinstance(created, str) and created.endswith("Z")
    assert spdx["creationInfo"]["creators"]
    for package in spdx["packages"]:
        assert package["SPDXID"]
        assert package["name"]
        assert package["versionInfo"]


def _assert_spdx_three_ecosystems(spdx: dict[str, Any]) -> None:
    names = [package["name"] for package in spdx["packages"]]
    assert any(name.startswith("cargo:") for name in names), "Cargo lock ecosystem missing from SPDX"
    assert any(name.startswith("pnpm:") for name in names), "pnpm lock ecosystem missing from SPDX"
    pypi = [
        name
        for name in names
        if name != "js-agent" and not name.startswith(("cargo:", "pnpm:"))
    ]
    assert pypi, "uv/PyPI lock ecosystem missing from SPDX"
    assert "cargo:tauri" in names
    assert "cargo:serde" in names


def _assert_spdx_has_no_runtime_leak(text: str) -> None:
    home = str(Path.home())
    assert home not in text
    assert "chat.jsonl" not in text
    assert "/Users/jiangxuanzhen" not in text
    assert "BEGIN PRIVATE KEY" not in text
    assert ".tmp/" not in text
    assert "node_modules" not in text


def _write_synthetic_locks(tmp_path: Path) -> tuple[Path, Path, Path]:
    uv_lock = tmp_path / "uv.lock"
    uv_lock.write_text(
        '[[package]]\nname = "example-root"\nversion = "1.0"\n',
        encoding="utf-8",
    )
    cargo_lock = tmp_path / "Cargo.lock"
    cargo_lock.write_text(
        '[[package]]\nname = "tauri"\nversion = "2.0.0"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
        'checksum = "aa"\n\n'
        '[[package]]\nname = "serde"\nversion = "1.0.0"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
        'checksum = "bb"\n',
        encoding="utf-8",
    )
    pnpm_lock = tmp_path / "pnpm-lock.yaml"
    pnpm_lock.write_text(
        "lockfileVersion: '9.0'\n"
        "packages:\n"
        "  '@scope/synth-pkg@1.2.3':\n"
        "    resolution: {integrity: sha512-abc}\n",
        encoding="utf-8",
    )
    return uv_lock, cargo_lock, pnpm_lock


def test_generator_emits_uv_cargo_and_pnpm_from_synthetic_locks(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    uv_lock, cargo_lock, pnpm_lock = _write_synthetic_locks(tmp_path)
    monkeypatch.setattr(release_evidence, "LOCKFILE", uv_lock)
    monkeypatch.setattr(release_evidence, "CARGO_LOCK", cargo_lock)
    monkeypatch.setattr(release_evidence, "PNPM_LOCK", pnpm_lock)

    packages = release_evidence.read_lock_packages()
    names = {package.name for package in packages}
    assert names == {
        "example-root",
        "cargo:tauri",
        "cargo:serde",
        "pnpm:@scope/synth-pkg",
    }
    spdx = release_evidence.build_spdx(packages, "2026-08-15T00:00:00Z")
    _assert_spdx_schema(spdx)
    _assert_spdx_three_ecosystems(spdx)
    assert any(package["name"] == "pnpm:@scope/synth-pkg" for package in spdx["packages"])


def test_sbom_closure_fails_when_cargo_ecosystem_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    uv_lock, _cargo_lock, pnpm_lock = _write_synthetic_locks(tmp_path)
    monkeypatch.setattr(release_evidence, "LOCKFILE", uv_lock)
    monkeypatch.setattr(release_evidence, "CARGO_LOCK", tmp_path / "missing-cargo")
    monkeypatch.setattr(release_evidence, "PNPM_LOCK", pnpm_lock)

    packages = release_evidence.read_lock_packages()
    spdx = release_evidence.build_spdx(packages, "2026-08-15T00:00:00Z")
    with pytest.raises(AssertionError, match="Cargo"):
        _assert_spdx_three_ecosystems(spdx)


def test_sbom_closure_fails_when_pnpm_ecosystem_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    uv_lock, cargo_lock, _pnpm_lock = _write_synthetic_locks(tmp_path)
    monkeypatch.setattr(release_evidence, "LOCKFILE", uv_lock)
    monkeypatch.setattr(release_evidence, "CARGO_LOCK", cargo_lock)
    monkeypatch.setattr(release_evidence, "PNPM_LOCK", tmp_path / "missing-pnpm")

    packages = release_evidence.read_lock_packages()
    spdx = release_evidence.build_spdx(packages, "2026-08-15T00:00:00Z")
    with pytest.raises(AssertionError, match="pnpm"):
        _assert_spdx_three_ecosystems(spdx)


def test_legacy_uv_only_spdx_fixture_fails_closure() -> None:
    fixture = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "legacy-uv-only",
        "documentNamespace": "https://example.invalid/legacy",
        "creationInfo": {
            "created": "2026-07-16T21:27:26Z",
            "creators": ["Tool: scripts/generate_release_evidence.py"],
        },
        "packages": [
            {"SPDXID": "SPDXRef-Package-js-agent", "name": "js-agent", "versionInfo": "0.1.5"},
            {"SPDXID": "SPDXRef-Package-aiosqlite", "name": "aiosqlite", "versionInfo": "0.22.1"},
        ],
        "relationships": [],
    }
    _assert_spdx_schema(fixture)
    with pytest.raises(AssertionError, match="Cargo|pnpm"):
        _assert_spdx_three_ecosystems(fixture)


def test_committed_spdx_is_closed_with_current_real_locks() -> None:
    packages = release_evidence.read_lock_packages()
    sbom_path = release_evidence.SECURITY_DIR / "SBOM.spdx.json"
    created = release_evidence._existing_generated_at(sbom_path)
    assert created is not None
    generated = release_evidence.generate_static_artifacts(packages, created)[sbom_path]
    committed = sbom_path.read_text(encoding="utf-8")
    assert committed == generated
    spdx = json.loads(committed)
    _assert_spdx_schema(spdx)
    _assert_spdx_three_ecosystems(spdx)
    _assert_spdx_has_no_runtime_leak(committed)
    names = {package["name"] for package in spdx["packages"]}
    for package in packages:
        assert package.name in names
    assert len(spdx["packages"]) > 134
    uv_digest = hashlib.sha256(release_evidence.LOCKFILE.read_bytes()).hexdigest()
    cargo_digest = hashlib.sha256(release_evidence.CARGO_LOCK.read_bytes()).hexdigest()
    pnpm_digest = hashlib.sha256(release_evidence.PNPM_LOCK.read_bytes()).hexdigest()
    assert len(uv_digest) == 64
    assert len(cargo_digest) == 64
    assert len(pnpm_digest) == 64
    comment = str(spdx["creationInfo"].get("comment", ""))
    assert "lockfile" in comment.lower()
    from js.echo.ledger.release_gates import release_source_digest

    source_digest = release_source_digest(release_evidence.ROOT)
    assert len(source_digest) == 64


def test_spdx_generation_is_byte_stable_for_identical_inputs() -> None:
    packages = release_evidence.read_lock_packages()
    sbom_path = release_evidence.SECURITY_DIR / "SBOM.spdx.json"
    first = release_evidence.generate_static_artifacts(packages, "2026-08-15T00:00:00Z")[sbom_path]
    second = release_evidence.generate_static_artifacts(packages, "2026-08-15T00:00:00Z")[sbom_path]
    assert first == second
    _assert_spdx_has_no_runtime_leak(first)
