"""Import-cycle and firewall tests for the extracted packages."""

from __future__ import annotations

import ast
from pathlib import Path

from echo_core.taint import USER_TURN

from js.orin import taint as js_taint

ROOT = Path(__file__).resolve().parents[2]


def test_js_orin_taint_reexports_echo_core() -> None:
    assert js_taint.USER_TURN == USER_TURN


def test_extracted_packages_do_not_import_js() -> None:
    hits: list[str] = []
    for pkg in (
        ROOT / "packages" / "echo-core" / "echo_core",
        ROOT / "packages" / "orin-proto" / "orin_proto",
        ROOT / "packages" / "orin-guard" / "orin_guard",
    ):
        for py in pkg.rglob("*.py"):
            tree = ast.parse(py.read_text(encoding="utf-8"), filename=str(py))
            for node in ast.walk(tree):
                names: list[str] = []
                if isinstance(node, ast.Import):
                    names = [a.name.split(".")[0] for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    names = [node.module.split(".")[0]]
                if "js" in names:
                    hits.append(str(py.relative_to(ROOT)))
    assert hits == []
