#!/usr/bin/env python3
"""Import firewall: echo-core/orin-guard/orin-proto must not import js.*.

echo-core must not import orin_guard.
orin-proto must not import echo_core or orin_guard.
orin-guard may import echo_core and orin_proto.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

RULES: list[tuple[Path, frozenset[str]]] = [
    (ROOT / "packages" / "echo-core" / "echo_core", frozenset({"js", "orin_guard", "orin_proto"})),
    (ROOT / "packages" / "orin-proto" / "orin_proto", frozenset({"js", "echo_core", "orin_guard"})),
    (ROOT / "packages" / "orin-guard" / "orin_guard", frozenset({"js"})),
]


def _top(name: str) -> str:
    return name.split(".")[0]


def scan(src: Path, banned: frozenset[str]) -> list[str]:
    hits: list[str] = []
    for py in src.rglob("*.py"):
        tree = ast.parse(py.read_text(encoding="utf-8"), filename=str(py))
        for node in ast.walk(tree):
            mods: list[str] = []
            if isinstance(node, ast.Import):
                mods = [_top(a.name) for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                mods = [_top(node.module)]
            for mod in mods:
                if mod in banned:
                    hits.append(f"{py.relative_to(ROOT)}:{node.lineno}: import {mod}")
    return hits


def main() -> int:
    all_hits: list[str] = []
    for src, banned in RULES:
        if not src.is_dir():
            print(f"missing {src}", file=sys.stderr)
            return 1
        all_hits.extend(scan(src, banned))
    if all_hits:
        print("import firewall failed:", file=sys.stderr)
        for hit in all_hits:
            print(f"  {hit}", file=sys.stderr)
        return 1
    print("import firewall ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
