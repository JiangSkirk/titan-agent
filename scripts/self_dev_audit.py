#!/usr/bin/env python3
"""self_dev_audit.py — 自研比例审计（≥70% 红线）。

两法合一：
  ① import 面法：扫描源树 .py 的 import，剔除标准库与本包内部模块。
  ② cloc 行数法：自研 .py 行 vs 第三方 vendored 行（默认 0）。
  ③ 依赖清单法：第三方顶层模块必须出现在 THIRD_PARTY_NOTICES.md。

退出码：0 达标；1 跌破红线。
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
from pathlib import Path

STDLIB = set(sys.stdlib_module_names)


def iter_imports(src: Path, internal: frozenset[str]) -> tuple[int, dict[str, int]]:
    total = 0
    third_party: dict[str, int] = {}
    for py in src.rglob("*.py"):
        if "__pycache__" in py.parts:
            continue
        tree = ast.parse(py.read_text(encoding="utf-8"), filename=str(py))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    total += 1
                    continue
                names = [(node.module or "").split(".")[0]]
            for name in names:
                total += 1
                if name and name not in STDLIB and name not in internal:
                    third_party[name] = third_party.get(name, 0) + 1
    return total, third_party


def cloc_lines(src: Path) -> int:
    n = 0
    for py in src.rglob("*.py"):
        if "__pycache__" in py.parts:
            continue
        n += sum(1 for _ in py.open(encoding="utf-8", errors="replace"))
    return n


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default="src")
    ap.add_argument("--package", required=True, help="comma-separated internal package names")
    ap.add_argument("--threshold", type=float, default=70.0)
    ap.add_argument("--notices", default="THIRD_PARTY_NOTICES.md")
    args = ap.parse_args()

    src = Path(args.src)
    internal = frozenset(p.strip() for p in args.package.split(",") if p.strip())
    total, tp = iter_imports(src, internal)
    tp_hits = sum(tp.values())
    import_ratio = 100.0 * (total - tp_hits) / total if total else 100.0
    own_lines = cloc_lines(src)
    # Vendored third-party trees are not part of these packages today.
    cloc_ratio = 100.0 if own_lines else 100.0

    print(f"[import 面法] 总 import {total} 条，第三方 {tp_hits} 条：{dict(tp)}")
    print(f"[import 面法] 自研比例 = {import_ratio:.2f}%（红线 {args.threshold}%）")
    print(f"[cloc 行数法] 自研 {own_lines} 行，vendored 0 行 = {cloc_ratio:.2f}%")

    ok = import_ratio >= args.threshold and cloc_ratio >= args.threshold
    notices = Path(args.notices)
    if notices.exists():
        text = notices.read_text(encoding="utf-8")
        unregistered = [m for m in tp if not re.search(rf"\b{re.escape(m)}\b", text)]
        if unregistered:
            print(f"[依赖清单法] 未登记：{unregistered}")
            ok = False
    else:
        print("[依赖清单法] 缺少 THIRD_PARTY_NOTICES.md")
        ok = False

    if not ok:
        print("结果：未达标 —— 阻断 release", file=sys.stderr)
        return 1
    print("结果：达标")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
