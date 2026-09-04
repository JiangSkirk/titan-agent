#!/usr/bin/env python3
"""Export hashed third-party constraints.txt from the frozen lockfile.

Workspace members (echo-core / orin-proto / orin-guard) are omitted:
they are not on PyPI, and ``--require-hashes`` cannot mix unhashed
``-e`` lines. ``--check`` fails if the committed file drifts from
``uv export``.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = REPO / "constraints.txt"
HEADER = """# Hashed third-party constraints exported from uv.lock.
# Do not edit by hand. Regenerate with:
#   uv run python scripts/export_constraints.py
#
# Workspace packages (echo-core, orin-proto, orin-guard) are omitted on
# purpose: they live in packages/ and are not on PyPI. Editable -e lines
# have no --hash= and would break pip --require-hashes.
#
# From this clone (understands the workspace):
#   uv sync --frozen
# Hashed third-party pins, then local packages:
#   pip install --require-hashes -r constraints.txt
#   pip install --no-deps ./packages/echo-core ./packages/orin-proto ./packages/orin-guard .
#
"""
EXPORT_CMD = (
    "uv",
    "export",
    "--format",
    "requirements.txt",
    "--frozen",
    "--no-dev",
    "--no-emit-project",
    "--no-emit-workspace",
    "--no-annotate",
    "--no-header",
    "--extra",
    "office",
    "--extra",
    "pdf",
    "--extra",
    "telegram",
    "--extra",
    "discord",
    "--extra",
    "monitor",
    "--extra",
    "echo-tokenizer",
    "--extra",
    "desktop",
)


def export_body(*, cwd: Path = REPO) -> str:
    result = subprocess.run(
        EXPORT_CMD,
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )
    body = result.stdout
    if not body.strip():
        raise RuntimeError("uv export produced an empty constraints body")
    if "--hash=" not in body:
        raise RuntimeError("uv export omitted hashes; refuse unsigned constraints")
    if any(line.startswith("-e ") for line in body.splitlines()):
        raise RuntimeError("editable pins in hashed constraints; refuse")
    return body if body.endswith("\n") else f"{body}\n"


def render_constraints(*, cwd: Path = REPO) -> str:
    return HEADER + export_body(cwd=cwd)


def write_constraints(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def check_constraints(path: Path, expected: str) -> int:
    if not path.is_file():
        print("CONSTRAINTS_STALE: missing constraints.txt", file=sys.stderr)
        return 1
    actual = path.read_text(encoding="utf-8")
    if actual != expected:
        print(
            "CONSTRAINTS_STALE: constraints.txt does not match uv.lock export",
            file=sys.stderr,
        )
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Path to write or check (default: repo constraints.txt)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail if the committed file does not match a fresh export",
    )
    args = parser.parse_args()
    expected = render_constraints()
    if args.check:
        return check_constraints(args.output, expected)
    write_constraints(args.output, expected)
    print(f"wrote {args.output} ({len(expected.splitlines())} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
