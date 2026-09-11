#!/usr/bin/env python3
"""Supply-chain release helpers (SBOM / provenance placeholders).

Real SLSA provenance and Sigstore signing happen in CI on a tagged release.
This script fails closed when the artifacts are missing rather than inventing
them.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dist", type=Path, required=True)
    parser.add_argument("--require-sbom", action="store_true")
    parser.add_argument("--require-provenance", action="store_true")
    args = parser.parse_args()
    wheels = list(args.dist.glob("*.whl"))
    if not wheels:
        print("no wheels in dist/", file=sys.stderr)
        return 1
    ok = True
    if args.require_sbom and not list(args.dist.glob("*.spdx.json")):
        print("SBOM missing", file=sys.stderr)
        ok = False
    if args.require_provenance and not list(args.dist.glob("*.intoto.jsonl")):
        print("SLSA provenance missing", file=sys.stderr)
        ok = False
    if not ok:
        return 1
    print(f"supply-chain placeholders ok ({len(wheels)} wheels)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
