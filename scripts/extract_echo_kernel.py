#!/usr/bin/env python3
"""Copy selected js.echo kernel modules into echo_core and leave shims behind."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "js" / "echo"
DST = ROOT / "packages" / "echo-core" / "echo_core"

FILES = [
    "types.py",
    "primitives.py",
    "core.py",
    "amber.py",
    "amber_tree.py",
    "tide.py",
    "tide_controller.py",
    "wheel.py",
    "timing_wheel.py",
    "capability.py",
    "capability_constants.py",
    "capability_encoding.py",
    "capability_exceptions.py",
    "os_sandbox.py",
    "sandbox.py",
    "mode_contract.py",
    "execution_contract.py",
    "runtime.py",
    "testing.py",
    "ledger/__init__.py",
    "ledger/_hashing.py",
    "ledger/types.py",
    "ledger/kernel.py",
    "ledger/policy.py",
    "ledger/merkle.py",
    "ledger/epoch.py",
    "ledger/tip_seal.py",
    "ledger/tip_anchor.py",
    "ledger/journal.py",
    "ledger/effects.py",
    "ledger/journal_recovery.py",
    "ledger/archive_store.py",
    "ledger/partition_retention.py",
    "ledger/privacy.py",
    "ledger/memory.py",
    "ledger/plugins.py",
    "ledger/sandbox_backend.py",
    "ledger/strict_json.py",
    "ledger/slo.py",
    "ledger/slo_contract.py",
    "ledger/compat.py",
    "ledger/verification.py",
]


def rewrite(text: str) -> str:
    text = text.replace("from js.echo.", "from echo_core.")
    text = text.replace("import js.echo.", "import echo_core.")
    text = text.replace(
        "from js.utils.log import get_logger", "from echo_core.logging import get_logger"
    )
    text = text.replace('get_logger("js.echo.', 'get_logger("echo_core.')
    text = text.replace("js.echo.types.CapabilityLease", "echo_core.types.CapabilityLease")
    return text


def shim_text(module: str) -> str:
    return (
        '"""Compatibility shim — implementation lives in echo_core."""\n'
        "from __future__ import annotations\n\n"
        f"from {module} import *  # noqa: F403\n"
    )


def main() -> None:
    for rel in FILES:
        src = SRC / rel
        dst = DST / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        raw = src.read_text(encoding="utf-8")
        dst.write_text(rewrite(raw), encoding="utf-8")
        mod = "echo_core." + rel.replace("/", ".").removesuffix(".py")
        if mod.endswith(".__init__"):
            mod = mod[: -len(".__init__")]
        src.write_text(shim_text(mod), encoding="utf-8")
        print(f"extracted {rel}")


if __name__ == "__main__":
    main()
