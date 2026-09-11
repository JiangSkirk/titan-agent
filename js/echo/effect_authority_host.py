"""Build Host-wired EffectAuthority for EchoRuntime."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from echo_core.effect_authority import (
    EffectAuthority,
    WiringMode,
    classify_wiring,
    null_unwired_authority,
    require_boot_ok,
)
from echo_core.ledger.journal import FileEchoLedger
from orin_guard.kernel.gate import GateKernel

from js.echo.guardian_adapter import OrinGuardian
from js.echo.ledger_append_adapter import FileEchoLedgerAppend


def build_host_effect_authority(
    *,
    state_dir: Path,
    mac_key: bytes | None = None,
    journal_key: bytes | None = None,
    enabled: bool = True,
    enforce: bool = True,
    chat_only: bool = False,
    tool_table_empty: bool = True,
) -> EffectAuthority:
    """Construct the Host D1 gate. Fail closed on illegal enabled/¬enforce."""

    require_boot_ok(enabled=enabled, enforce=enforce)
    wiring = classify_wiring(
        enabled=enabled,
        chat_only=chat_only,
        enforce=enforce,
        tool_table_empty=tool_table_empty,
    )
    if wiring is WiringMode.UNWIRED:
        return null_unwired_authority()
    if wiring is WiringMode.ILLEGAL:
        raise RuntimeError("illegal effect authority wiring")

    key = mac_key if mac_key is not None else b"echo-effect-authority-mac-key-32b!!"
    jkey = journal_key if journal_key is not None else b"echo-effect-stamp-journal-key-32b"
    stamp_dir = Path(state_dir) / "echo" / "effect_authority"
    stamp_dir.mkdir(parents=True, exist_ok=True)
    journal = FileEchoLedger(stamp_dir / "stamp_receipts.jsonl", mac_key=jkey)
    return EffectAuthority(
        guardian=OrinGuardian(GateKernel(key, enforce=True)),
        ledger=FileEchoLedgerAppend(journal),
        wiring=wiring,
    )


def effect_authority_from_agent(agent: Any) -> EffectAuthority:
    settings = getattr(agent, "settings", None)
    state_dir = Path(getattr(settings, "state_dir", Path(".")))
    orin = getattr(settings, "orin", None)
    # EffectAuthority enforce is the D1 gate flag (GateKernel), not Stage C.
    chat_only = bool(getattr(settings, "echo_chat_only", False))
    tool_names = getattr(agent, "_current_allowed_tools", None) or set()
    tool_table_empty = len(tool_names) == 0
    # Default Host: effect authority enabled+enforce so Interpreter.exec is gated.
    enabled = True
    enforce = True
    if chat_only:
        enabled = False
    _ = orin  # product orin.enforce remains Stage C; not used here
    return build_host_effect_authority(
        state_dir=state_dir,
        enabled=enabled,
        enforce=enforce,
        chat_only=chat_only,
        tool_table_empty=tool_table_empty,
    )


__all__ = ["build_host_effect_authority", "effect_authority_from_agent"]
