"""Echo fail-closed effect authority contracts (upgrade v0.3.3 D1)."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from echo_core.effect_authority import (
    STAMP_RECEIPT_RECORD_TYPE,
    BootDenied,
    EffectAuthority,
    EffectAuthorityError,
    EffectProposal,
    WiringMode,
    classify_wiring,
    null_unwired_authority,
    require_boot_ok,
)
from echo_core.execution_contract import current_execution_contract
from echo_core.ledger.journal import FileEchoLedger
from echo_core.spi.guardian import GuardianDenied, NullGuardian
from orin_guard.kernel.gate import GateKernel

from js.echo.guardian_adapter import OrinGuardian
from js.echo.ledger_append_adapter import FileEchoLedgerAppend

REPO_ROOT = Path(__file__).resolve().parents[2]
ECHO_CORE_ROOT = REPO_ROOT / "packages" / "echo-core" / "echo_core"


def _proposal(*, effect_class: str = "tool") -> EffectProposal:
    return EffectProposal(
        owner="owner-a",
        session="session-a",
        run="run-a",
        effect_class=effect_class,
        grants=frozenset({"private.read"}),
        budget=1,
    )


def _authority(tmp_path: Path, *, wiring: WiringMode = WiringMode.WIRED) -> EffectAuthority:
    journal = FileEchoLedger(tmp_path / "stamp.jsonl", mac_key=b"j" * 32)
    guardian = OrinGuardian(GateKernel(b"k" * 32))
    return EffectAuthority(
        guardian=guardian,
        ledger=FileEchoLedgerAppend(journal),
        wiring=wiring,
    )


def test_consume_before_stamp_denied(tmp_path: Path) -> None:
    auth = _authority(tmp_path)
    pending = auth.issue(_proposal(), lease_id="lease-1")
    assert pending.phase.value == "PENDING"
    with pytest.raises(EffectAuthorityError, match="consume-before-stamp"):
        auth.consume("lease-1")


def test_exec_without_stamp_denied(tmp_path: Path) -> None:
    auth = _authority(tmp_path)
    auth.issue(_proposal(), lease_id="lease-2")
    with pytest.raises(EffectAuthorityError, match="exec without stamp"):
        auth.require_exec("lease-2")
    with pytest.raises(EffectAuthorityError, match="exec without stamp"):
        auth.require_exec("missing-lease")


def test_no_public_effect_ticket_symbol() -> None:
    import echo_core
    import echo_core.effect_authority as authority

    assert not hasattr(echo_core, "EffectTicket")
    assert not hasattr(authority, "EffectTicket")
    public = set(getattr(echo_core, "__all__", ()))
    assert "EffectTicket" not in public


def test_interpreter_rejects_ticket_without_lease_receipt(tmp_path: Path) -> None:
    auth = _authority(tmp_path)
    auth.issue(_proposal(), lease_id="lease-3")
    auth.stamp("lease-3")
    with pytest.raises(EffectAuthorityError, match="lease receipt"):
        auth.require_exec("lease-3")
    receipt = auth.consume("lease-3")
    assert auth.require_exec("lease-3") == receipt


def test_interpreter_requires_ledger_receipt(tmp_path: Path) -> None:
    """Frozen alias — Interpreter.exec requires durable ledger receipt."""

    test_interpreter_rejects_ticket_without_lease_receipt(tmp_path)


def test_execution_contract_ledger_owner_is_file_echo_ledger() -> None:
    contract = current_execution_contract()
    assert contract.ledger_owner == "FileEchoLedger"


def test_only_host_adapter_appends_stamp_receipt(tmp_path: Path) -> None:
    journal = FileEchoLedger(tmp_path / "stamp.jsonl", mac_key=b"j" * 32)
    adapter = FileEchoLedgerAppend(journal)
    auth = EffectAuthority(
        guardian=OrinGuardian(GateKernel(b"k" * 32)),
        ledger=adapter,
        wiring=WiringMode.WIRED,
    )
    auth.issue(_proposal(), lease_id="lease-4")
    stamped = auth.stamp("lease-4")
    rows = [r for r in journal.records if r.record_type == STAMP_RECEIPT_RECORD_TYPE]
    assert len(rows) == 1
    assert rows[0].payload["stamp_id"] == stamped.stamp_id
    assert rows[0].payload["phase"] == "STAMPED"
    # Interpreter / echo-core must not be the concrete append owner.
    assert adapter.__module__.startswith("js.echo.")


def test_echo_core_has_no_ledger_append_symbol() -> None:
    """Protocol may exist; concrete Host append must not live in echo-core."""

    offenders: list[str] = []
    for path in sorted(ECHO_CORE_ROOT.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name in {
                "FileEchoLedgerAppend",
                "HostLedgerAppend",
                "StampLedgerAppend",
            }:
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{node.name}")
            if isinstance(node, ast.FunctionDef) and node.name in {
                "append_stamp_receipt",
                "append_stamped",
            }:
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{node.name}")
    assert offenders == []
    # Protocol is declared; no journal-fd holder in effect authority module.
    source = (ECHO_CORE_ROOT / "effect_authority.py").read_text(encoding="utf-8")
    assert "FileEchoLedger(" not in source
    assert "open(" not in source


def test_safety_service_cannot_append_journal() -> None:
    from echo_core.spi.ports import SafetyService

    from js.echo.ledger.service import EchoSafetyService

    assert not hasattr(SafetyService, "append")
    assert "append" not in getattr(SafetyService, "__protocol_attrs__", set())
    # Public stamp-receipt append must not be a SafetyService method.
    assert not hasattr(EchoSafetyService, "append")
    assert not hasattr(EchoSafetyService, "append_stamp_receipt")
    assert not hasattr(EchoSafetyService, "append_journal")


def test_no_second_journal_writer() -> None:
    """Durable Echo journal writes are owned by FileEchoLedger."""

    from js.echo import FrameLedger
    from js.echo.ledger.journal import FileEchoLedger

    assert FrameLedger is FileEchoLedger
    # Host stamp adapter wraps FileEchoLedger rather than inventing a writer.
    source = (
        REPO_ROOT / "js" / "echo" / "ledger_append_adapter.py"
    ).read_text(encoding="utf-8")
    assert "FileEchoLedger" in source
    assert "class FileEchoLedgerAppend" in source


def test_turn_executor_bypass_red(tmp_path: Path) -> None:
    """Bypassing stamp/consume (naked tool exec) is denied by authority."""

    auth = _authority(tmp_path)
    # Simulate a TurnExecutor / agent._execute_tool_call bypass with no lease.
    with pytest.raises(EffectAuthorityError, match="exec without stamp"):
        auth.require_exec("bypass-lease")

    # Real `_execute_tool_call` exists on the Host agent, but EffectInterpreter
    # is the only caller path that may reach it under the frozen contract.
    interpreter = (
        REPO_ROOT / "js" / "echo" / "effect_interpreter.py"
    ).read_text(encoding="utf-8")
    assert "_execute_tool_call" in interpreter
    agent_base = (REPO_ROOT / "js" / "agent" / "base.py").read_text(encoding="utf-8")
    assert "async def _execute_tool_call" in agent_base


def test_no_execute_tool_call_bypass_symbol() -> None:
    """No public execute_tool_call that skips EffectInterpreter."""

    offenders: list[str] = []
    roots = (
        REPO_ROOT / "js" / "echo",
        REPO_ROOT / "packages" / "echo-core" / "echo_core",
    )
    for root in roots:
        for path in root.rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if (
                    isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and node.name == "execute_tool_call"
                ):
                    offenders.append(str(path.relative_to(REPO_ROOT)))
    assert offenders == []


def test_no_second_run_echo_turn_entrypoint() -> None:
    matches: list[str] = []
    for path in (REPO_ROOT / "js").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "run_echo_turn":
                matches.append(str(path.relative_to(REPO_ROOT)))
    assert matches == ["js/echo/turn_runtime.py"]


def test_unwired_null_guardian_denies_sink() -> None:
    auth = null_unwired_authority()
    with pytest.raises(GuardianDenied):
        auth.issue(_proposal(effect_class="tool"), lease_id="u1")
    with pytest.raises(GuardianDenied):
        NullGuardian().stamp(
            owner="o",
            session="s",
            run="r",
            effect_class="tool",
            grants=frozenset({"private.read"}),
            budget=1,
        )


def test_unwired_model_effect_denied() -> None:
    auth = null_unwired_authority()
    with pytest.raises(GuardianDenied):
        auth.propose(_proposal(effect_class="model"))


def test_enabled_without_enforce_boot_fails() -> None:
    with pytest.raises(BootDenied, match="enabled without enforce"):
        require_boot_ok(enabled=True, enforce=False)
    require_boot_ok(enabled=False, enforce=False)
    require_boot_ok(enabled=True, enforce=True)


def test_chat_only_not_classified_as_unwired() -> None:
    assert classify_wiring(enabled=False, chat_only=True) is WiringMode.CHAT_ONLY
    assert classify_wiring(enabled=False, chat_only=False) is WiringMode.UNWIRED
    assert classify_wiring(enabled=True, chat_only=False) is WiringMode.WIRED
    # CHAT_ONLY ≻ UNWIRED even when enabled=false.
    assert classify_wiring(enabled=False, chat_only=True) is not WiringMode.UNWIRED


def test_chat_only_ticket_issued_by_gatekernel(tmp_path: Path) -> None:
    auth = _authority(tmp_path, wiring=WiringMode.CHAT_ONLY)
    # Chat-only model tickets still go through GateKernel via OrinGuardian.
    auth.issue(_proposal(effect_class="model"), lease_id="chat-1")
    stamped = auth.stamp("chat-1")
    assert stamped.stamp_id
    assert isinstance(auth.guardian, OrinGuardian)


def test_chat_only_host_cannot_forge_pending_stamp(tmp_path: Path) -> None:
    auth = _authority(tmp_path, wiring=WiringMode.CHAT_ONLY)
    auth.issue(_proposal(effect_class="model"), lease_id="chat-2")
    with pytest.raises(EffectAuthorityError, match="cannot forge"):
        auth.forge_pending_stamp_denied("chat-2", forged_stamp_id="forged-stamp")


def test_chat_only_path_contract(tmp_path: Path) -> None:
    auth = _authority(tmp_path, wiring=WiringMode.CHAT_ONLY)
    # Model/chat may issue; tool sinks remain denied on the chat-only path.
    auth.issue(_proposal(effect_class="model"), lease_id="chat-3")
    with pytest.raises(EffectAuthorityError, match="chat_only"):
        auth.issue(_proposal(effect_class="tool"), lease_id="chat-tool")


def test_stamped_state_durable_on_echo_ledger(tmp_path: Path) -> None:
    journal_path = tmp_path / "stamp.jsonl"
    journal = FileEchoLedger(journal_path, mac_key=b"j" * 32)
    auth = EffectAuthority(
        guardian=OrinGuardian(GateKernel(b"k" * 32)),
        ledger=FileEchoLedgerAppend(journal),
        wiring=WiringMode.WIRED,
    )
    auth.issue(_proposal(), lease_id="lease-d")
    stamped = auth.stamp("lease-d")
    reopened = FileEchoLedger(journal_path, mac_key=b"j" * 32)
    rows = [r for r in reopened.records if r.record_type == STAMP_RECEIPT_RECORD_TYPE]
    assert len(rows) == 1
    assert rows[0].payload["phase"] == "STAMPED"
    assert rows[0].payload["stamp_id"] == stamped.stamp_id
    assert rows[0].payload["lease_id"] == "lease-d"


def test_live_cache_hydrates_from_echo_ledger_stamped_row(tmp_path: Path) -> None:
    journal = FileEchoLedger(tmp_path / "stamp.jsonl", mac_key=b"j" * 32)
    first = EffectAuthority(
        guardian=OrinGuardian(GateKernel(b"k" * 32)),
        ledger=FileEchoLedgerAppend(journal),
        wiring=WiringMode.WIRED,
    )
    proposal = _proposal()
    first.issue(proposal, lease_id="lease-h")
    stamped = first.stamp("lease-h")
    row = next(r for r in journal.records if r.record_type == STAMP_RECEIPT_RECORD_TYPE)

    # Fresh authority instance hydrates live cache from durable STAMPED row.
    second = EffectAuthority(
        guardian=OrinGuardian(GateKernel(b"k" * 32)),
        ledger=FileEchoLedgerAppend(journal),
        wiring=WiringMode.WIRED,
    )
    hydrated = second.hydrate_from_stamped_row(dict(row.payload), proposal=proposal)
    assert hydrated.lease_id == "lease-h"
    assert hydrated.stamp_id == stamped.stamp_id
    assert hydrated.phase.value == "STAMPED"


def test_pulse_emits_no_exec() -> None:
    from js.echo.core import pulse
    from js.echo.testing import new_fake_amber, new_fake_tide, new_fake_wheel

    _successor, actions = pulse(0, [], new_fake_amber(), new_fake_wheel(), new_fake_tide())
    kinds = {type(action).__name__ for action in actions}
    assert "Exec" not in kinds
    assert "CommitFrame" not in kinds
