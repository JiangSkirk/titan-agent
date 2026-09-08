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
    chat_only_ticket_id,
    classify_wiring,
    null_unwired_authority,
    require_boot_ok,
)
from echo_core.execution_contract import current_execution_contract
from echo_core.ledger.journal import FileEchoLedger
from echo_core.spi.guardian import GuardianDenied, NullGuardian
from orin_guard.kernel.gate import GateKernel

from js.echo.effect_bind import (
    require_effect_exec_receipt,
    reset_effect_exec_receipt,
    set_effect_exec_receipt,
)
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


def _authority(tmp_path: Path, *, wiring: WiringMode = WiringMode.WIRED_ENFORCE) -> EffectAuthority:
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
        wiring=WiringMode.WIRED_ENFORCE,
    )
    auth.issue(_proposal(), lease_id="lease-4")
    stamped = auth.stamp("lease-4")
    rows = [r for r in journal.records if r.record_type == STAMP_RECEIPT_RECORD_TYPE]
    assert len(rows) == 1
    assert rows[0].payload["stamp_id"] == stamped.stamp_id
    assert rows[0].payload["phase"] == "STAMPED"
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
    source = (ECHO_CORE_ROOT / "effect_authority.py").read_text(encoding="utf-8")
    assert "FileEchoLedger(" not in source
    assert "open(" not in source


def test_safety_service_cannot_append_journal() -> None:
    from echo_core.spi.ports import SafetyService

    from js.echo.ledger.service import EchoSafetyService

    assert not hasattr(SafetyService, "append")
    assert "append" not in getattr(SafetyService, "__protocol_attrs__", set())
    assert not hasattr(EchoSafetyService, "append")
    assert not hasattr(EchoSafetyService, "append_stamp_receipt")
    assert not hasattr(EchoSafetyService, "append_journal")


def test_no_second_journal_writer() -> None:
    """Durable Echo journal writes are owned by FileEchoLedger."""

    from js.echo import FrameLedger
    from js.echo.ledger.journal import FileEchoLedger

    assert FrameLedger is FileEchoLedger
    source = (REPO_ROOT / "js" / "echo" / "ledger_append_adapter.py").read_text(encoding="utf-8")
    assert "FileEchoLedger" in source
    assert "class FileEchoLedgerAppend" in source


@pytest.mark.asyncio
async def test_turn_executor_bypass_red(tmp_path: Path) -> None:
    """Naked ToolExecutorMixin._execute_tool_call without D1 receipt is denied.

    This fails the build if the legacy hot-path can still execute tools while
    bypassing Echo EffectAuthority / EffectInterpreter.
    """

    from js.agent.tool_executor import ToolExecutorMixin

    # Bind the real method without constructing a full agent/registry graph.
    execute = ToolExecutorMixin._execute_tool_call
    with pytest.raises(EffectAuthorityError, match="bypasses Echo EffectAuthority"):
        await execute(
            object(),
            {
                "id": "tc1",
                "type": "function",
                "function": {"name": "file_read", "arguments": "{}"},
            },
            "session",
            "run",
            "user",
        )

    # Real `_execute_tool_call` exists on the Host agent, but EffectInterpreter
    # is the only caller path that may reach it under the frozen contract.
    interpreter = (
        REPO_ROOT / "js" / "echo" / "effect_interpreter.py"
    ).read_text(encoding="utf-8")
    assert "_execute_tool_call" in interpreter
    agent_base = (REPO_ROOT / "js" / "agent" / "base.py").read_text(encoding="utf-8")
    assert "async def _execute_tool_call" in agent_base


def test_no_execute_tool_call_bypass_symbol() -> None:
    """Public execute_tool_call is banned; underscore bypass must refuse naked calls."""

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

    # `_execute_tool_call` may exist on the Host agent, but must call
    # require_effect_exec_receipt so naked invocation cannot bypass Echo.
    source = (REPO_ROOT / "js" / "agent" / "tool_executor.py").read_text(encoding="utf-8")
    assert "require_effect_exec_receipt" in source
    assert "async def _execute_tool_call" in source
    with pytest.raises(EffectAuthorityError, match="bypasses Echo EffectAuthority"):
        require_effect_exec_receipt()


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
    assert (
        classify_wiring(enabled=False, chat_only=True, tool_table_empty=True)
        is WiringMode.CHAT_ONLY
    )
    assert classify_wiring(enabled=False, chat_only=False) is WiringMode.UNWIRED
    assert (
        classify_wiring(enabled=True, chat_only=False, enforce=True)
        is WiringMode.WIRED_ENFORCE
    )
    # CHAT_ONLY ≻ UNWIRED when chat_only ∧ ¬enabled ∧ empty tools.
    assert (
        classify_wiring(enabled=False, chat_only=True, tool_table_empty=True)
        is not WiringMode.UNWIRED
    )
    # enabled=true + chat_only=true is NEVER CHAT_ONLY.
    assert (
        classify_wiring(enabled=True, chat_only=True, enforce=True)
        is WiringMode.WIRED_ENFORCE
    )
    assert (
        classify_wiring(enabled=True, chat_only=True, enforce=False) is WiringMode.ILLEGAL
    )


def test_chat_only_ticket_issued_by_gatekernel(tmp_path: Path) -> None:
    auth = _authority(tmp_path, wiring=WiringMode.CHAT_ONLY)
    auth.issue(_proposal(effect_class="model"), lease_id="chat-1")
    stamped = auth.stamp("chat-1")
    assert stamped.stamp_id == chat_only_ticket_id("chat-1")
    assert stamped.stamp_id == "chat_only:chat-1"
    assert isinstance(auth.guardian, OrinGuardian)


def test_chat_only_host_cannot_forge_pending_stamp(tmp_path: Path) -> None:
    auth = _authority(tmp_path, wiring=WiringMode.CHAT_ONLY)
    auth.issue(_proposal(effect_class="model"), lease_id="chat-2")
    with pytest.raises(EffectAuthorityError, match="cannot forge"):
        auth.forge_pending_stamp_denied("chat-2", forged_stamp_id="forged-stamp")
    with pytest.raises(EffectAuthorityError, match="cannot forge"):
        auth.forge_pending_stamp_denied(
            "chat-2", forged_stamp_id="chat_only:chat-2"
        )


def test_chat_only_path_contract(tmp_path: Path) -> None:
    auth = _authority(tmp_path, wiring=WiringMode.CHAT_ONLY)
    auth.issue(_proposal(effect_class="model"), lease_id="chat-3")
    with pytest.raises(EffectAuthorityError, match="chat_only"):
        auth.issue(_proposal(effect_class="tool"), lease_id="chat-tool")


def test_stamped_state_durable_on_echo_ledger(tmp_path: Path) -> None:
    journal_path = tmp_path / "stamp.jsonl"
    journal = FileEchoLedger(journal_path, mac_key=b"j" * 32)
    auth = EffectAuthority(
        guardian=OrinGuardian(GateKernel(b"k" * 32)),
        ledger=FileEchoLedgerAppend(journal),
        wiring=WiringMode.WIRED_ENFORCE,
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
        wiring=WiringMode.WIRED_ENFORCE,
    )
    proposal = _proposal()
    first.issue(proposal, lease_id="lease-h")
    stamped = first.stamp("lease-h")
    row = next(r for r in journal.records if r.record_type == STAMP_RECEIPT_RECORD_TYPE)

    second = EffectAuthority(
        guardian=OrinGuardian(GateKernel(b"k" * 32)),
        ledger=FileEchoLedgerAppend(journal),
        wiring=WiringMode.WIRED_ENFORCE,
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


def test_effect_bind_receipt_roundtrip(tmp_path: Path) -> None:
    auth = _authority(tmp_path)
    receipt = auth.admit_effect(_proposal(), lease_id="bind-1")
    handle = set_effect_exec_receipt(receipt)
    try:
        assert require_effect_exec_receipt() == receipt
    finally:
        reset_effect_exec_receipt(handle)
    with pytest.raises(EffectAuthorityError):
        require_effect_exec_receipt()


def test_connector_without_d1_receipt_denied(tmp_path: Path) -> None:
    """ConnectorEffect must walk D1; unwired / unbound connector exec is denied."""

    from js.echo.effect_interpreter import EffectInterpreter

    interp = EffectInterpreter(object(), effect_authority=None)
    # Minimal context: only fields _admit_d1 reads.
    context = type(
        "Ctx",
        (),
        {
            "owner_key_hash": "owner-a",
            "session_id": "session-a",
            "run_id": "run-a",
        },
    )()
    with pytest.raises(EffectAuthorityError, match="EffectAuthority is not wired"):
        interp._admit_d1(
            effect_class="connector",
            context=context,  # type: ignore[arg-type]
            lease_id="connector:run-a:lease-x",
            grants=frozenset({"egress.send"}),
            tool_name="connector.local_import.read",
        )

    # Naked require without bind — same as tool bypass for connector path.
    with pytest.raises(EffectAuthorityError, match="bypasses Echo EffectAuthority"):
        require_effect_exec_receipt()

    source = (REPO_ROOT / "js" / "echo" / "effect_interpreter.py").read_text(encoding="utf-8")
    assert "require_effect_exec_receipt" in source
    assert 'effect_class="connector"' in source
    assert "receipt_id=d1_receipt.consume_receipt_hash" in source
    # Dual ticket collapsed: no lease_authority verify/consume on connector path.
    assert "lease_authority.verify_bound" not in source
    assert "lease_authority.consume_bound" not in source
    assert "_get_echo_tool_lease_authority" not in source
    assert "receipt_id=\"\"" not in source


def test_connector_single_d1_receipt_path(tmp_path: Path) -> None:
    """Connector success carries exactly the D1 consume receipt — one chain."""

    from js.echo.effect_interpreter import EffectInterpreter

    auth = _authority(tmp_path)
    interp = EffectInterpreter(object(), effect_authority=auth)
    context = type(
        "Ctx",
        (),
        {
            "owner_key_hash": "owner-a",
            "session_id": "session-a",
            "run_id": "run-a",
        },
    )()
    receipt = interp._admit_d1(
        effect_class="connector",
        context=context,  # type: ignore[arg-type]
        lease_id="connector:run-a:lease-single",
        grants=frozenset({"egress.send"}),
        tool_name="connector.local_import.read",
    )
    assert receipt.consume_receipt_hash
    assert receipt.lease_id == "connector:run-a:lease-single"
    # Same lease cannot be admitted twice (single-use D1 chain).
    with pytest.raises(EffectAuthorityError, match="already issued"):
        interp._admit_d1(
            effect_class="connector",
            context=context,  # type: ignore[arg-type]
            lease_id="connector:run-a:lease-single",
            grants=frozenset({"egress.send"}),
            tool_name="connector.local_import.read",
        )


def test_tool_admit_does_not_hardcode_private_read() -> None:
    """Tool admit must derive grants; hardcoding private.read is a defect."""

    from js.echo.effect_grants import assert_grants_cover_tool, grants_for_effect_tool

    required = grants_for_effect_tool("browser_fetch")
    assert "private.read" not in required or required != frozenset({"private.read"})
    assert "egress.send" in required
    with pytest.raises(EffectAuthorityError, match="grants incomplete"):
        assert_grants_cover_tool("browser_fetch", frozenset({"private.read"}))

    source = (REPO_ROOT / "js" / "echo" / "effect_interpreter.py").read_text(encoding="utf-8")
    assert "grants_for_effect_tool" in source
    assert 'grants=frozenset({"private.read"})' not in source
    assert "resource_scope=resource_scope" in source
    assert "args_hash=_d1_args_hash" in source or "args_hash=request.authority_binding_hash()" in source
    assert 'f"connector:{request.lease.lease_id}:{request.lease.nonce}"' in source
    assert "connector:{context.run_id}:" not in source


def test_assert_grants_cover_tool_honors_resource_scope() -> None:
    from js.echo.effect_grants import assert_grants_cover_tool, grants_for_effect_tool

    # Scope with "private" adds private.read even when sinks alone may not.
    required = grants_for_effect_tool("memory_store", resource_scope="private workspace")
    assert "private.read" in required
    with pytest.raises(EffectAuthorityError, match="grants incomplete"):
        assert_grants_cover_tool(
            "memory_store",
            frozenset(),
            resource_scope="private workspace",
        )


def test_tool_admit_binds_args_hash(tmp_path: Path) -> None:
    from js.echo.effect_interpreter import EffectInterpreter, _d1_args_hash

    auth = _authority(tmp_path)
    interp = EffectInterpreter(object(), effect_authority=auth)
    context = type(
        "Ctx",
        (),
        {
            "owner_key_hash": "owner-a",
            "session_id": "session-a",
            "run_id": "run-a",
        },
    )()
    args_hash = _d1_args_hash('{"path":"a.txt"}')
    receipt = interp._admit_d1(
        effect_class="tool",
        context=context,  # type: ignore[arg-type]
        lease_id="tool:run-a:file_read:tc-args",
        grants=frozenset({"private.read"}),
        tool_name="file_read",
        resource_scope="private",
        args_hash=args_hash,
    )
    assert receipt.lease_id == "tool:run-a:file_read:tc-args"
    assert args_hash
    # Second admit with different args_hash but same lease_id still denied (single-use).
    with pytest.raises(EffectAuthorityError, match="already issued"):
        interp._admit_d1(
            effect_class="tool",
            context=context,  # type: ignore[arg-type]
            lease_id="tool:run-a:file_read:tc-args",
            grants=frozenset({"private.read"}),
            tool_name="file_read",
            resource_scope="private",
            args_hash=_d1_args_hash('{"path":"b.txt"}'),
        )


def test_tool_admit_denied_without_real_required_grants(tmp_path: Path) -> None:
    """Even with private.read present, missing real tool grants are denied."""

    from js.echo.effect_interpreter import EffectInterpreter

    auth = _authority(tmp_path)
    interp = EffectInterpreter(object(), effect_authority=auth)
    context = type(
        "Ctx",
        (),
        {
            "owner_key_hash": "owner-a",
            "session_id": "session-a",
            "run_id": "run-a",
        },
    )()
    with pytest.raises(EffectAuthorityError, match="grants incomplete"):
        interp._admit_d1(
            effect_class="tool",
            context=context,  # type: ignore[arg-type]
            lease_id="tool:run-a:browser_fetch:tc1",
            grants=frozenset({"private.read"}),
            tool_name="browser_fetch",
        )


def test_gatekernel_rejects_empty_lease_for_tool_class() -> None:
    """Align with Orin PR #4: tool/connector issue requires non-empty lease_id."""

    from orin_guard.kernel.dual import PolicyPlane
    from orin_guard.kernel.gate import LEASE_BOUND_EFFECTS, TicketDenied

    assert frozenset({"tool", "connector"}) == LEASE_BOUND_EFFECTS
    kernel = GateKernel(b"k" * 32)
    plane = PolicyPlane(
        owner="o",
        session="s",
        run="r",
        effect_class="tool",
        grants=frozenset({"private.read"}),
        budget=1,
    )
    with pytest.raises(TicketDenied, match="non-empty lease_id"):
        kernel.issue(plane, lease_id="")
