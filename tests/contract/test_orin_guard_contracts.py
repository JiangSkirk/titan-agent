"""Orin frozen architecture contracts (shared suite with Echo).

Names are pinned by the Orin/Echo architecture freeze. Do not invent a parallel
C1–C23 numbering scheme in this file or the PR coverage map.
"""

from __future__ import annotations

import ast
import os
from pathlib import Path

import pytest
from echo_core.effect_authority import (
    EffectAuthority,
    EffectAuthorityError,
    EffectProposal,
    WiringMode,
)
from echo_core.ledger.journal import FileEchoLedger
from echo_core.spi.guardian import GuardianDenied, NullGuardian
from echo_core.taint import WEB_CONTENT
from orin_guard.broker.cred import CredBroker, CredBrokerDenied
from orin_guard.kernel.conjunction import ConjunctionDenied, require_conjunction
from orin_guard.kernel.dual import PolicyPlane
from orin_guard.kernel.gate import GateKernel, TicketDenied
from orin_guard.kernel.grants import grants_for_tool

from js.echo.guardian_adapter import OrinGuardian
from js.echo.ledger_append_adapter import FileEchoLedgerAppend
from js.orind import policy as policy_mod
from js.orind.gatekeeper import GateKeeper
from js.orind.store import OrinStore

REPO_ROOT = Path(__file__).resolve().parents[2]
ORIN_GUARD_ROOT = REPO_ROOT / "packages" / "orin-guard" / "orin_guard"
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


def test_interpreter_requires_ledger_receipt(tmp_path: Path) -> None:
    """Frozen alias of durable lease-receipt preflight for Interpreter.exec."""

    auth = _authority(tmp_path)
    auth.issue(_proposal(), lease_id="lease-ir")
    auth.stamp("lease-ir")
    with pytest.raises(EffectAuthorityError, match="lease receipt"):
        auth.require_exec("lease-ir")
    receipt = auth.consume("lease-ir")
    assert auth.require_exec("lease-ir") == receipt


def test_mac_missing_grants_digest_denied() -> None:
    import dataclasses

    from orin_guard.kernel.gate import grants_digest

    kernel = GateKernel(b"k" * 32)
    plane = PolicyPlane("o", "s", "r", "tool", frozenset({"private.read"}), 1)
    ticket = kernel.issue(plane, lease_id="lease-mg", args_hash="a")
    blank = dataclasses.replace(ticket, grants_digest="")
    assert blank.grants_digest != grants_digest(ticket.grants)
    with pytest.raises(TicketDenied, match="MAC mismatch"):
        kernel.consume(blank, owner="o", run="r")


def test_mac_args_hash_mismatch_denied() -> None:
    import dataclasses

    kernel = GateKernel(b"k" * 32)
    plane = PolicyPlane("o", "s", "r", "tool", frozenset({"private.read"}), 1)
    ticket = kernel.issue(plane, lease_id="lease-ma", args_hash="args-1")
    bad = dataclasses.replace(ticket, args_hash="args-2")
    with pytest.raises(TicketDenied, match="MAC mismatch"):
        kernel.consume(bad, owner="o", run="r")


def test_cred_exchange_is_single_use() -> None:
    broker = CredBroker(b"k" * 32, allowed_hosts=frozenset({"api.example"}))
    token = broker.issue("o", "api.example", b"sk-test")
    assert broker.exchange(token, owner="o", host="api.example") == b"sk-test"
    with pytest.raises(CredBrokerDenied, match="already spent"):
        broker.exchange(token, owner="o", host="api.example")


def test_conjunction_lethal_ticket() -> None:
    kernel = GateKernel(b"k" * 32)
    with pytest.raises(ConjunctionDenied, match="unsatisfiable"):
        kernel.issue(
            PolicyPlane(
                "o",
                "s",
                "r",
                "tool",
                frozenset({"private.read", "web.read", "egress.send"}),
                1,
            ),
            lease_id="lease-lethal",
        )


def test_synthetic_path_file_web_egress_denied() -> None:
    grants = grants_for_tool(
        "send_mail", resource_scope="private inbox", context_taint=WEB_CONTENT
    )
    with pytest.raises(ConjunctionDenied, match="unsatisfiable"):
        require_conjunction(grants)


def test_orin_guard_process_never_opens_echo_ledger() -> None:
    """orin-guard must not open or append the Echo host ledger."""

    offenders: list[str] = []
    banned = (
        "FileEchoLedger",
        "echo_tool_lease.jsonl",
        "stamp_receipt",
        "LedgerAppendPort",
        "append_stamp",
    )
    for path in sorted(ORIN_GUARD_ROOT.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        for token in banned:
            if token in text:
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{token}")
    assert offenders == []


def test_production_build_strips_orin_allow_ambient() -> None:
    offenders: list[str] = []
    for root in (ORIN_GUARD_ROOT, ECHO_CORE_ROOT):
        for path in sorted(root.rglob("*.py")):
            if "ORIN_ALLOW_AMBIENT" in path.read_text(encoding="utf-8"):
                offenders.append(str(path.relative_to(REPO_ROOT)))
    assert offenders == []


def test_orin_allow_ambient_env_ignored_still_denies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ORIN_ALLOW_AMBIENT", "1")
    assert os.environ.get("ORIN_ALLOW_AMBIENT") == "1"
    with pytest.raises(ConjunctionDenied):
        require_conjunction(frozenset({"private.read", "web.read", "egress.send"}))
    with pytest.raises(GuardianDenied):
        NullGuardian().stamp(
            owner="o",
            session="s",
            run="r",
            effect_class="tool",
            grants=frozenset({"private.read"}),
            budget=1,
            lease_id="ambient-lease",
        )


def test_crash_between_lease_and_ticket_consume_lease_spent_ticket_live(
    tmp_path: Path,
) -> None:
    """Lease/ticket crash window: guardian ticket burned while lease still STAMPED."""

    auth = _authority(tmp_path)
    auth.issue(_proposal(), lease_id="lease-crash-1")
    stamped = auth.stamp("lease-crash-1")
    # Out-of-band ticket consume (crash before durable lease consume receipt).
    auth.guardian.consume(stamped.stamp_id, owner="owner-a", run="run-a")
    with pytest.raises(GuardianDenied):
        auth.consume("lease-crash-1")
    with pytest.raises(EffectAuthorityError, match="lease receipt"):
        auth.require_exec("lease-crash-1")


def test_crash_between_ticket_and_lease_consume_ticket_spent_lease_live(
    tmp_path: Path,
) -> None:
    """Sibling crash window: durable lease consume must not leave a reusable ticket."""

    auth = _authority(tmp_path)
    auth.issue(_proposal(), lease_id="lease-crash-2")
    stamped = auth.stamp("lease-crash-2")
    auth.consume("lease-crash-2")
    with pytest.raises(GuardianDenied):
        auth.guardian.consume(stamped.stamp_id, owner="owner-a", run="run-a")


def test_shadow_cannot_rewrite_verdict(tmp_path: Path) -> None:
    """Shadow mode may observe denies; it must not flip them to allow."""

    store = OrinStore(tmp_path / "orin.db")
    gate = GateKeeper(
        mac_key=b"k" * 32,
        ledger_path=tmp_path / "echo_tool_lease.jsonl",
        store=store,
        key_dir=tmp_path / "keys",
        shadow_mode=True,
    )
    decision = gate._evaluate_policy(  # noqa: SLF001 - contract pin
        tool_name="shell_exec",
        context_taint=WEB_CONTENT,
        arg_taint_bits=WEB_CONTENT,
        args_overlap_dirty=True,
        clearance=0,
    )
    assert decision.verdict != policy_mod.VERDICT_ALLOW
    assert not str(decision.reason).startswith("shadow:")


def test_lease_authority_not_hosted_in_orind() -> None:
    """LeaseAuthority class must live in echo-core, not be redefined under orind."""

    from echo_core.capability import LeaseAuthority

    assert LeaseAuthority.__module__.startswith("echo_core")
    offenders: list[str] = []
    for path in sorted((REPO_ROOT / "js" / "orind").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name == "LeaseAuthority":
                offenders.append(str(path.relative_to(REPO_ROOT)))
    assert offenders == []
    for path in sorted(ORIN_GUARD_ROOT.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name == "LeaseAuthority":
                offenders.append(str(path.relative_to(REPO_ROOT)))
    assert offenders == []


def test_tool_effect_empty_lease_id_denied() -> None:
    kernel = GateKernel(b"k" * 32)
    with pytest.raises(TicketDenied, match="lease_id"):
        kernel.issue(
            PolicyPlane("o", "s", "r", "tool", frozenset({"private.read"}), 1),
            lease_id="",
        )


def test_open_packages_ship_standalone_mit_license() -> None:
    """orin-guard / orin-proto / echo-core each carry MIT for independent publish."""

    for rel in (
        "packages/orin-guard/LICENSE",
        "packages/orin-proto/LICENSE",
        "packages/echo-core/LICENSE",
    ):
        path = REPO_ROOT / rel
        text = path.read_text(encoding="utf-8")
        assert "MIT License" in text
        assert "Permission is hereby granted" in text


def test_no_public_effect_ticket_symbol() -> None:
    """Frozen: EffectTicket stays GateKernel-internal; no dual-ticket public API."""

    import orin_guard

    assert "EffectTicket" not in orin_guard.__all__
    assert not hasattr(orin_guard, "EffectTicket")


def test_orin_guard_declares_echo_core_hard_dependency() -> None:
    """No stub: echo-core remains a required peer of orin-guard."""

    text = (REPO_ROOT / "packages" / "orin-guard" / "pyproject.toml").read_text(
        encoding="utf-8"
    )
    assert "echo-core==3.0.0" in text
    assert "orin-proto==2.0.0" in text


def test_connector_effect_empty_lease_id_denied() -> None:
    kernel = GateKernel(b"k" * 32)
    with pytest.raises(TicketDenied, match="lease_id"):
        kernel.issue(
            PolicyPlane("o", "s", "r", "connector", frozenset({"private.read"}), 1),
            lease_id="",
        )


def test_mac_lease_id_mismatch_denied() -> None:
    import dataclasses

    kernel = GateKernel(b"k" * 32)
    plane = PolicyPlane("o", "s", "r", "tool", frozenset({"private.read"}), 1)
    ticket = kernel.issue(plane, lease_id="lease-ml", args_hash="args-1")
    bad = dataclasses.replace(ticket, lease_id="lease-forged")
    with pytest.raises(TicketDenied, match="MAC mismatch"):
        kernel.consume(bad, owner="o", run="r")


def test_chat_only_ticket_id_pinned_by_gatekernel() -> None:
    from orin_guard.kernel.gate import CHAT_ONLY_TICKET_PREFIX

    kernel = GateKernel(b"k" * 32)
    lease = f"{CHAT_ONLY_TICKET_PREFIX}chat-contract-1"
    ticket = kernel.issue(
        PolicyPlane("o", "s", "r", "model", frozenset({"private.read"}), 1),
        lease_id=lease,
    )
    assert ticket.ticket_id == lease
    assert ticket.lease_id == lease
