"""Package-local Orin 2.0 pins using frozen architecture contract names."""

from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest
from echo_core.taint import WEB_CONTENT
from orin_guard.broker.cred import CredBroker, CredBrokerDenied
from orin_guard.kernel.conjunction import ConjunctionDenied, require_conjunction
from orin_guard.kernel.dual import PolicyPlane
from orin_guard.kernel.gate import EffectTicket, GateKernel, TicketDenied, grants_digest
from orin_guard.kernel.grants import grants_for_tool

PACKAGE_ROOT = Path(__file__).resolve().parents[1]


def _plane(
    grants: frozenset[str] | None = None,
    *,
    effect_class: str = "tool",
) -> PolicyPlane:
    return PolicyPlane(
        "o",
        "s",
        "r",
        effect_class,
        grants if grants is not None else frozenset({"private.read"}),
        1,
    )


def test_consume_before_stamp_denied() -> None:
    kernel = GateKernel(b"k" * 32)
    forged = EffectTicket(
        ticket_id="deadbeef" * 8,
        owner="o",
        session="s",
        run="r",
        effect_class="tool",
        grants=frozenset({"private.read"}),
        mac="0" * 64,
        expires_at=9_999_999_999.0,
        nonce="00",
        grants_digest=grants_digest(frozenset({"private.read"})),
        args_hash="",
        lease_id="lease-forged",
    )
    with pytest.raises(TicketDenied, match="consume-before-stamp"):
        kernel.consume(forged, owner="o", run="r")


def test_mac_missing_grants_digest_denied() -> None:
    kernel = GateKernel(b"k" * 32)
    ticket = kernel.issue(_plane(), lease_id="lease-g", args_hash="args")
    blank = dataclasses.replace(ticket, grants_digest="")
    with pytest.raises(TicketDenied, match="MAC mismatch"):
        kernel.consume(blank, owner="o", run="r")


def test_mac_args_hash_mismatch_denied() -> None:
    kernel = GateKernel(b"k" * 32)
    ticket = kernel.issue(_plane(), lease_id="lease-a", args_hash="sha256:" + "a" * 64)
    tampered = dataclasses.replace(ticket, args_hash="sha256:" + "b" * 64)
    with pytest.raises(TicketDenied, match="MAC mismatch"):
        kernel.consume(tampered, owner="o", run="r")


def test_cred_exchange_is_single_use() -> None:
    broker = CredBroker(b"k" * 32, allowed_hosts=frozenset({"api.example"}))
    token = broker.issue("o", "api.example", b"real-key")
    assert broker.exchange(token, owner="o", host="api.example") == b"real-key"
    with pytest.raises(CredBrokerDenied, match="already spent"):
        broker.exchange(token, owner="o", host="api.example")


def test_conjunction_lethal_ticket() -> None:
    kernel = GateKernel(b"k" * 32)
    with pytest.raises(ConjunctionDenied, match="unsatisfiable"):
        kernel.issue(
            _plane(frozenset({"private.read", "web.read", "egress.send"})),
            lease_id="lease-lethal",
        )


def test_synthetic_path_file_web_egress_denied() -> None:
    grants = grants_for_tool(
        "send_mail", resource_scope="private inbox", context_taint=WEB_CONTENT
    )
    with pytest.raises(ConjunctionDenied, match="unsatisfiable"):
        require_conjunction(grants)


def test_tool_effect_empty_lease_id_denied() -> None:
    kernel = GateKernel(b"k" * 32)
    with pytest.raises(TicketDenied, match="lease_id"):
        kernel.issue(_plane(effect_class="tool"), lease_id="")
    # Model tickets are not lease-bound at GateKernel.
    model = kernel.issue(_plane(effect_class="model"), lease_id="")
    assert model.effect_class == "model"


def test_connector_effect_empty_lease_id_denied() -> None:
    kernel = GateKernel(b"k" * 32)
    with pytest.raises(TicketDenied, match="lease_id"):
        kernel.issue(_plane(effect_class="connector"), lease_id="")


def test_mac_lease_id_mismatch_denied() -> None:
    kernel = GateKernel(b"k" * 32)
    ticket = kernel.issue(_plane(), lease_id="lease-bound", args_hash="args-1")
    tampered = dataclasses.replace(ticket, lease_id="lease-other")
    with pytest.raises(TicketDenied, match="MAC mismatch"):
        kernel.consume(tampered, owner="o", run="r")


def test_chat_only_ticket_id_pinned_by_gatekernel() -> None:
    from orin_guard.kernel.gate import CHAT_ONLY_TICKET_PREFIX

    kernel = GateKernel(b"k" * 32)
    lease = f"{CHAT_ONLY_TICKET_PREFIX}chat-oss-1"
    ticket = kernel.issue(_plane(effect_class="model"), lease_id=lease)
    assert ticket.ticket_id == lease
    assert ticket.lease_id == lease
    kernel.consume(ticket, owner="o", run="r")


def test_stored_expires_at_enforced() -> None:
    kernel = GateKernel(b"k" * 32)
    ticket = kernel.issue(_plane(), lease_id="lease-exp", now=100.0)
    assert ticket.expires_at == 400.0
    forged = dataclasses.replace(ticket, expires_at=10_000.0)
    with pytest.raises(TicketDenied, match="expired"):
        kernel.consume(forged, owner="o", run="r", now=401.0)


def test_single_use_ticket() -> None:
    kernel = GateKernel(b"k" * 32)
    ticket = kernel.issue(_plane(), lease_id="lease-once")
    kernel.consume(ticket, owner="o", run="r")
    with pytest.raises(TicketDenied, match="already consumed"):
        kernel.consume(ticket, owner="o", run="r")


def test_production_build_strips_orin_allow_ambient() -> None:
    """Production package sources must not reference ORIN_ALLOW_AMBIENT."""

    root = PACKAGE_ROOT / "orin_guard"
    offenders: list[str] = []
    for path in sorted(root.rglob("*.py")):
        if "ORIN_ALLOW_AMBIENT" in path.read_text(encoding="utf-8"):
            offenders.append(str(path.relative_to(PACKAGE_ROOT)))
    assert offenders == []


def test_orin_allow_ambient_env_ignored_still_denies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ORIN_ALLOW_AMBIENT", "1")
    monkeypatch.setenv("ORIN_ALLOW_AMBIENT", "true")
    with pytest.raises(ConjunctionDenied, match="unsatisfiable"):
        require_conjunction(frozenset({"private.read", "web.read", "egress.send"}))
    kernel = GateKernel(b"k" * 32)
    with pytest.raises(TicketDenied, match="lease_id"):
        kernel.issue(_plane(), lease_id="")


def test_conjunction_has_no_timeout_or_yolo_allow_hatch() -> None:
    """timeout / scanner-unavailable / ambient hatches must never flip deny → allow."""

    root = PACKAGE_ROOT / "orin_guard"
    # Hatch identifiers only — prose that says "no YOLO" is fine.
    banned = (
        "ORIN_ALLOW_AMBIENT",
        "ALLOW_ON_TIMEOUT",
        "timeout_allow",
        "scanner_unavailable_allow",
        "yolo_allow",
        "YOLO_ALLOW",
    )
    offenders: list[str] = []
    for path in sorted(root.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        for token in banned:
            if token in text:
                offenders.append(f"{path.relative_to(PACKAGE_ROOT)}:{token}")
    assert offenders == []
    with pytest.raises(ConjunctionDenied, match="unsatisfiable"):
        require_conjunction(frozenset({"private.read", "web.read", "egress.send"}))


def test_orin_guard_tests_has_no_init_py() -> None:
    """Package tests must not ship ``__init__.py`` (shadows repo ``tests``)."""

    assert not (PACKAGE_ROOT / "tests" / "__init__.py").exists()


def test_package_ships_standalone_mit_license() -> None:
    """Independent publish must not rely on the monorepo root LICENSE only."""

    license_path = PACKAGE_ROOT / "LICENSE"
    text = license_path.read_text(encoding="utf-8")
    assert license_path.is_file()
    assert "MIT License" in text
    assert "Permission is hereby granted" in text
    notices = PACKAGE_ROOT / "THIRD_PARTY_NOTICES.md"
    assert notices.is_file()
    assert "echo-core" in notices.read_text(encoding="utf-8")


def test_frozen_kernel_denies_when_enforce() -> None:
    from orin_guard.kernel.gate import KernelUnavailable

    kernel = GateKernel(b"k" * 32, enforce=True)
    kernel.freeze()
    with pytest.raises(KernelUnavailable, match="frozen"):
        kernel.issue(_plane(), lease_id="lease-frozen")
