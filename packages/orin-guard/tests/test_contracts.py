"""Package-local Orin 2.0 contract tests (C1–C23 coverage anchors)."""

from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest
from orin_guard.broker.cred import CredBroker, CredBrokerDenied
from orin_guard.kernel.conjunction import ConjunctionDenied, require_conjunction
from orin_guard.kernel.dual import PolicyPlane
from orin_guard.kernel.gate import EffectTicket, GateKernel, TicketDenied, grants_digest

PACKAGE_ROOT = Path(__file__).resolve().parents[1]


def _plane(grants: frozenset[str] | None = None) -> PolicyPlane:
    return PolicyPlane(
        "o",
        "s",
        "r",
        "tool",
        grants if grants is not None else frozenset({"private.read"}),
        1,
    )


def test_c1_single_use_ticket() -> None:
    kernel = GateKernel(b"k" * 32)
    ticket = kernel.issue(_plane())
    kernel.consume(ticket, owner="o", run="r")
    with pytest.raises(TicketDenied, match="already consumed"):
        kernel.consume(ticket, owner="o", run="r")


def test_c2_stored_expires_at() -> None:
    kernel = GateKernel(b"k" * 32)
    ticket = kernel.issue(_plane(), now=100.0)
    assert ticket.expires_at == 400.0
    # Mutating a presented copy cannot extend the stored expiry.
    forged = dataclasses.replace(ticket, expires_at=10_000.0)
    with pytest.raises(TicketDenied, match="expired"):
        kernel.consume(forged, owner="o", run="r", now=401.0)


def test_c3_consume_before_stamp_denied() -> None:
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
        lease_id="",
    )
    with pytest.raises(TicketDenied, match="consume-before-stamp"):
        kernel.consume(forged, owner="o", run="r")


def test_c4_conjunction_lethal() -> None:
    with pytest.raises(ConjunctionDenied, match="unsatisfiable"):
        require_conjunction(frozenset({"private.read", "web.read", "egress.send"}))


def test_c6_mac_mismatch() -> None:
    kernel = GateKernel(b"k" * 32)
    ticket = kernel.issue(_plane(), args_hash="args-a", lease_id="lease-a")
    tampered = dataclasses.replace(ticket, mac="ff" * 32)
    with pytest.raises(TicketDenied, match="MAC mismatch"):
        kernel.consume(tampered, owner="o", run="r")


def test_c7_c8_c9_mac_binds_grants_args_lease() -> None:
    kernel = GateKernel(b"k" * 32)
    grants = frozenset({"private.read"})
    ticket = kernel.issue(
        _plane(grants),
        args_hash="sha256:" + "a" * 64,
        lease_id="lease-bound",
    )
    assert ticket.grants_digest == grants_digest(grants)
    assert ticket.args_hash == "sha256:" + "a" * 64
    assert ticket.lease_id == "lease-bound"

    wrong_grants = dataclasses.replace(
        ticket, grants_digest=grants_digest(frozenset({"web.read"}))
    )
    with pytest.raises(TicketDenied, match="MAC mismatch"):
        kernel.consume(wrong_grants, owner="o", run="r")

    ticket2 = kernel.issue(
        _plane(grants),
        args_hash="sha256:" + "b" * 64,
        lease_id="lease-bound-2",
    )
    wrong_args = dataclasses.replace(ticket2, args_hash="sha256:" + "c" * 64)
    with pytest.raises(TicketDenied, match="MAC mismatch"):
        kernel.consume(wrong_args, owner="o", run="r")

    ticket3 = kernel.issue(
        _plane(grants),
        args_hash="sha256:" + "d" * 64,
        lease_id="lease-bound-3",
    )
    wrong_lease = dataclasses.replace(ticket3, lease_id="lease-other")
    with pytest.raises(TicketDenied, match="MAC mismatch"):
        kernel.consume(wrong_lease, owner="o", run="r")

    ok = kernel.issue(
        _plane(grants),
        args_hash="sha256:" + "e" * 64,
        lease_id="lease-ok",
    )
    assert kernel.consume(ok, owner="o", run="r")


def test_c10_credbroker_single_use() -> None:
    broker = CredBroker(b"k" * 32, allowed_hosts=frozenset({"api.example"}))
    token = broker.issue("o", "api.example", b"real-key")
    assert broker.exchange(token, owner="o", host="api.example") == b"real-key"
    with pytest.raises(CredBrokerDenied, match="already spent"):
        broker.exchange(token, owner="o", host="api.example")


def test_c16_no_orin_allow_ambient_escape() -> None:
    """Package must not ship an ORIN_ALLOW_AMBIENT product escape hatch."""

    root = PACKAGE_ROOT / "orin_guard"
    offenders: list[str] = []
    for path in sorted(root.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        if "ORIN_ALLOW_AMBIENT" in text:
            offenders.append(str(path.relative_to(PACKAGE_ROOT)))
    assert offenders == []
