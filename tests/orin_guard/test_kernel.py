"""orin-guard kernel tests."""

from __future__ import annotations

import os

import pytest
from echo_core.taint import SECRET, WEB_CONTENT
from orin_guard.broker.cred import CredBroker, CredBrokerDenied
from orin_guard.cells.config import CellConfigDenied, validate_bind_mounts, validate_network
from orin_guard.kernel.conjunction import ConjunctionDenied, require_conjunction
from orin_guard.kernel.dual import PolicyPlane, reject_observation_policy_fields
from orin_guard.kernel.exec_kernel import ExecKernel, ExecKernelDenied, ExecPlan, PlanStep
from orin_guard.kernel.exec_parse import ExecParseDenied, prefer_argv, reject_lexical_bypass
from orin_guard.kernel.gate import GateKernel, TicketDenied
from orin_guard.kernel.grants import grants_for_tool
from orin_guard.kernel.identity import IdentityDenied, resolve_allowlist_identity
from orin_guard.kernel.ifc import IFCDenied, IFCEngine
from orin_guard.kernel.peer import PeerDenied, authenticate_peer
from orin_guard.mcp.gate import MCPGate, MCPGateDenied


def test_lethal_trifecta_hard_deny() -> None:
    with pytest.raises(ConjunctionDenied, match="unsatisfiable"):
        require_conjunction(frozenset({"private.read", "web.read", "egress.send"}))
    require_conjunction(frozenset({"private.read", "web.read"}))


def test_gate_kernel_single_use() -> None:
    kernel = GateKernel(b"k" * 32)
    plane = PolicyPlane("o", "s", "r", "tool", frozenset({"private.read"}), 1)
    ticket = kernel.issue(plane)
    kernel.consume(ticket, owner="o", run="r")
    with pytest.raises(TicketDenied):
        kernel.consume(ticket, owner="o", run="r")


def test_gate_kernel_rejects_expired_ticket() -> None:
    kernel = GateKernel(b"k" * 32)
    plane = PolicyPlane("o", "s", "r", "tool", frozenset({"private.read"}), 1)
    ticket = kernel.issue(plane, now=100.0)
    with pytest.raises(TicketDenied, match="expired"):
        kernel.consume(ticket, owner="o", run="r", now=401.0)


def test_gate_kernel_consume_within_ttl() -> None:
    kernel = GateKernel(b"k" * 32)
    plane = PolicyPlane("o", "s", "r", "tool", frozenset({"private.read"}), 1)
    ticket = kernel.issue(plane, now=100.0)
    receipt = kernel.consume(ticket, owner="o", run="r", now=200.0)
    assert receipt


def test_learn_widen_requires_grant() -> None:
    kernel = GateKernel(b"k" * 32)
    with pytest.raises(TicketDenied, match="owner grant"):
        kernel.issue(PolicyPlane("o", "s", "r", "learn.widen", frozenset(), 1))


def test_exec_kernel_tainted_sink() -> None:
    kernel = ExecKernel()
    with pytest.raises(ExecKernelDenied):
        kernel.check(
            ExecPlan(steps=(PlanStep("browser_fetch", slot_taint=WEB_CONTENT),), privileged=True)
        )
    with pytest.raises(ExecKernelDenied):
        kernel.check(ExecPlan(steps=(PlanStep("file_read"),), privileged=False))


def test_ifc_secret_cannot_egress() -> None:
    engine = IFCEngine()
    label = engine.label_from_taint(SECRET, provenance="vault")
    with pytest.raises(IFCDenied):
        engine.check_flow(label, "net_egress")


def test_cred_broker_opaque_only() -> None:
    broker = CredBroker(b"k" * 32, allowed_hosts=frozenset({"api.example"}))
    token = broker.issue("o", "api.example", b"real-key")
    assert b"real-key" not in token.token_id.encode()
    assert broker.exchange(token, owner="o", host="api.example") == b"real-key"
    with pytest.raises(CredBrokerDenied):
        broker.issue("o", "evil.example", b"x")


def test_mcp_no_force_and_pin_drift() -> None:
    gate = MCPGate()
    gate.pin("browser", '{"name":"browser"}')
    with pytest.raises(MCPGateDenied, match="drifted"):
        gate.pin("browser", '{"name":"browser","extra":1}')
    with pytest.raises(MCPGateDenied, match="no --force"):
        gate.assert_unforced(force=True)


def test_identity_ignores_display_name() -> None:
    ident = resolve_allowlist_identity(
        platform="telegram",
        immutable_id="42",
        display_name="admin",
        allow_ids=frozenset({"42"}),
    )
    assert ident.immutable_id == "42"
    with pytest.raises(IdentityDenied):
        resolve_allowlist_identity(
            platform="telegram",
            immutable_id="admin",
            display_name="42",
            allow_ids=frozenset({"42"}),
        )


def test_exec_parse_rejects_tricks() -> None:
    with pytest.raises(ExecParseDenied):
        reject_lexical_bypass("echo hello \\\n world")
    with pytest.raises(ExecParseDenied):
        reject_lexical_bypass("busybox sh")
    with pytest.raises(ExecParseDenied):
        reject_lexical_bypass("tar --compress-prog")

    assert prefer_argv(("ls", "-l")) == ("ls", "-l")
    with pytest.raises(ExecParseDenied):
        prefer_argv(())


def test_peer_loopback_is_not_identity() -> None:
    uid = os.getuid()
    authenticate_peer(
        uid=uid,
        pid=os.getpid(),
        allowed_uids=frozenset({uid}),
        allowed_pids=frozenset({os.getpid()}),
        loopback=True,
    )
    with pytest.raises(PeerDenied):
        authenticate_peer(
            uid=uid + 1,
            pid=os.getpid(),
            allowed_uids=frozenset({uid}),
            allowed_pids=frozenset({os.getpid()}),
            loopback=True,
        )


def test_observation_cannot_carry_policy() -> None:
    with pytest.raises(Exception, match="policy"):
        reject_observation_policy_fields({"grants": ["egress.send"]})


def test_cell_config_rejects_host_ns() -> None:
    with pytest.raises(CellConfigDenied):
        validate_network("host")
    with pytest.raises(CellConfigDenied):
        validate_bind_mounts(("/etc:/etc",))


def test_grants_for_send_mail_with_web_and_private() -> None:
    grants = grants_for_tool("send_mail", resource_scope="private inbox", context_taint=WEB_CONTENT)
    with pytest.raises(ConjunctionDenied):
        require_conjunction(grants)
