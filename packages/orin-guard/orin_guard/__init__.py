"""orin-guard public surface. Does not import ``js.*``.

GateKernel is an Echo sidecar stamp authority — not a runtime, ledger
writer, or orchestrator. See package README for the openable API.

``EffectTicket`` is GateKernel-internal only and is **not** exported here.
The public capability ticket is Echo ``CapabilityLease``.
"""

from __future__ import annotations

from orin_guard.broker.cred import CredBroker, CredBrokerDenied
from orin_guard.kernel.conjunction import (
    ConjunctionDenied,
    check_conjunction,
    require_conjunction,
)
from orin_guard.kernel.dual import PolicyPlane
from orin_guard.kernel.gate import (
    CHAT_ONLY_TICKET_PREFIX,
    GateKernel,
    KernelUnavailable,
    TicketDenied,
    grants_digest,
)
from orin_guard.mcp.gate import MCPGate, MCPGateDenied

__all__ = [
    "CHAT_ONLY_TICKET_PREFIX",
    "ConjunctionDenied",
    "CredBroker",
    "CredBrokerDenied",
    "GateKernel",
    "KernelUnavailable",
    "MCPGate",
    "MCPGateDenied",
    "PolicyPlane",
    "TicketDenied",
    "check_conjunction",
    "grants_digest",
    "require_conjunction",
]
