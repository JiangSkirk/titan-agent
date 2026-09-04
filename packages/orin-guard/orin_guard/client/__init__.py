"""orin-guard client stub — Hosts wire this; the daemon holds keys."""

from __future__ import annotations

from orin_guard.kernel.dual import PolicyPlane
from orin_guard.kernel.gate import EffectTicket, GateKernel


class GuardClient:
    def __init__(self, kernel: GateKernel) -> None:
        self._kernel = kernel

    def issue(self, plane: PolicyPlane) -> EffectTicket:
        return self._kernel.issue(plane)

    def consume(self, ticket: EffectTicket, *, owner: str, run: str) -> str:
        return self._kernel.consume(ticket, owner=owner, run=run)


__all__ = ["GuardClient"]
