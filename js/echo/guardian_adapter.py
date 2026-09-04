"""Host glue: Echo proposes, orin-guard GateKernel stamps.

echo-core never imports orin-guard. This adapter is the js-agent SPI binding.
"""

from __future__ import annotations

from echo_core.spi.guardian import GuardianDenied, GuardianSPI
from orin_guard.kernel.dual import PolicyPlane
from orin_guard.kernel.gate import EffectTicket, GateKernel, KernelUnavailable, TicketDenied


class OrinGuardian:
    """``GuardianSPI`` backed by an in-process GateKernel (tests / Stage A)."""

    def __init__(self, kernel: GateKernel) -> None:
        self._kernel = kernel
        self._tickets: dict[str, EffectTicket] = {}

    def stamp(
        self,
        *,
        owner: str,
        session: str,
        run: str,
        effect_class: str,
        grants: frozenset[str],
        budget: int,
        taint: int = 0,
    ) -> str:
        _ = taint
        try:
            ticket = self._kernel.issue(
                PolicyPlane(
                    owner=owner,
                    session=session,
                    run=run,
                    effect_class=effect_class,
                    grants=grants,
                    budget=budget,
                )
            )
        except (TicketDenied, KernelUnavailable) as exc:
            raise GuardianDenied(str(exc)) from exc
        self._tickets[ticket.ticket_id] = ticket
        return ticket.ticket_id

    def consume(self, ticket_id: str, *, owner: str, run: str) -> None:
        ticket = self._tickets.get(ticket_id)
        if ticket is None:
            raise GuardianDenied("ticket missing")
        try:
            self._kernel.consume(ticket, owner=owner, run=run)
        except (TicketDenied, KernelUnavailable) as exc:
            raise GuardianDenied(str(exc)) from exc
        self._tickets.pop(ticket_id, None)


__all__ = ["GuardianDenied", "GuardianSPI", "OrinGuardian"]
