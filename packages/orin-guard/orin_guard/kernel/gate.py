"""GateKernel — issue / consume / freeze. ``enforce`` defaults True."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from typing import Final

from orin_guard.kernel.conjunction import require_conjunction
from orin_guard.kernel.dual import PolicyPlane

ALLOWED_EFFECTS: Final[frozenset[str]] = frozenset(
    {"tool", "model", "connector", "learn.tighten", "learn.note", "learn.widen"}
)


class KernelUnavailable(RuntimeError):
    """enforce=True and the kernel cannot serve; fail closed."""


class TicketDenied(PermissionError):
    """Issue or consume refused."""


@dataclass(frozen=True, slots=True)
class EffectTicket:
    ticket_id: str
    owner: str
    session: str
    run: str
    effect_class: str
    grants: frozenset[str]
    mac: str
    expires_at: float
    nonce: str


class GateKernel:
    """Deterministic stamp authority. No LLM on the decision path."""

    def __init__(self, mac_key: bytes, *, enforce: bool = True) -> None:
        if len(mac_key) < 32:
            raise ValueError("mac_key must be at least 32 bytes")
        self._key = mac_key
        self.enforce = enforce
        self._live: dict[str, EffectTicket] = {}
        self._consumed: set[str] = set()
        self._frozen = False

    def issue(self, plane: PolicyPlane, *, now: float | None = None) -> EffectTicket:
        if self._frozen and self.enforce:
            raise KernelUnavailable("kernel is frozen")
        if plane.budget < 1:
            raise TicketDenied("budget < 1")
        if plane.effect_class not in ALLOWED_EFFECTS:
            raise TicketDenied("effect_class is not registered")
        require_conjunction(plane.grants)
        if plane.effect_class == "learn.widen" and not plane.grants:
            raise TicketDenied("learn.widen requires an explicit owner grant")
        stamp = now if now is not None else time.time()
        nonce = secrets.token_hex(16)
        ticket_id = hashlib.sha256(f"{plane.owner}:{plane.run}:{nonce}".encode()).hexdigest()
        mac = hmac.new(
            self._key,
            f"{ticket_id}:{plane.owner}:{plane.run}:{plane.effect_class}".encode(),
            hashlib.sha256,
        ).hexdigest()
        ticket = EffectTicket(
            ticket_id=ticket_id,
            owner=plane.owner,
            session=plane.session,
            run=plane.run,
            effect_class=plane.effect_class,
            grants=plane.grants,
            mac=mac,
            expires_at=stamp + 300.0,
            nonce=nonce,
        )
        self._live[ticket_id] = ticket
        return ticket

    def consume(
        self, ticket: EffectTicket, *, run: str, owner: str, now: float | None = None
    ) -> str:
        if self._frozen and self.enforce:
            raise KernelUnavailable("kernel is frozen")
        stored = self._live.get(ticket.ticket_id)
        if stored is None or ticket.ticket_id in self._consumed:
            raise TicketDenied("ticket missing or already consumed")
        stamp = now if now is not None else time.time()
        if stamp > stored.expires_at:
            self._live.pop(ticket.ticket_id, None)
            raise TicketDenied("ticket expired")
        if stored.run != run or stored.owner != owner:
            raise TicketDenied("ticket owner/run mismatch")
        expected = hmac.new(
            self._key,
            f"{stored.ticket_id}:{stored.owner}:{stored.run}:{stored.effect_class}".encode(),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(stored.mac, expected) or not hmac.compare_digest(
            ticket.mac, expected
        ):
            raise TicketDenied("ticket MAC mismatch")
        self._consumed.add(ticket.ticket_id)
        self._live.pop(ticket.ticket_id, None)
        return hashlib.sha256(f"receipt:{ticket.ticket_id}".encode()).hexdigest()

    def freeze(self) -> None:
        self._frozen = True


__all__ = [
    "ALLOWED_EFFECTS",
    "EffectTicket",
    "GateKernel",
    "KernelUnavailable",
    "TicketDenied",
]
