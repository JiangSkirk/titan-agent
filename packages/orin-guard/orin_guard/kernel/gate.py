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
# Tool-class sinks must bind a non-empty lease_id into the stamp MAC.
LEASE_BOUND_EFFECTS: Final[frozenset[str]] = frozenset({"tool", "connector"})


class KernelUnavailable(RuntimeError):
    """enforce=True and the kernel cannot serve; fail closed."""


class TicketDenied(PermissionError):
    """Issue or consume refused."""


def grants_digest(grants: frozenset[str]) -> str:
    """Stable SHA-256 hex digest of a grant set (sorted, comma-joined)."""

    canonical = ",".join(sorted(grants))
    return hashlib.sha256(canonical.encode()).hexdigest()


def _ticket_mac_payload(
    *,
    ticket_id: str,
    owner: str,
    run: str,
    effect_class: str,
    grants_digest_hex: str,
    args_hash: str,
    lease_id: str,
) -> bytes:
    return (
        f"{ticket_id}:{owner}:{run}:{effect_class}:"
        f"{grants_digest_hex}:{args_hash}:{lease_id}"
    ).encode()


def _digest_eq(left: str, right: str) -> bool:
    """Constant-time equality that never raises on unequal lengths."""

    if len(left) != len(right):
        return False
    return hmac.compare_digest(left, right)


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
    grants_digest: str = ""
    args_hash: str = ""
    lease_id: str = ""


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

    def issue(
        self,
        plane: PolicyPlane,
        *,
        now: float | None = None,
        args_hash: str = "",
        lease_id: str = "",
    ) -> EffectTicket:
        if self._frozen and self.enforce:
            raise KernelUnavailable("kernel is frozen")
        if plane.budget < 1:
            raise TicketDenied("budget < 1")
        if plane.effect_class not in ALLOWED_EFFECTS:
            raise TicketDenied("effect_class is not registered")
        if plane.effect_class in LEASE_BOUND_EFFECTS and not lease_id:
            raise TicketDenied("tool-class effect requires non-empty lease_id")
        require_conjunction(plane.grants)
        if plane.effect_class == "learn.widen" and not plane.grants:
            raise TicketDenied("learn.widen requires an explicit owner grant")
        stamp = now if now is not None else time.time()
        nonce = secrets.token_hex(16)
        ticket_id = hashlib.sha256(f"{plane.owner}:{plane.run}:{nonce}".encode()).hexdigest()
        digest = grants_digest(plane.grants)
        mac = hmac.new(
            self._key,
            _ticket_mac_payload(
                ticket_id=ticket_id,
                owner=plane.owner,
                run=plane.run,
                effect_class=plane.effect_class,
                grants_digest_hex=digest,
                args_hash=args_hash,
                lease_id=lease_id,
            ),
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
            grants_digest=digest,
            args_hash=args_hash,
            lease_id=lease_id,
        )
        self._live[ticket_id] = ticket
        return ticket

    def consume(
        self, ticket: EffectTicket, *, run: str, owner: str, now: float | None = None
    ) -> str:
        if self._frozen and self.enforce:
            raise KernelUnavailable("kernel is frozen")
        if ticket.ticket_id in self._consumed:
            raise TicketDenied("ticket missing or already consumed")
        stored = self._live.get(ticket.ticket_id)
        if stored is None:
            # GateKernel.issue is the stamp; consume without a live stamp is denied.
            raise TicketDenied("consume-before-stamp denied")
        stamp = now if now is not None else time.time()
        if stamp > stored.expires_at:
            self._live.pop(ticket.ticket_id, None)
            raise TicketDenied("ticket expired")
        if stored.run != run or stored.owner != owner:
            raise TicketDenied("ticket owner/run mismatch")
        digest = grants_digest(stored.grants)
        if digest != stored.grants_digest:
            raise TicketDenied("ticket MAC mismatch")
        expected = hmac.new(
            self._key,
            _ticket_mac_payload(
                ticket_id=stored.ticket_id,
                owner=stored.owner,
                run=stored.run,
                effect_class=stored.effect_class,
                grants_digest_hex=digest,
                args_hash=stored.args_hash,
                lease_id=stored.lease_id,
            ),
            hashlib.sha256,
        ).hexdigest()
        if not _digest_eq(stored.mac, expected) or not _digest_eq(ticket.mac, expected):
            raise TicketDenied("ticket MAC mismatch")
        if (
            not _digest_eq(ticket.grants_digest, stored.grants_digest)
            or not _digest_eq(ticket.args_hash, stored.args_hash)
            or not _digest_eq(ticket.lease_id, stored.lease_id)
        ):
            raise TicketDenied("ticket MAC mismatch")
        self._consumed.add(ticket.ticket_id)
        self._live.pop(ticket.ticket_id, None)
        return hashlib.sha256(f"receipt:{ticket.ticket_id}".encode()).hexdigest()

    def freeze(self) -> None:
        self._frozen = True


__all__ = [
    "ALLOWED_EFFECTS",
    "LEASE_BOUND_EFFECTS",
    "EffectTicket",
    "GateKernel",
    "KernelUnavailable",
    "TicketDenied",
    "grants_digest",
]
