"""Fail-closed Echo effect authority (architecture D1).

Authority chain (frozen):

``propose → issue(PENDING lease) → GuardianSPI.stamp →
Host LedgerAppendPort.append(STAMPED) → durable consume → Interpreter.exec``

This module is the stamp/consume gate around effects. It is **not** a second
turn runtime and must not grow a parallel ``run_echo_turn``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Final

from echo_core.spi.guardian import GuardianDenied, GuardianSPI, NullGuardian
from echo_core.spi.ledger_append import LedgerAppendPort

STAMP_RECEIPT_RECORD_TYPE: Final[str] = "stamp_receipt"
LEASE_RECEIPT_RECORD_TYPE: Final[str] = "lease_consume_receipt"


class TicketPhase(StrEnum):
    PENDING = "PENDING"
    STAMPED = "STAMPED"
    CONSUMED = "CONSUMED"


class WiringMode(StrEnum):
    """Host guardian wiring classification.

    Precedence: ``CHAT_ONLY ≻ UNWIRED``.
    ``UNWIRED = enabled=false ∧ ¬chat_only``.
    """

    CHAT_ONLY = "CHAT_ONLY"
    UNWIRED = "UNWIRED"
    WIRED = "WIRED"


class EffectAuthorityError(PermissionError):
    """Effect authority chain refused an operation."""


class BootDenied(RuntimeError):
    """Host boot refused an illegal enabled/enforce combination."""


@dataclass(frozen=True, slots=True)
class EffectProposal:
    owner: str
    session: str
    run: str
    effect_class: str
    grants: frozenset[str]
    budget: int
    taint: int = 0


@dataclass(frozen=True, slots=True)
class PendingLease:
    lease_id: str
    proposal: EffectProposal
    phase: TicketPhase = TicketPhase.PENDING


@dataclass(frozen=True, slots=True)
class StampedLease:
    lease_id: str
    proposal: EffectProposal
    stamp_id: str
    record_hash: str
    phase: TicketPhase = TicketPhase.STAMPED


@dataclass(frozen=True, slots=True)
class LeaseReceipt:
    lease_id: str
    stamp_id: str
    consume_receipt_hash: str
    phase: TicketPhase = TicketPhase.CONSUMED


def classify_wiring(*, enabled: bool, chat_only: bool) -> WiringMode:
    """Classify host wiring. CHAT_ONLY outranks UNWIRED."""

    if chat_only:
        return WiringMode.CHAT_ONLY
    if not enabled:
        return WiringMode.UNWIRED
    return WiringMode.WIRED


def require_boot_ok(*, enabled: bool, enforce: bool) -> None:
    """Fail closed when effects are enabled without enforce."""

    if enabled and not enforce:
        raise BootDenied("enabled without enforce; refuse ambient effect authority")


@dataclass
class EffectAuthority:
    """In-process D1 gate. Host supplies guardian + LedgerAppendPort."""

    guardian: GuardianSPI
    ledger: LedgerAppendPort
    wiring: WiringMode = WiringMode.WIRED
    _live: dict[str, PendingLease | StampedLease | LeaseReceipt] = field(
        default_factory=dict, init=False, repr=False
    )
    _stamp_by_lease: dict[str, str] = field(default_factory=dict, init=False, repr=False)

    def propose(self, proposal: EffectProposal) -> EffectProposal:
        self._deny_if_unwired(effect_class=proposal.effect_class)
        return proposal

    def issue(self, proposal: EffectProposal, *, lease_id: str) -> PendingLease:
        self._deny_if_unwired(effect_class=proposal.effect_class)
        if not lease_id:
            raise EffectAuthorityError("lease_id required")
        if lease_id in self._live:
            raise EffectAuthorityError("lease already issued")
        pending = PendingLease(lease_id=lease_id, proposal=proposal)
        self._live[lease_id] = pending
        return pending

    def stamp(self, lease_id: str) -> StampedLease:
        entry = self._live.get(lease_id)
        if entry is None or entry.phase is not TicketPhase.PENDING:
            raise EffectAuthorityError("stamp requires a PENDING lease")
        assert isinstance(entry, PendingLease)
        proposal = entry.proposal
        self._deny_if_unwired(effect_class=proposal.effect_class)
        stamp_id = self.guardian.stamp(
            owner=proposal.owner,
            session=proposal.session,
            run=proposal.run,
            effect_class=proposal.effect_class,
            grants=proposal.grants,
            budget=proposal.budget,
            taint=proposal.taint,
            lease_id=lease_id,
        )
        record = self.ledger.append(
            record_type=STAMP_RECEIPT_RECORD_TYPE,
            tenant_id=proposal.owner,
            run_id=proposal.run,
            payload={
                "lease_id": lease_id,
                "stamp_id": stamp_id,
                "phase": TicketPhase.STAMPED.value,
                "session": proposal.session,
                "effect_class": proposal.effect_class,
                "grants": sorted(proposal.grants),
            },
        )
        record_hash = getattr(record, "record_hash", None) or str(record)
        stamped = StampedLease(
            lease_id=lease_id,
            proposal=proposal,
            stamp_id=stamp_id,
            record_hash=str(record_hash),
        )
        self._live[lease_id] = stamped
        self._stamp_by_lease[lease_id] = stamp_id
        return stamped

    def consume(self, lease_id: str) -> LeaseReceipt:
        entry = self._live.get(lease_id)
        if entry is None:
            raise EffectAuthorityError("consume requires a live lease")
        if entry.phase is TicketPhase.PENDING:
            raise EffectAuthorityError("consume-before-stamp denied")
        if entry.phase is TicketPhase.CONSUMED:
            raise EffectAuthorityError("lease already consumed")
        if entry.phase is not TicketPhase.STAMPED:
            raise EffectAuthorityError("consume requires STAMPED lease")
        assert isinstance(entry, StampedLease)
        self.guardian.consume(
            entry.stamp_id,
            owner=entry.proposal.owner,
            run=entry.proposal.run,
        )
        record = self.ledger.append(
            record_type=LEASE_RECEIPT_RECORD_TYPE,
            tenant_id=entry.proposal.owner,
            run_id=entry.proposal.run,
            payload={
                "lease_id": lease_id,
                "stamp_id": entry.stamp_id,
                "phase": TicketPhase.CONSUMED.value,
                "stamp_record_hash": entry.record_hash,
            },
        )
        consume_hash = getattr(record, "record_hash", None) or str(record)
        receipt = LeaseReceipt(
            lease_id=lease_id,
            stamp_id=entry.stamp_id,
            consume_receipt_hash=str(consume_hash),
        )
        self._live[lease_id] = receipt
        return receipt

    def require_exec(self, lease_id: str) -> LeaseReceipt:
        """Interpreter preflight: durable consume receipt required."""

        entry = self._live.get(lease_id)
        if entry is None:
            raise EffectAuthorityError("exec without stamp denied")
        if entry.phase is TicketPhase.PENDING:
            raise EffectAuthorityError("exec without stamp denied")
        if entry.phase is TicketPhase.STAMPED:
            raise EffectAuthorityError("ticket missing lease receipt")
        if entry.phase is not TicketPhase.CONSUMED:
            raise EffectAuthorityError("exec without stamp denied")
        assert isinstance(entry, LeaseReceipt)
        return entry

    def hydrate_from_stamped_row(self, payload: dict[str, Any], *, proposal: EffectProposal) -> StampedLease:
        """Rebuild live cache from a durable Echo ledger STAMPED row."""

        lease_id = str(payload.get("lease_id") or "")
        stamp_id = str(payload.get("stamp_id") or "")
        phase = str(payload.get("phase") or "")
        if not lease_id or not stamp_id or phase != TicketPhase.STAMPED.value:
            raise EffectAuthorityError("invalid stamped ledger row")
        stamped = StampedLease(
            lease_id=lease_id,
            proposal=proposal,
            stamp_id=stamp_id,
            record_hash=str(payload.get("record_hash") or stamp_id),
        )
        self._live[lease_id] = stamped
        self._stamp_by_lease[lease_id] = stamp_id
        return stamped

    def forge_pending_stamp_denied(self, lease_id: str, *, forged_stamp_id: str) -> None:
        """CHAT_ONLY / Host path: cannot mint STAMPED without GuardianSPI.stamp."""

        entry = self._live.get(lease_id)
        if entry is None or entry.phase is not TicketPhase.PENDING:
            raise EffectAuthorityError("forge requires PENDING lease")
        # Host writing a forged stamp id into the ledger without guardian.stamp
        # must not promote the live lease.
        if forged_stamp_id and forged_stamp_id not in self._stamp_by_lease.values():
            raise EffectAuthorityError("host cannot forge PENDING stamp")
        raise EffectAuthorityError("host cannot forge PENDING stamp")

    def _deny_if_unwired(self, *, effect_class: str) -> None:
        if self.wiring is WiringMode.UNWIRED:
            if isinstance(self.guardian, NullGuardian) or effect_class in {"tool", "model", "connector"}:
                raise GuardianDenied("unwired guardian; refuse ambient effect")
        if self.wiring is WiringMode.CHAT_ONLY and effect_class in {"tool", "connector"}:
            # Chat-only may stamp model/chat tickets via GateKernel; sinks stay closed.
            if effect_class != "model":
                raise EffectAuthorityError("chat_only path denies sink effects")


def null_unwired_authority() -> EffectAuthority:
    """Fail-closed default when Host has not wired a guardian."""

    class _NoAppend:
        def append(self, **_kwargs: Any) -> Any:
            raise GuardianDenied("unwired; refuse ledger append")

    return EffectAuthority(
        guardian=NullGuardian(),
        ledger=_NoAppend(),
        wiring=WiringMode.UNWIRED,
    )


__all__ = [
    "BootDenied",
    "EffectAuthority",
    "EffectAuthorityError",
    "EffectProposal",
    "LEASE_RECEIPT_RECORD_TYPE",
    "LeaseReceipt",
    "PendingLease",
    "STAMP_RECEIPT_RECORD_TYPE",
    "StampedLease",
    "TicketPhase",
    "WiringMode",
    "classify_wiring",
    "null_unwired_authority",
    "require_boot_ok",
]
