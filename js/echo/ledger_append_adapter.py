"""Host LedgerAppendPort backed by FileEchoLedger.

Only this Host adapter (and equivalent Hosts) may hold the journal fd used for
guardian stamp receipts. echo-core Interpreter must not open the journal.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from echo_core.ledger.journal import CommitRecord, FileEchoLedger


class FileEchoLedgerAppend:
    """``LedgerAppendPort`` implementation owned by the Host."""

    def __init__(self, ledger: FileEchoLedger) -> None:
        self._ledger = ledger

    def append(
        self,
        *,
        record_type: str,
        tenant_id: str,
        run_id: str,
        payload: dict[str, Any],
    ) -> CommitRecord:
        return self._ledger.append(
            record_type=record_type,
            tenant_id=tenant_id,
            run_id=run_id,
            payload=payload,
        )


__all__ = ["FileEchoLedgerAppend"]
