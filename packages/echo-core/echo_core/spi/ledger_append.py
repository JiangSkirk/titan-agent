"""LedgerAppendPort — Host-only stamp receipt append.

echo-core declares the port. Only a Host adapter may hold a journal fd and
append ``STAMPED`` receipts. The Interpreter must not implement this port.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class LedgerAppendPort(Protocol):
    """Host-owned durable append for guardian stamp receipts."""

    def append(
        self,
        *,
        record_type: str,
        tenant_id: str,
        run_id: str,
        payload: dict[str, Any],
    ) -> Any:
        """Persist one stamp/effect authority row. Fail closed on I/O errors."""
        ...


__all__ = ["LedgerAppendPort"]
