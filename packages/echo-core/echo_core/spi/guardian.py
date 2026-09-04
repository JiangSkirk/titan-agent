"""GuardianSPI — Echo proposes, a host-wired guardian stamps.

echo-core never imports orin-guard. A Host (js-agent or any embedder) binds
an implementation. ``NullGuardian`` is fail-closed: it never grants.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


class GuardianDenied(PermissionError):
    """The guardian refused to stamp an effect."""


@runtime_checkable
class GuardianSPI(Protocol):
    """Host-injected protection boundary. Decision path must be deterministic."""

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
        """Return an opaque ticket id, or raise GuardianDenied."""
        ...

    def consume(self, ticket_id: str, *, owner: str, run: str) -> None:
        """Single-use consume. Missing/foreign tickets fail closed."""
        ...


class NullGuardian:
    """Fail-closed default: no ambient grants when no guardian is wired."""

    def stamp(self, **_kwargs: Any) -> str:
        raise GuardianDenied("no guardian wired; refuse ambient execution")

    def consume(self, ticket_id: str, *, owner: str, run: str) -> None:
        raise GuardianDenied("no guardian wired; refuse ambient execution")


__all__ = ["GuardianDenied", "GuardianSPI", "NullGuardian"]
