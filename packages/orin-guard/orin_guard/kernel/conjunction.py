"""Lethal-trifecta conjunction kernel.

``private.read ∩ untrusted ∩ egress.send`` is structurally unsatisfiable.
There is no YOLO / timeout / scanner-unavailable path that can turn this
into an allow. Decision path contains no LLM.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

GRANT_PRIVATE_READ: Final[str] = "private.read"
GRANT_UNTRUSTED: Final[str] = "web.read"
GRANT_EGRESS: Final[str] = "egress.send"

LETHAL: Final[frozenset[str]] = frozenset({GRANT_PRIVATE_READ, GRANT_UNTRUSTED, GRANT_EGRESS})


class ConjunctionDenied(PermissionError):
    """The lethal trifecta was requested in one ticket."""


@dataclass(frozen=True, slots=True)
class ConjunctionVerdict:
    allowed: bool
    reason: str


def check_conjunction(grants: frozenset[str]) -> ConjunctionVerdict:
    """Return allow/deny. Lethal intersection is always deny."""

    present = LETHAL & grants
    if present == LETHAL:
        return ConjunctionVerdict(
            False,
            "lethal trifecta: private.read ∩ web.read ∩ egress.send is unsatisfiable",
        )
    return ConjunctionVerdict(True, "conjunction ok")


def require_conjunction(grants: frozenset[str]) -> None:
    verdict = check_conjunction(grants)
    if not verdict.allowed:
        raise ConjunctionDenied(verdict.reason)


__all__ = [
    "GRANT_EGRESS",
    "GRANT_PRIVATE_READ",
    "GRANT_UNTRUSTED",
    "LETHAL",
    "ConjunctionDenied",
    "ConjunctionVerdict",
    "check_conjunction",
    "require_conjunction",
]
