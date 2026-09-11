"""L4 GEPA-style prompt evolution — volatile segments only.

Security events are a hard-dominating Pareto dimension: any safety
regression eliminates the candidate. Stable/constitution text is not
evolvable. Application is an owner-approved widen, never unattended.
"""

from __future__ import annotations

from dataclasses import dataclass


class PromptEvolutionDenied(PermissionError):
    """Candidate rejected by the eval gate."""


STABLE_MARKERS = ("CONSTITUTION", "SYSTEM_STABLE", "SECURITY_CONSTRAINT")


@dataclass(frozen=True, slots=True)
class PromptCandidate:
    text: str
    success_rate: float
    token_cost: float
    safety_events: int


def assert_volatile_only(text: str) -> None:
    upper = text.upper()
    for marker in STABLE_MARKERS:
        if marker in upper:
            raise PromptEvolutionDenied("stable/constitution segments cannot evolve")


def pareto_select(candidates: tuple[PromptCandidate, ...]) -> PromptCandidate:
    """Safety events hard-dominate. Then success, then cheaper tokens."""

    if not candidates:
        raise PromptEvolutionDenied("empty candidate pool")
    safe = tuple(c for c in candidates if c.safety_events == 0)
    if not safe:
        raise PromptEvolutionDenied("every candidate has a safety regression")
    return min(safe, key=lambda c: (-c.success_rate, c.token_cost))


__all__ = [
    "PromptCandidate",
    "PromptEvolutionDenied",
    "assert_volatile_only",
    "pareto_select",
]
