"""Dual planes: policy is owner-written; observation cannot become grants."""

from __future__ import annotations

from dataclasses import dataclass


class PlaneViolation(PermissionError):
    """Observation text tried to write a policy field."""


_POLICY_KEYS = frozenset(
    {
        "grants",
        "effect_class",
        "budget",
        "owner",
        "session",
        "run",
        "policy_profile",
        "orin",
    }
)


@dataclass(frozen=True, slots=True)
class PolicyPlane:
    owner: str
    session: str
    run: str
    effect_class: str
    grants: frozenset[str]
    budget: int


@dataclass(frozen=True, slots=True)
class ObservationPlane:
    text: str
    taint: int = 0


def reject_observation_policy_fields(payload: dict[str, object] | None) -> None:
    """Refuse any observation dict that carries policy keys."""

    if not isinstance(payload, dict):
        return
    for key in payload:
        if str(key).strip() in _POLICY_KEYS:
            raise PlaneViolation("observation plane cannot carry policy fields")


__all__ = [
    "ObservationPlane",
    "PlaneViolation",
    "PolicyPlane",
    "reject_observation_policy_fields",
]
