"""FIDES-style information-flow labels. Deterministic, no LLM."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

from echo_core.taint import SECRET, WEB_CONTENT


class Confidentiality(IntEnum):
    PUBLIC = 0
    INTERNAL = 1
    SECRET = 2


@dataclass(frozen=True, slots=True)
class IFCLabel:
    confidentiality: Confidentiality
    integrity: str
    provenance: str


class IFCDenied(PermissionError):
    """Information-flow policy refused the flow."""


class IFCEngine:
    def label_from_taint(self, taint: int, *, provenance: str) -> IFCLabel:
        conf = Confidentiality.SECRET if taint & SECRET else Confidentiality.INTERNAL
        integrity = "low" if taint & WEB_CONTENT else "high"
        return IFCLabel(conf, integrity, provenance)

    def check_flow(self, src: IFCLabel, sink: str) -> None:
        if src.confidentiality is Confidentiality.SECRET and sink in {"net_egress", "egress.send"}:
            raise IFCDenied("SECRET → net_egress is refused")
        if src.integrity == "low" and sink in {"file_write", "policy.change"}:
            raise IFCDenied("low-integrity data cannot write or change policy")


__all__ = ["Confidentiality", "IFCDenied", "IFCEngine", "IFCLabel"]
