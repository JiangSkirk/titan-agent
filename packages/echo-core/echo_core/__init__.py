"""Echo 3.0 standalone kernel.

This package has **zero** ``js.*`` imports. Hosts (including js-agent) consume
it through SPI ports. Evolution polarity lives in :mod:`echo_core.phylogeny`.
"""

from __future__ import annotations

from echo_core.phylogeny import Phylogeny, PhylogenyError
from echo_core.spi.guardian import GuardianDenied, GuardianSPI, NullGuardian

ECHO_3_ARCHITECTURE = "echo-3.0"

__all__ = [
    "ECHO_3_ARCHITECTURE",
    "GuardianDenied",
    "GuardianSPI",
    "NullGuardian",
    "Phylogeny",
    "PhylogenyError",
]
