"""Echo 3.0 SPI — kernel/host boundary. Zero I/O in the protocols themselves."""

from __future__ import annotations

from echo_core.spi.guardian import GuardianSPI, NullGuardian
from echo_core.spi.ports import (
    LedgerStore,
    MetricsSink,
    ModelAdapter,
    SafetyService,
    Sandbox,
    SettingsView,
    Store,
    TCBHook,
    ToolAdapter,
    TurnOutcomeRecorder,
)

__all__ = [
    "GuardianSPI",
    "LedgerStore",
    "MetricsSink",
    "ModelAdapter",
    "NullGuardian",
    "SafetyService",
    "Sandbox",
    "SettingsView",
    "Store",
    "TCBHook",
    "ToolAdapter",
    "TurnOutcomeRecorder",
]
