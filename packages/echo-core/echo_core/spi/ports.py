"""Host-replaceable ports. Concrete adapters live outside the kernel."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping, Sequence


@runtime_checkable
class SettingsView(Protocol):
    """Read-only settings surface replacing ``js.config`` inside the kernel."""

    def get(self, key: str, default: Any = None) -> Any: ...


@runtime_checkable
class MetricsSink(Protocol):
    def increment(self, name: str, value: float = 1.0, **labels: str) -> None: ...


@runtime_checkable
class TCBHook(Protocol):
    """Trusted computing base probe used by the OS sandbox."""

    def sandbox_carrier_available(self) -> bool: ...


@runtime_checkable
class ModelAdapter(Protocol):
    async def chat(self, messages: Sequence[Mapping[str, Any]], **kwargs: Any) -> Any: ...


@runtime_checkable
class ToolAdapter(Protocol):
    async def execute(self, name: str, arguments: Mapping[str, Any]) -> Any: ...


@runtime_checkable
class SafetyService(Protocol):
    def begin_chat_turn(self, **kwargs: Any) -> Any: ...
    def authorize_model_call(self, **kwargs: Any) -> Any: ...
    def finish_chat_turn(self, **kwargs: Any) -> None: ...


@runtime_checkable
class TurnOutcomeRecorder(Protocol):
    """Learning-signal outlet. Must not become a second Exec path."""

    def record_turn(self, score: Any) -> None: ...
    def record_tool(self, score: Any) -> None: ...


@runtime_checkable
class LedgerStore(Protocol):
    def append(self, frame: Any) -> int: ...
    def frames(self) -> Iterator[Any]: ...
    def flock(self) -> bool: ...


@runtime_checkable
class Sandbox(Protocol):
    def grant(self, tool_name: str, resource_scope: str, now: int) -> Any: ...
    def execute(self, lease: Any, arguments_hash: str) -> str: ...


@runtime_checkable
class Store(Protocol):
    def load(self, key: str) -> bytes | None: ...
    def save(self, key: str, blob: bytes, *, version: int) -> int: ...


__all__ = [
    "LedgerStore",
    "MetricsSink",
    "ModelAdapter",
    "SafetyService",
    "Sandbox",
    "SettingsView",
    "Store",
    "TCBHook",
    "ToolAdapter",
    "TurnOutcomeRecorder",
]
