"""Host-replaceable Signer and NetGuard ports. Implementations live in the Host."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class Signer(Protocol):
    def sign(self, payload: bytes) -> bytes: ...

    def verify(self, payload: bytes, signature: bytes) -> bool: ...


@runtime_checkable
class NetGuard(Protocol):
    def resolve_and_validate(self, url: str, **kwargs: Any) -> Any: ...
