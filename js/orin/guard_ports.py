"""Host adapters for orin-guard Signer / NetGuard ports."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from js.security import net_guard as _net_guard
from js.security.signer import sign_content, verify_signature


class HostSigner:
    def __init__(self, state_dir: Path, *, public_key_b64: str) -> None:
        self._state_dir = Path(state_dir)
        self._public_key_b64 = public_key_b64

    def sign(self, payload: bytes) -> bytes:
        return sign_content(payload.decode("utf-8"), self._state_dir).encode("ascii")

    def verify(self, payload: bytes, signature: bytes) -> bool:
        return verify_signature(
            payload.decode("utf-8"),
            signature.decode("ascii"),
            self._public_key_b64,
        )


class HostNetGuard:
    def resolve_and_validate(self, url: str, **kwargs: Any) -> Any:
        return _net_guard.resolve_and_validate(url, **kwargs)
