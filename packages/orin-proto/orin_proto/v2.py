"""orin/v2 wire protocol. Frozen v1 kinds plus v2 extensions.

This package has no I/O and holds no keys. Framing is 4-byte big-endian
length + JSON, max 64 KiB per frame (deliberately not a WebSocket gateway).
"""

from __future__ import annotations

import json
import struct
from typing import Any, Final

PROTOCOL_VERSION: Final[int] = 2
MAX_FRAME_BYTES: Final[int] = 64 * 1024
_LEN = struct.Struct("!I")

# v1 kinds remain valid. v2 adds plan/check/ifc/cred/mcp/conjunction.
V1_KINDS: Final[frozenset[str]] = frozenset(
    {
        "hello",
        "hello_ack",
        "issue",
        "issue_ack",
        "consume",
        "consume_ack",
        "revoke",
        "revoke_ack",
        "error",
    }
)
V2_KINDS: Final[frozenset[str]] = frozenset(
    {
        "exec.plan",
        "exec.check",
        "ifc.evaluate",
        "cred.issue",
        "cred.exchange",
        "mcp.pin",
        "conjunction.check",
    }
)
KNOWN_KINDS: Final[frozenset[str]] = V1_KINDS | V2_KINDS


class FrameError(ValueError):
    """Malformed or oversized orin/v2 frame."""


def pack(payload: dict[str, Any]) -> bytes:
    """Encode one JSON object as a length-prefixed frame."""

    kind = payload.get("type")
    if not isinstance(kind, str) or kind not in KNOWN_KINDS:
        raise FrameError("unknown or unregistered frame type")
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if len(body) > MAX_FRAME_BYTES:
        raise FrameError("frame exceeds 64 KiB")
    return _LEN.pack(len(body)) + body


def unpack(buffer: bytes) -> tuple[dict[str, Any], bytes]:
    """Decode one frame; return (payload, remainder). Extra bytes are rejected."""

    if len(buffer) < 4:
        raise FrameError("truncated length prefix")
    (n,) = _LEN.unpack(buffer[:4])
    if n < 0 or n > MAX_FRAME_BYTES:
        raise FrameError("illegal frame length")
    if len(buffer) < 4 + n:
        raise FrameError("truncated frame body")
    if len(buffer) > 4 + n:
        raise FrameError("trailing bytes after frame")
    try:
        payload = json.loads(buffer[4 : 4 + n].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FrameError("frame is not JSON") from exc
    if not isinstance(payload, dict):
        raise FrameError("frame payload must be an object")
    kind = payload.get("type")
    if not isinstance(kind, str) or kind not in KNOWN_KINDS:
        raise FrameError("unknown or unregistered frame type")
    return payload, b""


__all__ = [
    "KNOWN_KINDS",
    "MAX_FRAME_BYTES",
    "PROTOCOL_VERSION",
    "V1_KINDS",
    "V2_KINDS",
    "FrameError",
    "pack",
    "unpack",
]
