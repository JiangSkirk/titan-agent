from __future__ import annotations

import hmac
import json
from typing import Any

from echo_core.primitives import stable_payload_hash


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def stable_hash(value: Any) -> str:
    return stable_payload_hash(value)


def stable_hmac(key: bytes, value: Any) -> bytes:
    payload = canonical_json(value).encode("utf-8")
    return hmac.new(key, payload, digestmod="sha256").digest()


def hmac_matches(key: bytes, value: Any, mac: bytes) -> bool:
    return hmac.compare_digest(stable_hmac(key, value), mac)


def digest_eq(left: str | bytes, right: str | bytes) -> bool:
    """Constant-time equality for digests. Different lengths are a mismatch."""

    left_b = left.encode("utf-8") if isinstance(left, str) else left
    right_b = right.encode("utf-8") if isinstance(right, str) else right
    if len(left_b) != len(right_b):
        return False
    return hmac.compare_digest(left_b, right_b)
