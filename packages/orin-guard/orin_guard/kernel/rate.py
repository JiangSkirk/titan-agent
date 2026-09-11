"""Token bucket. Loopback is not a rate-limit exemption."""

from __future__ import annotations

import time
from dataclasses import dataclass, field


class RateLimited(PermissionError):
    """Caller exceeded the token bucket."""


@dataclass
class TokenBucket:
    rate: float = 20.0
    burst: float = 40.0
    tokens: float = 40.0
    updated_at: float = field(default_factory=time.monotonic)

    def take(self, n: float = 1.0, *, loopback: bool = False) -> None:
        now = time.monotonic()
        elapsed = max(0.0, now - self.updated_at)
        self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
        self.updated_at = now
        _ = loopback  # never an exemption
        if self.tokens < n:
            raise RateLimited("token bucket exhausted")
        self.tokens -= n


__all__ = ["RateLimited", "TokenBucket"]
