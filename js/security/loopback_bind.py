"""Fail-closed bind-host policy for cleartext HTTP servers."""

from __future__ import annotations

LITERAL_LOOPBACK_BIND_HOSTS = frozenset({"127.0.0.1", "::1"})


class CleartextBindError(ValueError):
    """Raised when a server would listen off loopback without TLS."""


def require_literal_loopback_bind(host: object) -> str:
    """Accept only literal loopback bind hosts for cleartext HTTP/WebSocket."""
    if type(host) is not str:
        raise CleartextBindError("non-loopback cleartext HTTP bind is not allowed")
    candidate = host.strip()
    if candidate not in LITERAL_LOOPBACK_BIND_HOSTS:
        raise CleartextBindError("non-loopback cleartext HTTP bind is not allowed")
    return candidate
