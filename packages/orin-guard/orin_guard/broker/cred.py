"""Credential broker — sandbox holds only opaque tokens, never raw keys."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass


class CredBrokerDenied(PermissionError):
    """Token issue or exchange refused."""


@dataclass(frozen=True, slots=True)
class OpaqueToken:
    token_id: str
    owner: str
    host: str
    expires_at: float
    mac: str


class CredBroker:
    def __init__(self, mac_key: bytes, *, allowed_hosts: frozenset[str] | None = None) -> None:
        self._key = mac_key
        self._allowed = allowed_hosts or frozenset()
        self._secrets: dict[str, bytes] = {}

    def issue(
        self,
        owner: str,
        host: str,
        secret: bytes,
        *,
        ttl: float = 300.0,
    ) -> OpaqueToken:
        if self._allowed and host not in self._allowed:
            raise CredBrokerDenied("host is not on the egress allowlist")
        token_id = secrets.token_hex(16)
        expires = time.time() + ttl
        mac = hmac.new(self._key, f"{token_id}:{owner}:{host}".encode(), hashlib.sha256).hexdigest()
        self._secrets[token_id] = secret
        return OpaqueToken(token_id, owner, host, expires, mac)

    def exchange(self, token: OpaqueToken, *, owner: str, host: str) -> bytes:
        if token.owner != owner or token.host != host:
            raise CredBrokerDenied("token identity mismatch")
        if time.time() > token.expires_at:
            raise CredBrokerDenied("token expired")
        expected = hmac.new(
            self._key, f"{token.token_id}:{token.owner}:{token.host}".encode(), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(token.mac, expected):
            raise CredBrokerDenied("token MAC mismatch")
        secret = self._secrets.get(token.token_id)
        if secret is None:
            raise CredBrokerDenied("token already spent or unknown")
        return secret


__all__ = ["CredBroker", "CredBrokerDenied", "OpaqueToken"]
