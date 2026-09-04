"""MCP gate: pin tool definitions by content hash. No --force bypass."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass


class MCPGateDenied(PermissionError):
    """MCP pin or install refused."""


@dataclass(frozen=True, slots=True)
class PinnedTool:
    name: str
    definition_hash: str
    first_seen_uses: int = 0


class MCPGate:
    def __init__(self) -> None:
        self._pins: dict[str, PinnedTool] = {}
        self._quarantine: set[str] = set()

    @staticmethod
    def definition_hash(body: str) -> str:
        return hashlib.sha256(body.encode("utf-8")).hexdigest()

    def pin(self, name: str, body: str) -> PinnedTool:
        digest = self.definition_hash(body)
        existing = self._pins.get(name)
        if existing is not None and existing.definition_hash != digest:
            self._quarantine.add(name)
            raise MCPGateDenied("tool definition drifted; re-approval required")
        pinned = PinnedTool(name, digest)
        self._pins[name] = pinned
        self._quarantine.add(name)
        return pinned

    def allow_after_uses(self, name: str, uses: int, *, threshold: int = 10) -> None:
        if name not in self._pins:
            raise MCPGateDenied("unknown tool")
        if uses < threshold:
            raise MCPGateDenied("first-seen isolation still active")
        self._quarantine.discard(name)

    def assert_unforced(self, *, force: bool) -> None:
        if force:
            raise MCPGateDenied("MCPGate has no --force bypass")


__all__ = ["MCPGate", "MCPGateDenied", "PinnedTool"]
