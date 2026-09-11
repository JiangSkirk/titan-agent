"""Immutable-identity allowlist primitive shared by every channel adapter."""

from __future__ import annotations

from dataclasses import dataclass


class IdentityDenied(PermissionError):
    """Allowlist matched a mutable display field or missed the immutable id."""


@dataclass(frozen=True, slots=True)
class AllowlistIdentity:
    platform: str
    immutable_id: str


def resolve_allowlist_identity(
    *,
    platform: str,
    immutable_id: str,
    display_name: str | None,
    allow_ids: frozenset[str],
) -> AllowlistIdentity:
    """Only platform-assigned immutable IDs are keys. Display names never match."""

    _ = display_name  # explicitly unused — mutable fields are not keys
    if not immutable_id or immutable_id not in allow_ids:
        raise IdentityDenied("allowlist requires a platform-assigned immutable id")
    return AllowlistIdentity(platform=platform, immutable_id=immutable_id)


__all__ = ["AllowlistIdentity", "IdentityDenied", "resolve_allowlist_identity"]
