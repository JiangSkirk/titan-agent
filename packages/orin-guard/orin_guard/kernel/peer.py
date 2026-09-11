"""OS peer authentication. Loopback is a flag, not a principal."""

from __future__ import annotations

from dataclasses import dataclass


class PeerDenied(PermissionError):
    """Peer credentials failed."""


@dataclass(frozen=True, slots=True)
class Peer:
    uid: int
    pid: int
    loopback: bool


def authenticate_peer(
    *,
    uid: int,
    pid: int,
    allowed_uids: frozenset[int],
    allowed_pids: frozenset[int],
    loopback: bool = False,
) -> Peer:
    """uid + start-pid set. Knowing the socket path is not identity."""

    if uid not in allowed_uids:
        raise PeerDenied("uid is not in the allow set")
    if pid not in allowed_pids:
        raise PeerDenied("pid is not in the start-pid set")
    return Peer(uid=uid, pid=pid, loopback=loopback)


__all__ = ["Peer", "PeerDenied", "authenticate_peer"]
