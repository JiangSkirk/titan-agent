"""Sandbox config integrity — bind-mount / network namespace checks at create time."""

from __future__ import annotations

from pathlib import Path

BLOCKED_HOST_PATHS = (
    "/etc",
    "/proc",
    "/sys",
    "/dev",
    "/root",
    "/boot",
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/private/etc",
    "/private/var/run/docker.sock",
)


class CellConfigDenied(PermissionError):
    """Sandbox configuration would collapse isolation."""


def validate_bind_mounts(binds: tuple[str, ...]) -> None:
    for bind in binds:
        src = Path(bind.split(":", 1)[0]).as_posix()
        for blocked in BLOCKED_HOST_PATHS:
            if src == blocked or src.startswith(blocked + "/") or blocked.startswith(src + "/"):
                raise CellConfigDenied(f"blocked host path: {src}")


def validate_network(mode: str) -> None:
    if mode in {"host", "container"}:
        raise CellConfigDenied("host/container network namespaces are refused")


__all__ = ["BLOCKED_HOST_PATHS", "CellConfigDenied", "validate_bind_mounts", "validate_network"]
