"""Runtime TCB write deny (standalone). No ``js`` import.

When a Host sets the package root via :func:`override_runtime_package_root`,
writes into that tree are denied except ``web/static``. Standalone echo-core
leaves the root unset, so TCB matching is a no-op.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path

RUNTIME_TCB_WRITE_ALLOW_PREFIXES: tuple[str, ...] = ("web/static",)

_package_root_override: ContextVar[Path | None] = ContextVar(
    "echo_core_runtime_tcb_package_root",
    default=None,
)


def runtime_package_root() -> Path | None:
    return _package_root_override.get()


@contextmanager
def override_runtime_package_root(root: Path) -> Iterator[Path]:
    resolved = root.resolve()
    token = _package_root_override.set(resolved)
    try:
        yield resolved
    finally:
        _package_root_override.reset(token)


def _relative_is_write_allowed(relative: Path) -> bool:
    posix = relative.as_posix().casefold()
    if posix in {".", ""}:
        return False
    for prefix in RUNTIME_TCB_WRITE_ALLOW_PREFIXES:
        folded = prefix.casefold()
        if posix == folded or posix.startswith(folded + "/"):
            return True
    return False


def is_runtime_tcb_write(target: Path, *, workspace: Path) -> bool:
    package_root = runtime_package_root()
    if package_root is None:
        return False
    try:
        workspace_root = workspace.resolve()
        candidate = target if target.is_absolute() else workspace_root / target
        candidate = candidate.resolve()
        candidate.relative_to(workspace_root)
        relative = candidate.relative_to(package_root)
    except (OSError, RuntimeError, ValueError):
        return False
    return not _relative_is_write_allowed(relative)


def token_is_runtime_tcb_write(token: str, *, workspace: Path) -> bool:
    if not token or token in {".", "-"} or "\x00" in token:
        return False
    if token.startswith("~"):
        return False
    normalized = os.path.normpath(token.replace("\\", "/"))
    if normalized in {".", ""}:
        return False
    parts = tuple(part for part in Path(normalized).parts if part not in ("", "."))
    if any(part == ".." for part in parts):
        return False
    candidate = Path(normalized)
    if not candidate.is_absolute():
        candidate = workspace / Path(*parts)
    return is_runtime_tcb_write(candidate, workspace=workspace)


def workspace_tcb_deny_targets(workspace: Path) -> tuple[tuple[Path, bool], ...]:
    try:
        workspace_root = workspace.resolve()
        package_root = runtime_package_root()
        if package_root is None:
            return ()
        package_root.relative_to(workspace_root)
    except (OSError, RuntimeError, ValueError):
        return ()
    return ((package_root, True),)


def workspace_tcb_allow_targets(workspace: Path) -> tuple[tuple[Path, bool], ...]:
    try:
        workspace_root = workspace.resolve()
        package_root = runtime_package_root()
        if package_root is None:
            return ()
        package_root.relative_to(workspace_root)
    except (OSError, RuntimeError, ValueError):
        return ()
    return tuple((package_root / prefix, True) for prefix in RUNTIME_TCB_WRITE_ALLOW_PREFIXES)


__all__ = [
    "RUNTIME_TCB_WRITE_ALLOW_PREFIXES",
    "is_runtime_tcb_write",
    "override_runtime_package_root",
    "runtime_package_root",
    "token_is_runtime_tcb_write",
    "workspace_tcb_allow_targets",
    "workspace_tcb_deny_targets",
]
