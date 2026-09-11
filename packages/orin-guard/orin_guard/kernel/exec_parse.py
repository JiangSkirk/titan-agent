"""Semantic exec checks — fail closed on shell tricks OpenClaw's lexical allowlist missed."""

from __future__ import annotations

_LINE_CONTINUATION = ("\\\n", "\\\r")
_MULTIPLEXERS = frozenset({"busybox", "toybox"})


class ExecParseDenied(PermissionError):
    """Command cannot be given a semantic identity."""


def reject_lexical_bypass(command: str) -> None:
    """Fail closed on line-continuation, multiplexer dispatch, and GNU abbrev."""

    if any(token in command for token in _LINE_CONTINUATION):
        raise ExecParseDenied("line continuation is a parse failure")
    head = command.strip().split(None, 1)[0] if command.strip() else ""
    binary = head.rsplit("/", 1)[-1]
    if binary in _MULTIPLEXERS:
        raise ExecParseDenied("multiplexer binaries must be unwrapped or blocked")
    if " --compress-prog" in f" {command} " or command.rstrip().endswith("--compress-prog"):
        raise ExecParseDenied("GNU long-option abbreviations are not an identity")


def prefer_argv(argv: tuple[str, ...]) -> tuple[str, ...]:
    """Direct-argv mode: no shell wrapper, no lexical parser."""

    if not argv:
        raise ExecParseDenied("empty argv")
    return argv


__all__ = ["ExecParseDenied", "prefer_argv", "reject_lexical_bypass"]
