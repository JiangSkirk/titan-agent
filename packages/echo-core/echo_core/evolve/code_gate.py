"""L5 code-level self-modification. Default closed; no unattended path."""

from __future__ import annotations


class CodeEvolutionDenied(PermissionError):
    """Kernel/security/ledger code cannot be evolved without a human gate."""


def assert_code_gate_open(*, enabled: bool) -> None:
    if not enabled:
        raise CodeEvolutionDenied("code-level evolution is disabled by default")
