"""Derive Echo effect grants from tool/capability metadata (not hardcoded)."""

from __future__ import annotations

from echo_core.effect_authority import EffectAuthorityError
from echo_core.sinks import sinks_for_tool
from orin_guard.kernel.grants import grants_for_tool


def grants_for_effect_tool(tool_name: str, *, resource_scope: str = "", context_taint: int = 0) -> frozenset[str]:
    """Return the authoritative grant set for a tool effect."""

    if not tool_name:
        raise EffectAuthorityError("tool name required to derive grants")
    return grants_for_tool(
        tool_name,
        resource_scope=resource_scope,
        context_taint=context_taint,
    )


def assert_grants_cover_tool(
    tool_name: str,
    grants: frozenset[str],
    *,
    resource_scope: str = "",
    context_taint: int = 0,
) -> None:
    """Deny when presented grants do not cover the tool's required grant set."""

    required = grants_for_effect_tool(
        tool_name,
        resource_scope=resource_scope,
        context_taint=context_taint,
    )
    if sinks_for_tool(tool_name) and not required:
        # Sink-bearing tools must resolve to at least one grant bit.
        raise EffectAuthorityError(f"tool {tool_name!r} requires derived grants")
    if not required.issubset(grants):
        missing = ", ".join(sorted(required - grants)) or "(none)"
        raise EffectAuthorityError(
            f"tool {tool_name!r} grants incomplete; missing {missing}"
        )


__all__ = ["assert_grants_cover_tool", "grants_for_effect_tool"]
