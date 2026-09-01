"""Map a tool + taint into conjunction grants. Deterministic, no LLM."""

from __future__ import annotations

from echo_core.sinks import (
    SINK_FS_OUTSIDE,
    SINK_FS_READ,
    SINK_FS_WRITE,
    SINK_NETWORK_EGRESS,
    sinks_for_tool,
)
from echo_core.taint import WEB_CONTENT

from orin_guard.kernel.conjunction import GRANT_EGRESS, GRANT_PRIVATE_READ, GRANT_UNTRUSTED

_WEB_TOOLS = frozenset(
    {
        "browser_fetch",
        "web_search",
        "webbridge_navigate",
        "webbridge_read",
        "webbridge_screenshot",
        "net.fetch",
        "net.send",
    }
)


def grants_for_tool(
    tool_name: str,
    *,
    resource_scope: str = "",
    context_taint: int = 0,
) -> frozenset[str]:
    grants: set[str] = set()
    sinks = sinks_for_tool(tool_name)
    scope = resource_scope.lower()
    if sinks & (SINK_FS_READ | SINK_FS_WRITE | SINK_FS_OUTSIDE) or "private" in scope:
        grants.add(GRANT_PRIVATE_READ)
    if (context_taint & WEB_CONTENT) or tool_name in _WEB_TOOLS:
        grants.add(GRANT_UNTRUSTED)
    if sinks & SINK_NETWORK_EGRESS:
        grants.add(GRANT_EGRESS)
    return frozenset(grants)
