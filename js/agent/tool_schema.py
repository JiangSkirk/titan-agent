"""Pure tool-schema filters used by the agent mixin.

``ToolExecutorMixin._get_tools_schema`` stays the public method and keeps
the same signature.  Trimming lives here so the 5k-line mixin is not the
only place that knows which tools survive local/cloud/degraded cuts.
"""

from __future__ import annotations

from typing import Any

from js.tools.registry import tool_requires_network

LOCAL_CORE_TOOL_NAMES = frozenset(
    {
        "web_search",
        "file_read",
        "file_write",
        "file_edit",
        "file_view",
        "shell",
        "python",
    }
)
CLOUD_CORE_TOOL_NAMES = frozenset(
    {
        "web_search",
        "browser_fetch",
        "file_read",
        "file_write",
        "file_edit",
        "file_view",
        "file_list",
        "code_search",
        "shell",
        "python",
        "web_navigate",
        "web_snapshot",
        "web_click",
        "web_fill",
        "web_screenshot",
        "web_evaluate",
        "web_extract_text",
        "web_find_tab",
        "web_list_tabs",
    }
)
_DEGRADED_NETWORK_TOOLS = frozenset(
    {"web_search", "browser_fetch", "browser_open", "fetch_url"}
)


def filter_openai_tool_schemas(
    schemas: list[dict[str, Any]],
    *,
    capability_ceiling: set[str] | None = None,
    network_enabled: bool = False,
    network_allowlist: tuple[str, ...] = (),
    is_local: bool = False,
    context_window: int = 128_000,
    degraded: bool = False,
) -> list[dict[str, Any]]:
    """Filter OpenAI tool schemas without depending on Agent state."""
    filtered = list(schemas)
    if capability_ceiling is not None:
        filtered = [
            schema
            for schema in filtered
            if str(schema.get("function", {}).get("name", "")) in capability_ceiling
        ]
    if not (network_enabled and tuple(network_allowlist)):
        filtered = [
            schema
            for schema in filtered
            if not tool_requires_network(
                str(schema.get("function", {}).get("name", "")),
                {},
            )
        ]
    if is_local and len(filtered) > 7:
        filtered = [
            schema
            for schema in filtered
            if str(schema.get("function", {}).get("name", "")) in LOCAL_CORE_TOOL_NAMES
        ]
    elif context_window < 32_000 and len(filtered) > 15:
        filtered = [
            schema
            for schema in filtered
            if str(schema.get("function", {}).get("name", "")) in CLOUD_CORE_TOOL_NAMES
        ]
    if not degraded:
        return filtered
    kept: list[dict[str, Any]] = []
    for schema in filtered:
        name = str(schema.get("function", {}).get("name", ""))
        if name in _DEGRADED_NETWORK_TOOLS or name.startswith("web_"):
            continue
        kept.append(schema)
    return kept
