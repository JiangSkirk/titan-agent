"""Behavior-neutral tool schema filter (extracted from the agent mixin)."""

from __future__ import annotations

from js.agent.tool_schema import filter_openai_tool_schemas


def _schema(name: str) -> dict[str, object]:
    return {"type": "function", "function": {"name": name, "parameters": {}}}


def test_degraded_mode_drops_network_tools() -> None:
    schemas = [_schema("file_read"), _schema("web_search"), _schema("browser_fetch")]
    names = [
        str(item["function"]["name"])  # type: ignore[index]
        for item in filter_openai_tool_schemas(
            schemas,
            network_enabled=True,
            network_allowlist=("api.tavily.com",),
            degraded=True,
        )
    ]
    assert names == ["file_read"]


def test_local_model_trims_to_core() -> None:
    schemas = [_schema(name) for name in (
        "file_read",
        "file_write",
        "file_edit",
        "file_view",
        "shell",
        "python",
        "web_search",
        "excel_read",
        "skill_foo",
    )]
    names = {
        str(item["function"]["name"])  # type: ignore[index]
        for item in filter_openai_tool_schemas(
            schemas,
            is_local=True,
            network_enabled=True,
            network_allowlist=("api.tavily.com",),
        )
    }
    assert "excel_read" not in names
    assert "skill_foo" not in names
    assert "file_read" in names
    assert "web_search" in names
