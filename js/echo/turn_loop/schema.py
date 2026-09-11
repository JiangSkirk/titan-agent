"""Adaptive Echo tool-schema selection for a single provider call."""

from __future__ import annotations

from typing import Any

from echo_core.deepseek_v4_protocol import (
    DEFAULT_CORE_TOOL_NAMES,
    EXPAND_ON_DEMAND_EXEC_TOOL_NAMES,
    EXPAND_ON_DEMAND_META_TOOL_NAMES,
)

# Pinned by echo_core.deepseek_v4_protocol (DeepSeek V4 lite boot surface ≤5).
_ECHO_CORE_TOOL_NAMES = set(DEFAULT_CORE_TOOL_NAMES)
# F-14 / v0.4.1: execution tools are NOT part of the always-on lite subset.
# Advertised only when the operator opts in via ``SecurityConfig.echo_exec_tools``.
_ECHO_EXEC_TOOL_NAMES = set(EXPAND_ON_DEMAND_EXEC_TOOL_NAMES)
# Meta expand-on-demand names (write/list/view/code_search/web_search) — never boot default.
_ECHO_META_EXPAND_TOOL_NAMES = set(EXPAND_ON_DEMAND_META_TOOL_NAMES)
_ECHO_DELETE_TERMS = ("delete", "remove", "rm ", "unlink", "删除", "删掉", "移除")
_ECHO_WRITE_TERMS = (
    "write",
    "create file",
    "new file",
    "overwrite",
    "save to",
    "写入",
    "创建文件",
    "新建",
)
_ECHO_LIST_VIEW_TERMS = (
    "list",
    "ls ",
    "directory",
    "tree",
    "view file",
    "目录",
    "列出",
    "查看文件",
)
_ECHO_CODE_SEARCH_TERMS = ("code search", "grep", "regex", "ripgrep", "代码搜索", "正则")
_ECHO_WEB_TERMS = (
    "http://",
    "https://",
    "url",
    "website",
    "web page",
    "browser",
    "browse",
    "navigate",
    "click",
    "screenshot",
    "网页",
    "网站",
    "浏览器",
    "点击",
    "截图",
    "打开网页",
    "抓取",
)
_ECHO_OFFICE_TERMS = (
    "csv",
    "excel",
    "xlsx",
    "xls",
    "spreadsheet",
    "worksheet",
    "表格",
    "电子表格",
)
_ECHO_WORD_TERMS = ("word", "docx", "document", "文档", "文字处理")
_ECHO_PDF_TERMS = ("pdf",)
_ECHO_ACCESSORY_TERMS = ("accessory", "trim", "辅料", "供应商下单", "bom")
_ECHO_PACKING_TERMS = ("packing", "packing details", "装箱", "发货", "卷号")
_ECHO_ROUTINE_TERMS = ("routine", "流程", "工作流")


def _echo_tool_schema_subset(
    query: str,
    schemas: list[dict[str, Any]],
    allow_exec_tools: bool = False,
) -> list[dict[str, Any]]:
    """Select a lower-token Echo tool schema for the current turn.

    The full registry is still available to the agent runtime; this only trims
    what is advertised to the model for a single provider call.  Lite core tools
    stay visible (≤5), while meta expand-on-demand / browser / office / skill
    schemas are included only when the user request gives a direct signal.

    F-14 / v0.4.1: an empty/blank query gets ONLY the lite core subset
    (fail-closed: never the full registry), and execution tools (shell/python)
    are advertised only when ``allow_exec_tools`` is set by explicit configuration.
    """
    if not schemas:
        return schemas
    core_names = set(_ECHO_CORE_TOOL_NAMES)
    if allow_exec_tools:
        core_names |= _ECHO_EXEC_TOOL_NAMES
    if not query.strip():
        return [
            schema
            for schema in schemas
            if str(schema.get("function", {}).get("name", "")) in core_names
        ]
    query_l = query.lower()
    needs_web = _query_has_any(query_l, _ECHO_WEB_TERMS)
    needs_office = _query_has_any(query_l, _ECHO_OFFICE_TERMS)
    needs_word = _query_has_any(query_l, _ECHO_WORD_TERMS)
    needs_pdf = _query_has_any(query_l, _ECHO_PDF_TERMS)
    needs_accessory = _query_has_any(query_l, _ECHO_ACCESSORY_TERMS)
    needs_packing = _query_has_any(query_l, _ECHO_PACKING_TERMS)
    needs_routine = _query_has_any(query_l, _ECHO_ROUTINE_TERMS)
    needs_delete = _query_has_any(query_l, _ECHO_DELETE_TERMS)
    needs_write = _query_has_any(query_l, _ECHO_WRITE_TERMS)
    needs_list_view = _query_has_any(query_l, _ECHO_LIST_VIEW_TERMS)
    needs_code_search = _query_has_any(query_l, _ECHO_CODE_SEARCH_TERMS)
    needs_skill = "skill" in query_l or "技能" in query_l
    selected: list[dict[str, Any]] = []
    for schema in schemas:
        name = str(schema.get("function", {}).get("name", ""))
        if (
            name in core_names
            or (name == "file_delete" and needs_delete)
            or (name == "file_write" and needs_write and name in _ECHO_META_EXPAND_TOOL_NAMES)
            or (name in {"file_list", "file_view"} and needs_list_view)
            or (name == "code_search" and needs_code_search)
            or ((name.startswith("web_") or name.startswith("browser")) and needs_web)
            or ((name.startswith("excel") or name.startswith("csv")) and needs_office)
            or (name.startswith("word") and needs_word)
            or (name.startswith("pdf") and needs_pdf)
            or (name == "accessory_order_run" and needs_accessory)
            or (name == "packing_details_run" and needs_packing)
            or (name.startswith("work_routine_") and needs_routine)
            or (name.startswith("skill_") and (needs_skill or _query_mentions_skill(query_l, name)))
        ):
            selected.append(schema)
    return selected or schemas


def _query_has_any(query_l: str, terms: tuple[str, ...]) -> bool:
    return any(term in query_l for term in terms)


def _query_mentions_skill(query_l: str, tool_name: str) -> bool:
    skill_name = tool_name.removeprefix("skill_").replace("_", "-")
    tokens = [part for part in skill_name.replace("-", " ").split() if len(part) >= 3]
    return any(part in query_l for part in tokens)
