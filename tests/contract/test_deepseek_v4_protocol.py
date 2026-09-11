"""DeepSeek V4 tool/edit protocol pin contracts (Echo-owned)."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from echo_core.deepseek_v4_protocol import (
    COMPETING_EDIT_PROTOCOLS,
    DEEPSEEK_V4_MODEL_IDS,
    DEFAULT_CORE_TOOL_NAMES,
    DEFAULT_EDIT_PROTOCOL,
    EXPAND_ON_DEMAND_EXEC_TOOL_NAMES,
    DeepSeekV4ProtocolError,
    EditProtocolId,
    ProtocolDenyCode,
    assert_no_competing_default,
    default_tool_surface,
    file_edit_openai_schema,
    is_deepseek_v4_model,
    protocol_manifest,
    require_deepseek_v4_model,
    require_default_edit_protocol,
    tool_error_envelope,
    validate_edit_arguments,
    validate_openai_tool_schema,
    validate_tool_error_envelope,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_protocol_manifest_stable() -> None:
    manifest = protocol_manifest()
    assert manifest["same_model_family"] == "deepseek-v4"
    assert manifest["default_edit_protocol"] == DEFAULT_EDIT_PROTOCOL.value
    assert set(manifest["model_ids"]) == set(DEEPSEEK_V4_MODEL_IDS)
    assert set(manifest["default_core_tools"]) == set(DEFAULT_CORE_TOOL_NAMES)
    assert "shell" not in manifest["default_core_tools"]
    assert set(manifest["expand_on_demand_exec_tools"]) == set(EXPAND_ON_DEMAND_EXEC_TOOL_NAMES)
    assert manifest["execution_boundary"] == "d1_admit_stamp_consume_exec"


def test_v4_model_lock() -> None:
    assert is_deepseek_v4_model("deepseek-v4-flash")
    assert is_deepseek_v4_model("deepseek/deepseek-v4-pro")
    assert not is_deepseek_v4_model("deepseek-chat")
    assert not is_deepseek_v4_model("gpt-5.4")
    with pytest.raises(DeepSeekV4ProtocolError) as exc:
        require_deepseek_v4_model("deepseek-reasoner")
    assert exc.value.code is ProtocolDenyCode.UNKNOWN_MODEL


def test_default_edit_protocol_rejects_competitors() -> None:
    assert require_default_edit_protocol(DEFAULT_EDIT_PROTOCOL) is DEFAULT_EDIT_PROTOCOL
    assert_no_competing_default("openai_function_file_edit")
    for competitor in COMPETING_EDIT_PROTOCOLS:
        with pytest.raises(DeepSeekV4ProtocolError) as exc:
            require_default_edit_protocol(competitor)
        assert exc.value.code is ProtocolDenyCode.COMPETING_DEFAULT
        with pytest.raises(DeepSeekV4ProtocolError):
            assert_no_competing_default(competitor.value)


def test_file_edit_schema_and_args() -> None:
    schema = file_edit_openai_schema()
    assert validate_openai_tool_schema(schema) == "file_edit"
    assert validate_edit_arguments(
        {"path": "a.py", "search": "old", "replace": "new"}
    ) == {"path": "a.py", "search": "old", "replace": "new"}
    with pytest.raises(DeepSeekV4ProtocolError) as exc:
        validate_edit_arguments({"path": "a.py", "search": "old"})
    assert exc.value.code is ProtocolDenyCode.INVALID_EDIT_ARGS


def test_tool_error_envelope_fail_closed() -> None:
    payload = tool_error_envelope(error="denied")
    validate_tool_error_envelope(payload)
    assert payload == {"success": False, "error": "denied", "output": ""}
    with pytest.raises(DeepSeekV4ProtocolError):
        tool_error_envelope(error="")
    with pytest.raises(DeepSeekV4ProtocolError):
        validate_tool_error_envelope({"success": True, "error": "x"})
    with pytest.raises(DeepSeekV4ProtocolError):
        validate_tool_error_envelope({"success": False, "error": ""})


def test_exec_tools_not_ambient_default() -> None:
    surface = default_tool_surface(allow_exec_tools=False)
    assert "shell" not in surface
    assert "python" not in surface
    assert "file_edit" in surface
    expanded = default_tool_surface(allow_exec_tools=True)
    assert {"shell", "python"} <= expanded


def test_host_adaptive_schema_imports_protocol_pin() -> None:
    """Host advertising must stay locked to the echo-core V4 pin."""

    from js.echo.turn_loop import schema as host_schema

    assert set(host_schema._ECHO_CORE_TOOL_NAMES) == set(DEFAULT_CORE_TOOL_NAMES)
    assert set(host_schema._ECHO_EXEC_TOOL_NAMES) == set(EXPAND_ON_DEMAND_EXEC_TOOL_NAMES)
    source = (REPO_ROOT / "js" / "echo" / "turn_loop" / "schema.py").read_text(encoding="utf-8")
    assert "from echo_core.deepseek_v4_protocol import" in source


def test_no_competing_v4_default_wired_in_echo_host() -> None:
    """Fail if Echo Host sources pin a competing edit protocol as V4 default."""

    roots = (
        REPO_ROOT / "packages" / "echo-core" / "echo_core",
        REPO_ROOT / "js" / "echo",
        REPO_ROOT / "benchmarks",
    )
    offenders: list[str] = []
    banned_assignments = {
        "DEFAULT_EDIT_PROTOCOL",
        "default_edit_protocol",
        "V4_EDIT_PROTOCOL",
        "DEEPSEEK_V4_EDIT_PROTOCOL",
    }
    for root in roots:
        if not root.exists():
            continue
        for path in root.rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            # Literal assignment of a competing id as a module-level default.
            for competitor in COMPETING_EDIT_PROTOCOLS:
                needle = f'= "{competitor.value}"'
                alt = f"= '{competitor.value}'"
                if needle in text or alt in text:
                    # Allow the enum definition / frozenset membership lists.
                    if path.name == "deepseek_v4_protocol.py":
                        continue
                    offenders.append(f"{path.relative_to(REPO_ROOT)}: {competitor.value}")
            tree = ast.parse(text, filename=str(path))
            for node in tree.body:
                if isinstance(node, ast.Assign):
                    targets = [
                        t.id for t in node.targets if isinstance(t, ast.Name) and t.id in banned_assignments
                    ]
                    if not targets:
                        continue
                    value = node.value
                    if isinstance(value, ast.Constant) and value.value in {
                        p.value for p in COMPETING_EDIT_PROTOCOLS
                    }:
                        offenders.append(
                            f"{path.relative_to(REPO_ROOT)}: {targets[0]}={value.value}"
                        )
                    if isinstance(value, ast.Attribute) and value.attr in {
                        p.name for p in COMPETING_EDIT_PROTOCOLS
                    }:
                        offenders.append(
                            f"{path.relative_to(REPO_ROOT)}: {targets[0]}={value.attr}"
                        )
    assert offenders == [], "competing V4 default protocol wired:\n" + "\n".join(offenders)


def test_default_edit_protocol_enum_exclusive() -> None:
    assert DEFAULT_EDIT_PROTOCOL is EditProtocolId.OPENAI_FUNCTION_FILE_EDIT
    assert DEFAULT_EDIT_PROTOCOL not in COMPETING_EDIT_PROTOCOLS
    assert EditProtocolId.APPLY_PATCH in COMPETING_EDIT_PROTOCOLS
