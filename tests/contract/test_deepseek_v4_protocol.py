"""DeepSeek V4 tool/edit protocol pin contracts (Echo-owned)."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from echo_core.deepseek_v4_protocol import (
    ALTERNATE_LITE_TOOL_NAMES,
    COMPETING_EDIT_PROTOCOLS,
    DEEPSEEK_V4_MODEL_IDS,
    DEFAULT_CORE_TOOL_NAMES,
    DEFAULT_EDIT_PROTOCOL,
    DEFAULT_SURFACE_PROFILE,
    EXPAND_ON_DEMAND_EXEC_TOOL_NAMES,
    EXPAND_ON_DEMAND_META_TOOL_NAMES,
    LITE_CANDIDATE_TOOL_NAMES,
    MAX_DEFAULT_TOOL_SURFACE,
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
    assert manifest["default_surface_profile"] == "harness_edit"
    assert manifest["default_edit_protocol"] == DEFAULT_EDIT_PROTOCOL.value
    assert set(manifest["model_ids"]) == set(DEEPSEEK_V4_MODEL_IDS)
    assert manifest["model_id_expansion"] == "exact_or_single_provider_prefix_only"
    assert set(manifest["default_core_tools"]) == set(DEFAULT_CORE_TOOL_NAMES)
    assert manifest["max_default_tool_surface"] == MAX_DEFAULT_TOOL_SURFACE
    assert "shell" not in manifest["default_core_tools"]
    assert "file_write" not in manifest["default_core_tools"]
    assert "web_search" not in manifest["default_core_tools"]
    assert set(manifest["expand_on_demand_meta_tools"]) == set(EXPAND_ON_DEMAND_META_TOOL_NAMES)
    assert set(manifest["expand_on_demand_exec_tools"]) == set(EXPAND_ON_DEMAND_EXEC_TOOL_NAMES)
    assert manifest["execution_boundary"] == "d1_admit_stamp_consume_exec"


def test_default_tool_surface_len_le_5() -> None:
    """Frozen Echo v0.4.1: default boot surface must stay ≤5."""

    assert DEFAULT_SURFACE_PROFILE == "harness_edit"
    assert len(DEFAULT_CORE_TOOL_NAMES) <= MAX_DEFAULT_TOOL_SURFACE
    assert len(DEFAULT_CORE_TOOL_NAMES) <= 5
    surface = default_tool_surface(allow_exec_tools=False)
    assert len(surface) <= 5
    assert len(surface) <= MAX_DEFAULT_TOOL_SURFACE
    assert surface == frozenset({"file_read", "file_search", "file_edit"})
    assert surface.issubset(LITE_CANDIDATE_TOOL_NAMES)
    assert not (surface & EXPAND_ON_DEMAND_META_TOOL_NAMES)
    # Opt-in exec still ≤5 for the harness_edit + shell/python set.
    with_exec = default_tool_surface(allow_exec_tools=True)
    assert len(with_exec) <= 5
    assert with_exec == surface | EXPAND_ON_DEMAND_EXEC_TOOL_NAMES


def test_lite_subset_harness_edit_and_alternate() -> None:
    assert DEFAULT_CORE_TOOL_NAMES.issubset(LITE_CANDIDATE_TOOL_NAMES)
    assert ALTERNATE_LITE_TOOL_NAMES.issubset(LITE_CANDIDATE_TOOL_NAMES)
    assert frozenset({"file_read", "file_search", "shell"}) == ALTERNATE_LITE_TOOL_NAMES
    # Thick names must stay expand-on-demand, never lite default.
    assert "file_write" in EXPAND_ON_DEMAND_META_TOOL_NAMES
    assert "web_search" in EXPAND_ON_DEMAND_META_TOOL_NAMES
    assert not (DEFAULT_CORE_TOOL_NAMES & EXPAND_ON_DEMAND_META_TOOL_NAMES)


def test_v4_model_lock_exact_ids_only() -> None:
    assert is_deepseek_v4_model("deepseek-v4-flash")
    assert is_deepseek_v4_model("deepseek/deepseek-v4-pro")
    assert not is_deepseek_v4_model("deepseek-chat")
    assert not is_deepseek_v4_model("gpt-5.4")
    # No wildcard: future SKUs must be explicitly added.
    assert not is_deepseek_v4_model("deepseek-v4-mini")
    assert not is_deepseek_v4_model("deepseek-v4-flash-experimental")
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
    """Host advertising must stay locked to the echo-core V4 lite pin."""

    from js.echo.turn_loop import schema as host_schema

    assert set(host_schema._ECHO_CORE_TOOL_NAMES) == set(DEFAULT_CORE_TOOL_NAMES)
    assert len(host_schema._ECHO_CORE_TOOL_NAMES) <= 5
    assert set(host_schema._ECHO_EXEC_TOOL_NAMES) == set(EXPAND_ON_DEMAND_EXEC_TOOL_NAMES)
    assert set(host_schema._ECHO_META_EXPAND_TOOL_NAMES) == set(EXPAND_ON_DEMAND_META_TOOL_NAMES)
    source = (REPO_ROOT / "js" / "echo" / "turn_loop" / "schema.py").read_text(encoding="utf-8")
    assert "from echo_core.deepseek_v4_protocol import" in source
    assert "EXPAND_ON_DEMAND_META_TOOL_NAMES" in source


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
            for competitor in COMPETING_EDIT_PROTOCOLS:
                needle = f'= "{competitor.value}"'
                alt = f"= '{competitor.value}'"
                if needle in text or alt in text:
                    if path.name == "deepseek_v4_protocol.py":
                        continue
                    offenders.append(f"{path.relative_to(REPO_ROOT)}: {competitor.value}")
            tree = ast.parse(text, filename=str(path))
            for node in tree.body:
                if isinstance(node, ast.Assign):
                    targets = [
                        t.id
                        for t in node.targets
                        if isinstance(t, ast.Name) and t.id in banned_assignments
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


def test_deny_code_mapping_ssot_complete_and_fail_closed() -> None:
    """Dual-track: Orin DENY_* passthrough + Echo short codes; unknown ≠ allow."""

    from echo_core.deny_code_mapping import (
        BANNED_LEGACY_REASON_CODES,
        ECHO_SHORT_CHAT_ONLY_TOOL_REJECTED,
        ECHO_SHORT_CONSUME_BEFORE_STAMP,
        ECHO_SHORT_MAC_MISMATCH,
        ECHO_SHORT_STAMP_DENIED,
        ECHO_SHORT_STAMP_TIMEOUT,
        ECHO_SHORT_UNWIRED_DENY,
        NEXT_DISABLE_CHAT_ONLY_AND_WIRE,
        NEXT_ENABLE_WIRED_OR_CHAT_ONLY,
        NEXT_INSPECT_GRANTS_ARGS_LEASE,
        NEXT_INSPECT_ORIN_DENY_FIELDS,
        NEXT_REPORT_DEFECT,
        NEXT_RETRY_NOT_SAME_CODE_IN_TURN,
        RELATED_ORIN_HOST_REASON_CODES,
        DenyMappingError,
        assert_mapping_denies,
        echo_short_reason_for_orin,
        host_orin_reason_for,
        lookup_protocol_deny_mapping,
        mapping_manifest,
        orin_to_echo_short_rows,
        passthrough_orin_reason_code,
        protocol_deny_code_mapping_rows,
    )

    rows = protocol_deny_code_mapping_rows()
    codes = {row.protocol_deny_code for row in rows}
    assert codes == {c.value for c in ProtocolDenyCode}
    assert all(row.host_orin_reason_code is None for row in rows)

    manifest = mapping_manifest()
    assert manifest["second_authority"] is False
    assert manifest["orin_passthrough"] is True
    assert manifest["rule"] == "unknown_mapping_is_deny_not_allow"
    assert manifest["orin_sot_path"] == "/workspace/orin-abcd/ORIN_ECHO_REASON_CODE_MAP_v0.1.md"

    expected_deny = frozenset(
        {
            "DENY_UNWIRED_NULL_GUARDIAN",
            "DENY_CHAT_ONLY_TOOL_FORBIDDEN",
            "DENY_MAC_MISMATCH",
            "DENY_TIMEOUT",
            "DENY_CONSUME_BEFORE_STAMP",
            "DENY_CONJUNCTION_LETHAL",
            "DENY_CRED_SPENT_OR_UNKNOWN",
            "DENY_MCP_PIN_FROZEN",
            "DENY_MCP_PIN_MISS",
            "DENY_UNIMPLEMENTED_CELL",
            "DENY_SHADOW_REWRITE_BANNED",
            "DENY_ROLE_SCOPE_MISS",
            "DENY_FREEZE",
            "DENY_POLICY",
        }
    )
    assert expected_deny == RELATED_ORIN_HOST_REASON_CODES
    assert not (RELATED_ORIN_HOST_REASON_CODES & BANNED_LEGACY_REASON_CODES)
    # Dual-track old strings must stay red / absent from RELATED.
    for legacy in (
        "local_policy_denied",
        "freeze_active",
        "effect_class_not_granted",
        "intent_expired",
        "no_state_witness",
        "unregistered_or_invalid_manifest",
        "budget_exhausted",
    ):
        assert legacy not in RELATED_ORIN_HOST_REASON_CODES
        assert legacy in BANNED_LEGACY_REASON_CODES
    # BANNED only gates RELATED membership — Echo short codes stay valid.
    assert ECHO_SHORT_CONSUME_BEFORE_STAMP not in BANNED_LEGACY_REASON_CODES
    assert ECHO_SHORT_CONSUME_BEFORE_STAMP == "consume_before_stamp"

    short_rows = orin_to_echo_short_rows()
    assert {r.orin_reason_code for r in short_rows} == expected_deny
    expected_short: dict[str, tuple[str, str]] = {
        "DENY_UNWIRED_NULL_GUARDIAN": (
            ECHO_SHORT_UNWIRED_DENY,
            NEXT_ENABLE_WIRED_OR_CHAT_ONLY,
        ),
        "DENY_CHAT_ONLY_TOOL_FORBIDDEN": (
            ECHO_SHORT_CHAT_ONLY_TOOL_REJECTED,
            NEXT_DISABLE_CHAT_ONLY_AND_WIRE,
        ),
        "DENY_MAC_MISMATCH": (ECHO_SHORT_MAC_MISMATCH, NEXT_INSPECT_GRANTS_ARGS_LEASE),
        "DENY_TIMEOUT": (ECHO_SHORT_STAMP_TIMEOUT, NEXT_RETRY_NOT_SAME_CODE_IN_TURN),
        "DENY_CONSUME_BEFORE_STAMP": (
            ECHO_SHORT_CONSUME_BEFORE_STAMP,
            NEXT_REPORT_DEFECT,
        ),
        "DENY_CONJUNCTION_LETHAL": (ECHO_SHORT_STAMP_DENIED, NEXT_INSPECT_ORIN_DENY_FIELDS),
        "DENY_CRED_SPENT_OR_UNKNOWN": (
            ECHO_SHORT_STAMP_DENIED,
            NEXT_INSPECT_ORIN_DENY_FIELDS,
        ),
        "DENY_MCP_PIN_FROZEN": (ECHO_SHORT_STAMP_DENIED, NEXT_INSPECT_ORIN_DENY_FIELDS),
        "DENY_MCP_PIN_MISS": (ECHO_SHORT_STAMP_DENIED, NEXT_INSPECT_ORIN_DENY_FIELDS),
        "DENY_UNIMPLEMENTED_CELL": (ECHO_SHORT_STAMP_DENIED, NEXT_INSPECT_ORIN_DENY_FIELDS),
        "DENY_SHADOW_REWRITE_BANNED": (
            ECHO_SHORT_STAMP_DENIED,
            NEXT_INSPECT_ORIN_DENY_FIELDS,
        ),
        "DENY_ROLE_SCOPE_MISS": (ECHO_SHORT_STAMP_DENIED, NEXT_INSPECT_ORIN_DENY_FIELDS),
        "DENY_FREEZE": (ECHO_SHORT_STAMP_DENIED, NEXT_INSPECT_ORIN_DENY_FIELDS),
        "DENY_POLICY": (ECHO_SHORT_STAMP_DENIED, NEXT_INSPECT_ORIN_DENY_FIELDS),
    }
    by_orin = {r.orin_reason_code: r for r in short_rows}
    for orin_code, (echo_code, next_action) in expected_short.items():
        assert by_orin[orin_code].echo_reason_code == echo_code
        assert by_orin[orin_code].next_action == next_action
    # Echo short consume_before_stamp remains a valid SoT §2 column value.
    consume = echo_short_reason_for_orin("DENY_CONSUME_BEFORE_STAMP")
    assert consume.echo_reason_code == ECHO_SHORT_CONSUME_BEFORE_STAMP
    assert consume.next_action == NEXT_REPORT_DEFECT

    assert passthrough_orin_reason_code("DENY_FREEZE") == "DENY_FREEZE"
    missing = echo_short_reason_for_orin(None, stamp_path=True)
    assert missing.echo_reason_code == ECHO_SHORT_STAMP_DENIED
    assert missing.next_action == NEXT_INSPECT_ORIN_DENY_FIELDS
    timeout = echo_short_reason_for_orin("DENY_TIMEOUT")
    assert timeout.echo_reason_code == ECHO_SHORT_STAMP_TIMEOUT
    assert timeout.next_action == NEXT_RETRY_NOT_SAME_CODE_IN_TURN
    mac = echo_short_reason_for_orin("DENY_MAC_MISMATCH")
    assert mac.echo_reason_code == ECHO_SHORT_MAC_MISMATCH
    assert mac.next_action == NEXT_INSPECT_GRANTS_ARGS_LEASE

    for code in ProtocolDenyCode:
        row = lookup_protocol_deny_mapping(code)
        assert assert_mapping_denies(code) == row
        assert host_orin_reason_for(code) is None

    with pytest.raises(DenyMappingError, match="unknown ProtocolDenyCode"):
        lookup_protocol_deny_mapping("deepseek_v4.not_a_real_code")
    with pytest.raises(DenyMappingError):
        passthrough_orin_reason_code("local_policy_denied")
    with pytest.raises(DenyMappingError):
        echo_short_reason_for_orin("DENY_NOT_IN_CATALOG")

    doc = (REPO_ROOT / "docs" / "echo" / "DEEPSEEK_V4_TOOL_EDIT_PROTOCOL.md").read_text(
        encoding="utf-8"
    )
    assert "ORIN_ECHO_REASON_CODE_MAP_v0.1.md" in doc
    assert "deny_code_mapping.py" in doc
    sot = (REPO_ROOT / "docs" / "echo" / "ORIN_ECHO_REASON_CODE_MAP_v0.1.md").read_text(
        encoding="utf-8"
    )
    assert "/workspace/orin-abcd/ORIN_ECHO_REASON_CODE_MAP_v0.1.md" in sot
    assert "DENY_UNWIRED_NULL_GUARDIAN" in sot
    assert "unwired_deny" in sot
    assert "chat_only_tool_rejected" in sot
    assert "mac_mismatch" in sot
    assert "consume_before_stamp" in sot
    assert "enable_wired_or_chat_only" in sot
    assert "retry_not_same_code_in_turn" in sot
