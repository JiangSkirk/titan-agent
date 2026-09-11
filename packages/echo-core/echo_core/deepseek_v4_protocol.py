"""DeepSeek V4 tool/edit protocol pin for Echo harness comparison.

Frozen for Minimal-vs-Echo same-model lock (DeepSeek V4 family).

Echo feeds V4 an **OpenAI-compatible function-calling** tool schema with a
**lite default boot surface (≤5 tools)**. Expand-on-demand metadata may
advertise more names; execution remains the D1 chain
(``propose → issue → stamp → durable consume → exec``).

Default profile (``harness_edit``): ``{file_read, file_search, file_edit}``.
Alternate lite profile (not the V4 harness default): ``{file_read, file_search, shell}``.

A second competing edit/tool protocol must not be wired as the **default**
for V4. Soft-fail / ambient allow is forbidden.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final, Mapping

PROTOCOL_VERSION: Final[str] = "echo-deepseek-v4-tool-edit-v1"
ARCHITECTURE_LOCK: Final[str] = "echo-orin-scheme-v0.4.1"
SAME_MODEL_FAMILY: Final[str] = "deepseek-v4"

# Frozen Echo v0.4.1: default advertised boot surface must stay ≤5.
MAX_DEFAULT_TOOL_SURFACE: Final[int] = 5

# Canonical model ids Echo locks for harness comparison.
# Expansion rule (fail-closed): only exact members of this frozenset, plus an
# optional single provider prefix (``vendor/deepseek-v4-flash``). No
# ``deepseek-v4-*`` wildcard — new SKUs must be added here explicitly.
DEEPSEEK_V4_MODEL_IDS: Final[frozenset[str]] = frozenset(
    {
        "deepseek-v4-flash",
        "deepseek-v4-pro",
    }
)

# Allowed members of any lite default profile (v0.4.1).
LITE_CANDIDATE_TOOL_NAMES: Final[frozenset[str]] = frozenset(
    {
        "file_read",
        "file_search",
        "code_search",
        "shell",
        "file_edit",
    }
)

# V4 harness default profile: edit required for Minimal-vs-Echo comparison.
DEFAULT_SURFACE_PROFILE: Final[str] = "harness_edit"
DEFAULT_CORE_TOOL_NAMES: Final[frozenset[str]] = frozenset(
    {
        "file_read",
        "file_search",
        "file_edit",
    }
)
# Alias used by docs/tests.
DEFAULT_LITE_TOOL_NAMES: Final[frozenset[str]] = DEFAULT_CORE_TOOL_NAMES

# Documented alternate lite profile (read/search/shell) — not the V4 default.
ALTERNATE_LITE_TOOL_NAMES: Final[frozenset[str]] = frozenset(
    {
        "file_read",
        "file_search",
        "shell",
    }
)

# Expand-on-demand advertisement metadata only (never ambient boot default).
EXPAND_ON_DEMAND_META_TOOL_NAMES: Final[frozenset[str]] = frozenset(
    {
        "file_write",
        "file_list",
        "file_view",
        "code_search",
        "web_search",
    }
)
EXPAND_ON_DEMAND_EXEC_TOOL_NAMES: Final[frozenset[str]] = frozenset({"shell", "python"})

EDIT_TOOL_NAME: Final[str] = "file_edit"
EDIT_REQUIRED_FIELDS: Final[tuple[str, ...]] = ("path", "search", "replace")


class EditProtocolId(StrEnum):
    """Edit/tool wire formats Echo may speak.

    Only ``OPENAI_FUNCTION_FILE_EDIT`` is the allowed **default** for DeepSeek V4.
    """

    OPENAI_FUNCTION_FILE_EDIT = "openai_function_file_edit"
    ANTHROPIC_TOOL_USE = "anthropic_tool_use"
    APPLY_PATCH = "apply_patch"
    XML_TOOL_CALL = "xml_tool_call"
    STR_REPLACE_EDITOR = "str_replace_editor"


DEFAULT_EDIT_PROTOCOL: Final[EditProtocolId] = EditProtocolId.OPENAI_FUNCTION_FILE_EDIT
COMPETING_EDIT_PROTOCOLS: Final[frozenset[EditProtocolId]] = frozenset(
    {
        EditProtocolId.ANTHROPIC_TOOL_USE,
        EditProtocolId.APPLY_PATCH,
        EditProtocolId.XML_TOOL_CALL,
        EditProtocolId.STR_REPLACE_EDITOR,
    }
)


class ProtocolDenyCode(StrEnum):
    """Fail-closed deny reason codes (never allow-on-soft-fail).

    These are Echo protocol-pin codes. Host/Orin GateKernel ``reason_code``
    strings are a separate plane — see docs mapping. Do not treat a missing
    Orin reason_code as soft-allow for these denials.
    """

    UNKNOWN_MODEL = "deepseek_v4.unknown_model"
    COMPETING_DEFAULT = "deepseek_v4.competing_default_protocol"
    INVALID_TOOL_SCHEMA = "deepseek_v4.invalid_tool_schema"
    INVALID_EDIT_ARGS = "deepseek_v4.invalid_edit_args"
    INVALID_ERROR_SHAPE = "deepseek_v4.invalid_error_shape"
    AMBIENT_EXEC_DEFAULT = "deepseek_v4.ambient_exec_default"
    THICK_DEFAULT_SURFACE = "deepseek_v4.thick_default_surface"


class DeepSeekV4ProtocolError(PermissionError):
    """Protocol pin refused an operation (fail-closed)."""

    def __init__(self, code: ProtocolDenyCode, detail: str) -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code.value}: {detail}")


@dataclass(frozen=True, slots=True)
class ToolErrorEnvelope:
    """Canonical tool error return shape fed back to DeepSeek V4."""

    success: bool
    error: str
    output: str = ""
    metadata: Mapping[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "success": self.success,
            "error": self.error,
            "output": self.output,
        }
        if self.metadata is not None:
            payload["metadata"] = dict(self.metadata)
        return payload


def is_deepseek_v4_model(model_id: str) -> bool:
    """Return True when ``model_id`` is an explicitly locked DeepSeek V4 id.

    Accepts exact ids in :data:`DEEPSEEK_V4_MODEL_IDS` (case-insensitive) or a
    single provider prefix form ``vendor/<id>``. Does **not** accept arbitrary
    ``deepseek-v4-*`` wildcards.
    """

    mid = (model_id or "").strip().lower()
    if not mid:
        return False
    if mid in DEEPSEEK_V4_MODEL_IDS:
        return True
    if "/" in mid:
        _, _, suffix = mid.rpartition("/")
        return suffix in DEEPSEEK_V4_MODEL_IDS
    return False


def require_deepseek_v4_model(model_id: str) -> str:
    """Fail closed unless ``model_id`` is a locked V4 id."""

    if not is_deepseek_v4_model(model_id):
        raise DeepSeekV4ProtocolError(
            ProtocolDenyCode.UNKNOWN_MODEL,
            f"model {model_id!r} is outside the DeepSeek V4 lock "
            f"(explicit ids only: {sorted(DEEPSEEK_V4_MODEL_IDS)})",
        )
    return model_id.strip()


def _assert_lite_profile(names: frozenset[str], *, label: str) -> frozenset[str]:
    """Any lite profile must be ≤5 and ⊆ :data:`LITE_CANDIDATE_TOOL_NAMES`."""

    if len(names) > MAX_DEFAULT_TOOL_SURFACE:
        raise DeepSeekV4ProtocolError(
            ProtocolDenyCode.THICK_DEFAULT_SURFACE,
            f"{label} has {len(names)} tools; max is {MAX_DEFAULT_TOOL_SURFACE}",
        )
    if not names.issubset(LITE_CANDIDATE_TOOL_NAMES):
        raise DeepSeekV4ProtocolError(
            ProtocolDenyCode.THICK_DEFAULT_SURFACE,
            f"{label} must be ⊆ lite candidates {sorted(LITE_CANDIDATE_TOOL_NAMES)}; "
            f"got extras {sorted(names - LITE_CANDIDATE_TOOL_NAMES)}",
        )
    thick = names & EXPAND_ON_DEMAND_META_TOOL_NAMES
    if thick:
        raise DeepSeekV4ProtocolError(
            ProtocolDenyCode.THICK_DEFAULT_SURFACE,
            f"{label} must not include expand-on-demand meta tools {sorted(thick)}",
        )
    return names


def default_tool_surface(*, allow_exec_tools: bool = False) -> frozenset[str]:
    """Default advertised tool names for a V4 turn (lite boot surface).

    Exec tools (shell/python) are never ambient on the harness_edit profile;
    they require explicit opt-in and still must keep the advertised set
    ≤ :data:`MAX_DEFAULT_TOOL_SURFACE`.
    """

    names = set(DEFAULT_CORE_TOOL_NAMES)
    if allow_exec_tools:
        names |= set(EXPAND_ON_DEMAND_EXEC_TOOL_NAMES)
    surface = frozenset(names)
    if len(surface) > MAX_DEFAULT_TOOL_SURFACE:
        raise DeepSeekV4ProtocolError(
            ProtocolDenyCode.THICK_DEFAULT_SURFACE,
            f"default_tool_surface has {len(surface)} tools; "
            f"max is {MAX_DEFAULT_TOOL_SURFACE}",
        )
    thick = surface & EXPAND_ON_DEMAND_META_TOOL_NAMES
    if thick:
        raise DeepSeekV4ProtocolError(
            ProtocolDenyCode.THICK_DEFAULT_SURFACE,
            f"default_tool_surface must not include meta expand tools {sorted(thick)}",
        )
    if not allow_exec_tools and surface & EXPAND_ON_DEMAND_EXEC_TOOL_NAMES:
        raise DeepSeekV4ProtocolError(
            ProtocolDenyCode.AMBIENT_EXEC_DEFAULT,
            "default_tool_surface must not ambient-advertise exec tools",
        )
    allowed = set(LITE_CANDIDATE_TOOL_NAMES)
    if allow_exec_tools:
        allowed |= set(EXPAND_ON_DEMAND_EXEC_TOOL_NAMES)
    if not surface.issubset(allowed):
        raise DeepSeekV4ProtocolError(
            ProtocolDenyCode.THICK_DEFAULT_SURFACE,
            f"default_tool_surface extras {sorted(surface - allowed)}",
        )
    return surface


def require_default_edit_protocol(protocol: EditProtocolId | str) -> EditProtocolId:
    """Fail closed if a competing edit protocol is selected as default for V4."""

    try:
        parsed = protocol if isinstance(protocol, EditProtocolId) else EditProtocolId(str(protocol))
    except ValueError as exc:
        raise DeepSeekV4ProtocolError(
            ProtocolDenyCode.COMPETING_DEFAULT,
            f"unknown edit protocol {protocol!r}",
        ) from exc
    if parsed is not DEFAULT_EDIT_PROTOCOL:
        raise DeepSeekV4ProtocolError(
            ProtocolDenyCode.COMPETING_DEFAULT,
            f"{parsed.value} must not be the DeepSeek V4 default "
            f"(required {DEFAULT_EDIT_PROTOCOL.value})",
        )
    return parsed


def assert_no_competing_default(protocol: EditProtocolId | str) -> None:
    """Red-light any competing protocol wired as the V4 default."""

    require_default_edit_protocol(protocol)


def validate_openai_tool_schema(schema: Mapping[str, Any]) -> str:
    """Validate one OpenAI function-calling tool schema Echo feeds to V4.

    Required shape::

        {"type": "function", "function": {"name": ..., "description": ...,
         "parameters": {"type": "object", "properties": {...}, "required": [...]}}}
    """

    if schema.get("type") != "function":
        raise DeepSeekV4ProtocolError(
            ProtocolDenyCode.INVALID_TOOL_SCHEMA,
            "tool schema type must be 'function'",
        )
    function = schema.get("function")
    if not isinstance(function, Mapping):
        raise DeepSeekV4ProtocolError(
            ProtocolDenyCode.INVALID_TOOL_SCHEMA,
            "tool schema missing function object",
        )
    name = function.get("name")
    if not isinstance(name, str) or not name:
        raise DeepSeekV4ProtocolError(
            ProtocolDenyCode.INVALID_TOOL_SCHEMA,
            "tool schema function.name required",
        )
    if "description" not in function:
        raise DeepSeekV4ProtocolError(
            ProtocolDenyCode.INVALID_TOOL_SCHEMA,
            "tool schema function.description required",
        )
    parameters = function.get("parameters")
    if not isinstance(parameters, Mapping):
        raise DeepSeekV4ProtocolError(
            ProtocolDenyCode.INVALID_TOOL_SCHEMA,
            "tool schema function.parameters required",
        )
    if parameters.get("type") != "object":
        raise DeepSeekV4ProtocolError(
            ProtocolDenyCode.INVALID_TOOL_SCHEMA,
            "parameters.type must be 'object'",
        )
    if "properties" not in parameters or not isinstance(parameters["properties"], Mapping):
        raise DeepSeekV4ProtocolError(
            ProtocolDenyCode.INVALID_TOOL_SCHEMA,
            "parameters.properties required",
        )
    required = parameters.get("required", [])
    if not isinstance(required, list):
        raise DeepSeekV4ProtocolError(
            ProtocolDenyCode.INVALID_TOOL_SCHEMA,
            "parameters.required must be a list when present",
        )
    return name


def validate_edit_arguments(arguments: Mapping[str, Any]) -> dict[str, str]:
    """Validate ``file_edit`` arguments under the pinned edit protocol."""

    missing = [field for field in EDIT_REQUIRED_FIELDS if field not in arguments]
    if missing:
        raise DeepSeekV4ProtocolError(
            ProtocolDenyCode.INVALID_EDIT_ARGS,
            f"file_edit missing required fields: {', '.join(missing)}",
        )
    normalized: dict[str, str] = {}
    for field in EDIT_REQUIRED_FIELDS:
        value = arguments[field]
        if not isinstance(value, str) or not value:
            raise DeepSeekV4ProtocolError(
                ProtocolDenyCode.INVALID_EDIT_ARGS,
                f"file_edit.{field} must be a non-empty string",
            )
        normalized[field] = value
    return normalized


def tool_error_envelope(
    *, error: str, output: str = "", metadata: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    """Build the fail-closed tool error payload returned to V4."""

    if not error:
        raise DeepSeekV4ProtocolError(
            ProtocolDenyCode.INVALID_ERROR_SHAPE,
            "tool error envelope requires a non-empty error string",
        )
    return ToolErrorEnvelope(
        success=False,
        error=error,
        output=output,
        metadata=metadata,
    ).to_dict()


def validate_tool_error_envelope(payload: Mapping[str, Any]) -> None:
    """Fail closed if an error return does not match the pinned shape."""

    if payload.get("success") is not False:
        raise DeepSeekV4ProtocolError(
            ProtocolDenyCode.INVALID_ERROR_SHAPE,
            "error envelope success must be false",
        )
    error = payload.get("error")
    if not isinstance(error, str) or not error:
        raise DeepSeekV4ProtocolError(
            ProtocolDenyCode.INVALID_ERROR_SHAPE,
            "error envelope requires non-empty error string",
        )
    if "output" in payload and not isinstance(payload["output"], str):
        raise DeepSeekV4ProtocolError(
            ProtocolDenyCode.INVALID_ERROR_SHAPE,
            "error envelope output must be a string when present",
        )


def file_edit_openai_schema() -> dict[str, Any]:
    """Canonical ``file_edit`` schema Echo advertises to DeepSeek V4."""

    return {
        "type": "function",
        "function": {
            "name": EDIT_TOOL_NAME,
            "description": (
                "Precisely edit a file by replacing a unique search block with new content. "
                "The search block must match exactly (including whitespace)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Path to the file to edit"},
                    "search": {
                        "type": "string",
                        "description": "Exact text block to search for",
                    },
                    "replace": {
                        "type": "string",
                        "description": "Replacement text block",
                    },
                },
                "required": list(EDIT_REQUIRED_FIELDS),
            },
        },
    }


def protocol_manifest() -> dict[str, Any]:
    """Stable manifest for docs, benches, and contract tests."""

    return {
        "protocol_version": PROTOCOL_VERSION,
        "architecture_lock": ARCHITECTURE_LOCK,
        "same_model_family": SAME_MODEL_FAMILY,
        "model_ids": sorted(DEEPSEEK_V4_MODEL_IDS),
        "model_id_expansion": "exact_or_single_provider_prefix_only",
        "default_surface_profile": DEFAULT_SURFACE_PROFILE,
        "default_edit_protocol": DEFAULT_EDIT_PROTOCOL.value,
        "competing_edit_protocols": sorted(p.value for p in COMPETING_EDIT_PROTOCOLS),
        "max_default_tool_surface": MAX_DEFAULT_TOOL_SURFACE,
        "default_core_tools": sorted(DEFAULT_CORE_TOOL_NAMES),
        "alternate_lite_tools": sorted(ALTERNATE_LITE_TOOL_NAMES),
        "lite_candidates": sorted(LITE_CANDIDATE_TOOL_NAMES),
        "expand_on_demand_meta_tools": sorted(EXPAND_ON_DEMAND_META_TOOL_NAMES),
        "expand_on_demand_exec_tools": sorted(EXPAND_ON_DEMAND_EXEC_TOOL_NAMES),
        "edit_tool": EDIT_TOOL_NAME,
        "edit_required_fields": list(EDIT_REQUIRED_FIELDS),
        "error_envelope_fields": ["success", "error", "output", "metadata"],
        "execution_boundary": "d1_admit_stamp_consume_exec",
    }


# Module import-time freeze: thick defaults fail closed before any Host wiring.
_assert_lite_profile(DEFAULT_CORE_TOOL_NAMES, label="DEFAULT_CORE_TOOL_NAMES")
_assert_lite_profile(ALTERNATE_LITE_TOOL_NAMES, label="ALTERNATE_LITE_TOOL_NAMES")
if DEFAULT_CORE_TOOL_NAMES & EXPAND_ON_DEMAND_EXEC_TOOL_NAMES:
    raise DeepSeekV4ProtocolError(
        ProtocolDenyCode.AMBIENT_EXEC_DEFAULT,
        "harness_edit default must not ambient-include shell/python",
    )

__all__ = [
    "ALTERNATE_LITE_TOOL_NAMES",
    "ARCHITECTURE_LOCK",
    "COMPETING_EDIT_PROTOCOLS",
    "DEFAULT_CORE_TOOL_NAMES",
    "DEFAULT_EDIT_PROTOCOL",
    "DEFAULT_LITE_TOOL_NAMES",
    "DEFAULT_SURFACE_PROFILE",
    "DEEPSEEK_V4_MODEL_IDS",
    "DeepSeekV4ProtocolError",
    "EDIT_REQUIRED_FIELDS",
    "EDIT_TOOL_NAME",
    "EXPAND_ON_DEMAND_EXEC_TOOL_NAMES",
    "EXPAND_ON_DEMAND_META_TOOL_NAMES",
    "EditProtocolId",
    "LITE_CANDIDATE_TOOL_NAMES",
    "MAX_DEFAULT_TOOL_SURFACE",
    "PROTOCOL_VERSION",
    "ProtocolDenyCode",
    "SAME_MODEL_FAMILY",
    "ToolErrorEnvelope",
    "assert_no_competing_default",
    "default_tool_surface",
    "file_edit_openai_schema",
    "is_deepseek_v4_model",
    "protocol_manifest",
    "require_deepseek_v4_model",
    "require_default_edit_protocol",
    "tool_error_envelope",
    "validate_edit_arguments",
    "validate_openai_tool_schema",
    "validate_tool_error_envelope",
]
