"""Single source of truth: ``ProtocolDenyCode`` ↔ Host/Orin ``reason_code``.

This module is a **mapping table only**. It does not create a second authority
plane, does not stamp leases, and does not soft-allow anything.

Fail-closed rules:

* Every ``ProtocolDenyCode`` must have exactly one row.
* Looking up an unknown deny code raises (never returns allow).
* ``host_orin_reason_code is None`` means Echo-pin-only — still a denial.
* Presence or absence of an Orin/Host ``reason_code`` never upgrades a pin
  denial to allow.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final, Mapping

from echo_core.deepseek_v4_protocol import ProtocolDenyCode

MAPPING_VERSION: Final[str] = "echo-deny-code-map-v1"


class DenyMappingError(PermissionError):
    """Deny-code mapping refused an operation (fail-closed; never allow)."""


class MappingPlane(StrEnum):
    """Where the denial is owned."""

    ECHO_PIN = "echo_pin"
    HOST_ADVERTISING = "host_advertising"
    RELATED_ORIN = "related_orin_observability"


@dataclass(frozen=True, slots=True)
class DenyCodeMappingRow:
    """One ProtocolDenyCode row in the SSOT table.

    ``host_orin_reason_code`` is the closest Host/Orin ``reason_code`` string
    when one exists for observability correlation. ``None`` means Echo-pin-only
    (no Orin GateKernel ticket equivalent). A ``None`` mapping is still deny.
    """

    protocol_deny_code: str
    host_orin_reason_code: str | None
    plane: MappingPlane
    notes: str


# SSOT rows — keep in sync with ProtocolDenyCode members.
_PROTOCOL_DENY_CODE_ROWS: Final[tuple[DenyCodeMappingRow, ...]] = (
    DenyCodeMappingRow(
        protocol_deny_code=ProtocolDenyCode.UNKNOWN_MODEL.value,
        host_orin_reason_code=None,
        plane=MappingPlane.ECHO_PIN,
        notes="Model outside DeepSeek V4 lock; not an Orin GateKernel ticket.",
    ),
    DenyCodeMappingRow(
        protocol_deny_code=ProtocolDenyCode.COMPETING_DEFAULT.value,
        host_orin_reason_code=None,
        plane=MappingPlane.ECHO_PIN,
        notes="Competing edit/tool wire format selected as V4 default.",
    ),
    DenyCodeMappingRow(
        protocol_deny_code=ProtocolDenyCode.INVALID_TOOL_SCHEMA.value,
        host_orin_reason_code=None,
        plane=MappingPlane.ECHO_PIN,
        notes="OpenAI function-calling schema shape invalid for V4 feed.",
    ),
    DenyCodeMappingRow(
        protocol_deny_code=ProtocolDenyCode.INVALID_EDIT_ARGS.value,
        host_orin_reason_code=None,
        plane=MappingPlane.ECHO_PIN,
        notes="file_edit missing/invalid path|search|replace.",
    ),
    DenyCodeMappingRow(
        protocol_deny_code=ProtocolDenyCode.INVALID_ERROR_SHAPE.value,
        host_orin_reason_code=None,
        plane=MappingPlane.ECHO_PIN,
        notes="Tool error envelope missing success=false or non-empty error.",
    ),
    DenyCodeMappingRow(
        protocol_deny_code=ProtocolDenyCode.AMBIENT_EXEC_DEFAULT.value,
        host_orin_reason_code="echo_exec_tools_required",
        plane=MappingPlane.HOST_ADVERTISING,
        notes=(
            "shell/python ambient on harness_edit. Host correlates with "
            "SecurityConfig.echo_exec_tools=false. Orin may separately emit "
            "local_policy_denied; that code must not soft-allow this pin denial."
        ),
    ),
    DenyCodeMappingRow(
        protocol_deny_code=ProtocolDenyCode.THICK_DEFAULT_SURFACE.value,
        host_orin_reason_code="echo_tool_surface_exceeds_lite",
        plane=MappingPlane.HOST_ADVERTISING,
        notes=(
            "Default boot surface >5 or includes expand-on-demand meta tools. "
            "Host advertising only; not an Orin stamp/consume reason."
        ),
    ),
)

# Adjacent Orin/Host reason_code / message tokens operators may see near D1.
# Listed for correlation only — none of these authorize a ProtocolDenyCode.
RELATED_ORIN_HOST_REASON_CODES: Final[frozenset[str]] = frozenset(
    {
        # js/orind GateDecision.reason_code samples (Orin-owned).
        "local_policy_denied",
        "freeze_active",
        "budget_exhausted",
        "effect_class_not_granted",
        "intent_expired",
        "no_state_witness",
        "unregistered_or_invalid_manifest",
        # Host Echo EffectAuthority / bind message fragments (not GateKernel codes).
        "bypasses_echo_effect_authority",
        "chat_only_path_denies_sink_effects",
        "refuse_ambient_effect",
        "enabled_without_enforce",
        "exec_without_stamp",
        "consume_before_stamp",
        # Host advertising correlates used in this mapping table.
        "echo_exec_tools_required",
        "echo_tool_surface_exceeds_lite",
    }
)

_BY_PROTOCOL_CODE: Final[Mapping[str, DenyCodeMappingRow]] = {
    row.protocol_deny_code: row for row in _PROTOCOL_DENY_CODE_ROWS
}


def _require_complete_coverage() -> None:
    missing = {c.value for c in ProtocolDenyCode} - set(_BY_PROTOCOL_CODE)
    if missing:
        raise DenyMappingError(
            f"deny-code mapping incomplete; missing rows for {sorted(missing)}"
        )
    if len(_BY_PROTOCOL_CODE) != len(_PROTOCOL_DENY_CODE_ROWS):
        raise DenyMappingError("deny-code mapping has duplicate protocol_deny_code rows")


_require_complete_coverage()


def protocol_deny_code_mapping_rows() -> tuple[DenyCodeMappingRow, ...]:
    """Return the frozen SSOT mapping rows."""

    return _PROTOCOL_DENY_CODE_ROWS


def lookup_protocol_deny_mapping(code: ProtocolDenyCode | str) -> DenyCodeMappingRow:
    """Look up one mapping row. Unknown codes raise (never allow)."""

    key = code.value if isinstance(code, ProtocolDenyCode) else str(code)
    row = _BY_PROTOCOL_CODE.get(key)
    if row is None:
        raise DenyMappingError(
            f"unknown ProtocolDenyCode {key!r}; unknown mapping is deny, not allow"
        )
    return row


def host_orin_reason_for(code: ProtocolDenyCode | str) -> str | None:
    """Return the mapped Host/Orin reason_code, or None for Echo-pin-only.

    ``None`` still means deny. Unknown codes raise ``DenyMappingError``.
    """

    return lookup_protocol_deny_mapping(code).host_orin_reason_code


def assert_mapping_denies(code: ProtocolDenyCode | str) -> DenyCodeMappingRow:
    """Fail-closed helper: resolve mapping and assert it is not an allow path."""

    row = lookup_protocol_deny_mapping(code)
    # Mapping rows are denials by definition; this exists so call sites cannot
    # "soft succeed" on a missing Orin reason_code.
    if row.protocol_deny_code not in _BY_PROTOCOL_CODE:
        raise DenyMappingError("mapped row vanished; refuse allow-on-soft-fail")
    return row


def mapping_manifest() -> dict[str, object]:
    """Machine-readable SSOT digest for docs/tests."""

    return {
        "mapping_version": MAPPING_VERSION,
        "rule": "unknown_mapping_is_deny_not_allow",
        "second_authority": False,
        "rows": [
            {
                "protocol_deny_code": row.protocol_deny_code,
                "host_orin_reason_code": row.host_orin_reason_code,
                "plane": row.plane.value,
                "notes": row.notes,
            }
            for row in _PROTOCOL_DENY_CODE_ROWS
        ],
        "related_orin_host_reason_codes": sorted(RELATED_ORIN_HOST_REASON_CODES),
    }


__all__ = [
    "RELATED_ORIN_HOST_REASON_CODES",
    "DenyCodeMappingRow",
    "DenyMappingError",
    "MAPPING_VERSION",
    "MappingPlane",
    "assert_mapping_denies",
    "host_orin_reason_for",
    "lookup_protocol_deny_mapping",
    "mapping_manifest",
    "protocol_deny_code_mapping_rows",
]
