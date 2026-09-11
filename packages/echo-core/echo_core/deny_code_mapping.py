"""Dual-track deny mapping: Orin ``DENY_*`` ↔ Echo short ``reason_code``.

**Orin SoT (authoritative):** ``/workspace/orin-abcd/ORIN_ECHO_REASON_CODE_MAP_v0.1.md``
**Echo citation copy:** ``docs/echo/ORIN_ECHO_REASON_CODE_MAP_v0.1.md``

Rules (v0.1):

* Orin owns ``DENY_*`` as ``orin_reason_code`` — **passthrough; Echo must not rewrite**.
* Echo owns the short ``reason_code`` column in SoT §2.
* ``RELATED_ORIN_HOST_REASON_CODES`` equals the Orin ``DENY_*`` catalog only.
* Missing ``orin_reason_code`` on the stamp path → fail-closed ``stamp_denied``.
* Unknown mapping ≠ allow.
* ``ProtocolDenyCode`` (DeepSeek V4 pin) rows stay Echo-only
  (``host_orin_reason_code=None``) — orthogonal to Orin ``DENY_*``.

This module is a **mapping table only**. It does not create a second authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final, Mapping

from echo_core.deepseek_v4_protocol import ProtocolDenyCode

MAPPING_VERSION: Final[str] = "orin-echo-reason-code-map-v0.1"
ORIN_SOT_PATH: Final[str] = "/workspace/orin-abcd/ORIN_ECHO_REASON_CODE_MAP_v0.1.md"
ECHO_CITATION_DOC: Final[str] = "docs/echo/ORIN_ECHO_REASON_CODE_MAP_v0.1.md"

# Echo-owned short reason_code values (SoT §2).
ECHO_SHORT_UNWIRED_DENY: Final[str] = "unwired_deny"
ECHO_SHORT_CHAT_ONLY_TOOL_REJECTED: Final[str] = "chat_only_tool_rejected"
ECHO_SHORT_MAC_MISMATCH: Final[str] = "mac_mismatch"
ECHO_SHORT_STAMP_TIMEOUT: Final[str] = "stamp_timeout"
ECHO_SHORT_CONSUME_BEFORE_STAMP: Final[str] = "consume_before_stamp"
ECHO_SHORT_STAMP_DENIED: Final[str] = "stamp_denied"

# Echo-owned next_action values (SoT §2).
NEXT_ENABLE_WIRED_OR_CHAT_ONLY: Final[str] = "enable_wired_or_chat_only"
NEXT_DISABLE_CHAT_ONLY_AND_WIRE: Final[str] = "disable_chat_only_and_wire"
NEXT_INSPECT_GRANTS_ARGS_LEASE: Final[str] = "inspect_grants_args_lease"
NEXT_RETRY_NOT_SAME_CODE_IN_TURN: Final[str] = "retry_not_same_code_in_turn"
NEXT_REPORT_DEFECT: Final[str] = "report_defect"
NEXT_INSPECT_ORIN_DENY_FIELDS: Final[str] = "inspect_orin_deny_fields"
DEFAULT_NEXT_ACTION: Final[str] = NEXT_INSPECT_ORIN_DENY_FIELDS

# Banned legacy Orin/js dual-track leftovers. Purpose: gate membership of
# RELATED_ORIN_HOST_REASON_CODES (Orin DENY_* catalog) only — NEVER ban Echo
# short-code column values from SoT §2 (e.g. ``consume_before_stamp``,
# ``unwired_deny``, ``mac_mismatch``, ``stamp_timeout``, …).
BANNED_LEGACY_REASON_CODES: Final[frozenset[str]] = frozenset(
    {
        "local_policy_denied",
        "freeze_active",
        "budget_exhausted",
        "effect_class_not_granted",
        "intent_expired",
        "no_state_witness",
        "unregistered_or_invalid_manifest",
    }
)


class DenyMappingError(PermissionError):
    """Deny-code mapping refused an operation (fail-closed; never allow)."""


class MappingPlane(StrEnum):
    """Where the denial is owned."""

    ECHO_PIN = "echo_pin"
    ORIN_PASSTHROUGH = "orin_passthrough"


@dataclass(frozen=True, slots=True)
class DenyCodeMappingRow:
    """One Echo ``ProtocolDenyCode`` row (orthogonal to Orin ``DENY_*``).

    ``host_orin_reason_code`` stays ``None`` for Echo-pin rows — they are not
    Orin GateKernel codes and must not rewrite Orin ``DENY_*``.
    """

    protocol_deny_code: str
    host_orin_reason_code: str | None
    plane: MappingPlane
    notes: str


@dataclass(frozen=True, slots=True)
class OrinEchoShortMapping:
    """One SoT §2 Orin → Echo short-code row."""

    orin_reason_code: str
    echo_reason_code: str
    next_action: str


# Orin-owned DENY_* catalog (SoT §1). Passthrough — Echo must not rewrite.
RELATED_ORIN_HOST_REASON_CODES: Final[frozenset[str]] = frozenset(
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

# SoT §2 — Orin DENY_* → Echo short reason_code (Echo-owned column; exact 1:1).
_ORIN_TO_ECHO_SHORT_ROWS: Final[tuple[OrinEchoShortMapping, ...]] = (
    OrinEchoShortMapping(
        "DENY_UNWIRED_NULL_GUARDIAN",
        ECHO_SHORT_UNWIRED_DENY,
        NEXT_ENABLE_WIRED_OR_CHAT_ONLY,
    ),
    OrinEchoShortMapping(
        "DENY_CHAT_ONLY_TOOL_FORBIDDEN",
        ECHO_SHORT_CHAT_ONLY_TOOL_REJECTED,
        NEXT_DISABLE_CHAT_ONLY_AND_WIRE,
    ),
    OrinEchoShortMapping(
        "DENY_MAC_MISMATCH",
        ECHO_SHORT_MAC_MISMATCH,
        NEXT_INSPECT_GRANTS_ARGS_LEASE,
    ),
    OrinEchoShortMapping(
        "DENY_TIMEOUT",
        ECHO_SHORT_STAMP_TIMEOUT,
        NEXT_RETRY_NOT_SAME_CODE_IN_TURN,
    ),
    OrinEchoShortMapping(
        "DENY_CONSUME_BEFORE_STAMP",
        ECHO_SHORT_CONSUME_BEFORE_STAMP,
        NEXT_REPORT_DEFECT,
    ),
    OrinEchoShortMapping(
        "DENY_CONJUNCTION_LETHAL",
        ECHO_SHORT_STAMP_DENIED,
        NEXT_INSPECT_ORIN_DENY_FIELDS,
    ),
    OrinEchoShortMapping(
        "DENY_CRED_SPENT_OR_UNKNOWN",
        ECHO_SHORT_STAMP_DENIED,
        NEXT_INSPECT_ORIN_DENY_FIELDS,
    ),
    OrinEchoShortMapping(
        "DENY_MCP_PIN_FROZEN",
        ECHO_SHORT_STAMP_DENIED,
        NEXT_INSPECT_ORIN_DENY_FIELDS,
    ),
    OrinEchoShortMapping(
        "DENY_MCP_PIN_MISS",
        ECHO_SHORT_STAMP_DENIED,
        NEXT_INSPECT_ORIN_DENY_FIELDS,
    ),
    OrinEchoShortMapping(
        "DENY_UNIMPLEMENTED_CELL",
        ECHO_SHORT_STAMP_DENIED,
        NEXT_INSPECT_ORIN_DENY_FIELDS,
    ),
    OrinEchoShortMapping(
        "DENY_SHADOW_REWRITE_BANNED",
        ECHO_SHORT_STAMP_DENIED,
        NEXT_INSPECT_ORIN_DENY_FIELDS,
    ),
    OrinEchoShortMapping(
        "DENY_ROLE_SCOPE_MISS",
        ECHO_SHORT_STAMP_DENIED,
        NEXT_INSPECT_ORIN_DENY_FIELDS,
    ),
    OrinEchoShortMapping(
        "DENY_FREEZE",
        ECHO_SHORT_STAMP_DENIED,
        NEXT_INSPECT_ORIN_DENY_FIELDS,
    ),
    OrinEchoShortMapping(
        "DENY_POLICY",
        ECHO_SHORT_STAMP_DENIED,
        NEXT_INSPECT_ORIN_DENY_FIELDS,
    ),
)

_ORIN_TO_ECHO: Final[Mapping[str, OrinEchoShortMapping]] = {
    row.orin_reason_code: row for row in _ORIN_TO_ECHO_SHORT_ROWS
}

# Echo-pin ProtocolDenyCode rows — all Echo-only (no Orin DENY_* rewrite).
_PROTOCOL_DENY_CODE_ROWS: Final[tuple[DenyCodeMappingRow, ...]] = (
    DenyCodeMappingRow(
        protocol_deny_code=ProtocolDenyCode.UNKNOWN_MODEL.value,
        host_orin_reason_code=None,
        plane=MappingPlane.ECHO_PIN,
        notes="Echo-pin only; outside DeepSeek V4 lock.",
    ),
    DenyCodeMappingRow(
        protocol_deny_code=ProtocolDenyCode.COMPETING_DEFAULT.value,
        host_orin_reason_code=None,
        plane=MappingPlane.ECHO_PIN,
        notes="Echo-pin only; competing edit protocol as V4 default.",
    ),
    DenyCodeMappingRow(
        protocol_deny_code=ProtocolDenyCode.INVALID_TOOL_SCHEMA.value,
        host_orin_reason_code=None,
        plane=MappingPlane.ECHO_PIN,
        notes="Echo-pin only; OpenAI FC schema shape invalid.",
    ),
    DenyCodeMappingRow(
        protocol_deny_code=ProtocolDenyCode.INVALID_EDIT_ARGS.value,
        host_orin_reason_code=None,
        plane=MappingPlane.ECHO_PIN,
        notes="Echo-pin only; file_edit path/search/replace invalid.",
    ),
    DenyCodeMappingRow(
        protocol_deny_code=ProtocolDenyCode.INVALID_ERROR_SHAPE.value,
        host_orin_reason_code=None,
        plane=MappingPlane.ECHO_PIN,
        notes="Echo-pin only; tool error envelope invalid.",
    ),
    DenyCodeMappingRow(
        protocol_deny_code=ProtocolDenyCode.AMBIENT_EXEC_DEFAULT.value,
        host_orin_reason_code=None,
        plane=MappingPlane.ECHO_PIN,
        notes="Echo-pin only; shell/python ambient on harness_edit.",
    ),
    DenyCodeMappingRow(
        protocol_deny_code=ProtocolDenyCode.THICK_DEFAULT_SURFACE.value,
        host_orin_reason_code=None,
        plane=MappingPlane.ECHO_PIN,
        notes="Echo-pin only; default boot surface exceeds lite ≤5.",
    ),
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
    if set(_ORIN_TO_ECHO) != set(RELATED_ORIN_HOST_REASON_CODES):
        raise DenyMappingError(
            "Orin→Echo short-code table must cover RELATED_ORIN_HOST_REASON_CODES exactly"
        )
    if RELATED_ORIN_HOST_REASON_CODES & BANNED_LEGACY_REASON_CODES:
        raise DenyMappingError(
            "RELATED_ORIN_HOST_REASON_CODES contains banned legacy dual-track strings"
        )
    if any(not code.startswith("DENY_") for code in RELATED_ORIN_HOST_REASON_CODES):
        raise DenyMappingError("RELATED set must be Orin DENY_* catalog only")


_require_complete_coverage()


def protocol_deny_code_mapping_rows() -> tuple[DenyCodeMappingRow, ...]:
    """Return Echo-pin ProtocolDenyCode rows (orthogonal to Orin DENY_*)."""

    return _PROTOCOL_DENY_CODE_ROWS


def orin_to_echo_short_rows() -> tuple[OrinEchoShortMapping, ...]:
    """Return SoT §2 Orin → Echo short-code rows."""

    return _ORIN_TO_ECHO_SHORT_ROWS


def lookup_protocol_deny_mapping(code: ProtocolDenyCode | str) -> DenyCodeMappingRow:
    """Look up one Echo-pin mapping row. Unknown codes raise (never allow)."""

    key = code.value if isinstance(code, ProtocolDenyCode) else str(code)
    row = _BY_PROTOCOL_CODE.get(key)
    if row is None:
        raise DenyMappingError(
            f"unknown ProtocolDenyCode {key!r}; unknown mapping is deny, not allow"
        )
    return row


def host_orin_reason_for(code: ProtocolDenyCode | str) -> str | None:
    """Echo-pin rows always return None (no Orin DENY_* rewrite)."""

    return lookup_protocol_deny_mapping(code).host_orin_reason_code


def assert_mapping_denies(code: ProtocolDenyCode | str) -> DenyCodeMappingRow:
    """Fail-closed helper: resolve Echo-pin mapping (never allow-on-soft-fail)."""

    row = lookup_protocol_deny_mapping(code)
    if row.protocol_deny_code not in _BY_PROTOCOL_CODE:
        raise DenyMappingError("mapped row vanished; refuse allow-on-soft-fail")
    return row


def passthrough_orin_reason_code(orin_reason_code: str) -> str:
    """Return Orin ``DENY_*`` unchanged. Unknown codes fail closed (never allow)."""

    code = (orin_reason_code or "").strip()
    if code not in RELATED_ORIN_HOST_REASON_CODES:
        raise DenyMappingError(
            f"unknown orin_reason_code {orin_reason_code!r}; "
            "Echo must not invent DENY_* codes; unknown is deny"
        )
    return code


def echo_short_reason_for_orin(
    orin_reason_code: str | None,
    *,
    stamp_path: bool = True,
) -> OrinEchoShortMapping:
    """Map Orin ``orin_reason_code`` → Echo short ``reason_code`` (SoT §2).

    Missing/empty on the stamp path → fail-closed ``stamp_denied``.
    Orin code is never rewritten; callers must keep passthrough separately.
    """

    if orin_reason_code is None or not str(orin_reason_code).strip():
        if stamp_path:
            return OrinEchoShortMapping(
                orin_reason_code="",
                echo_reason_code=ECHO_SHORT_STAMP_DENIED,
                next_action=DEFAULT_NEXT_ACTION,
            )
        raise DenyMappingError("missing orin_reason_code; refuse allow-on-soft-fail")
    code = passthrough_orin_reason_code(str(orin_reason_code))
    return _ORIN_TO_ECHO[code]


def mapping_manifest() -> dict[str, object]:
    """Machine-readable dual-track digest for docs/tests."""

    return {
        "mapping_version": MAPPING_VERSION,
        "orin_sot_path": ORIN_SOT_PATH,
        "echo_citation_doc": ECHO_CITATION_DOC,
        "rule": "unknown_mapping_is_deny_not_allow",
        "orin_passthrough": True,
        "second_authority": False,
        "related_orin_host_reason_codes": sorted(RELATED_ORIN_HOST_REASON_CODES),
        "orin_to_echo_short": [
            {
                "orin_reason_code": row.orin_reason_code,
                "echo_reason_code": row.echo_reason_code,
                "next_action": row.next_action,
            }
            for row in _ORIN_TO_ECHO_SHORT_ROWS
        ],
        "protocol_deny_code_rows": [
            {
                "protocol_deny_code": row.protocol_deny_code,
                "host_orin_reason_code": row.host_orin_reason_code,
                "plane": row.plane.value,
                "notes": row.notes,
            }
            for row in _PROTOCOL_DENY_CODE_ROWS
        ],
        "banned_legacy_reason_codes": sorted(BANNED_LEGACY_REASON_CODES),
    }


__all__ = [
    "BANNED_LEGACY_REASON_CODES",
    "DEFAULT_NEXT_ACTION",
    "ECHO_CITATION_DOC",
    "ECHO_SHORT_CHAT_ONLY_TOOL_REJECTED",
    "ECHO_SHORT_CONSUME_BEFORE_STAMP",
    "ECHO_SHORT_MAC_MISMATCH",
    "ECHO_SHORT_STAMP_DENIED",
    "ECHO_SHORT_STAMP_TIMEOUT",
    "ECHO_SHORT_UNWIRED_DENY",
    "MAPPING_VERSION",
    "NEXT_DISABLE_CHAT_ONLY_AND_WIRE",
    "NEXT_ENABLE_WIRED_OR_CHAT_ONLY",
    "NEXT_INSPECT_GRANTS_ARGS_LEASE",
    "NEXT_INSPECT_ORIN_DENY_FIELDS",
    "NEXT_REPORT_DEFECT",
    "NEXT_RETRY_NOT_SAME_CODE_IN_TURN",
    "ORIN_SOT_PATH",
    "RELATED_ORIN_HOST_REASON_CODES",
    "DenyCodeMappingRow",
    "DenyMappingError",
    "MappingPlane",
    "OrinEchoShortMapping",
    "assert_mapping_denies",
    "echo_short_reason_for_orin",
    "host_orin_reason_for",
    "lookup_protocol_deny_mapping",
    "mapping_manifest",
    "orin_to_echo_short_rows",
    "passthrough_orin_reason_code",
    "protocol_deny_code_mapping_rows",
]
