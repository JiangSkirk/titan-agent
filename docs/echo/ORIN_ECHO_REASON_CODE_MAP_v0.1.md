# Orin ↔ Echo reason_code map v0.1

**Orin SoT path (authoritative):** `/workspace/orin-abcd/ORIN_ECHO_REASON_CODE_MAP_v0.1.md`  
**Echo citation copy:** this file (`docs/echo/ORIN_ECHO_REASON_CODE_MAP_v0.1.md`)  
**Echo code mirror:** `packages/echo-core/echo_core/deny_code_mapping.py`

This document is a **citation / dual-track contract mirror**. Orin owns the
`DENY_*` catalog as `orin_reason_code` (**passthrough — Echo must not rewrite**).
Echo owns the short `reason_code` column below. This is **not** a second
authority plane.

Fail-closed: missing `orin_reason_code` on the stamp path → Echo short code
`stamp_denied`. Unknown mapping ≠ allow.

## §1 Orin `DENY_*` catalog (`orin_reason_code`, passthrough)

| `orin_reason_code` (Orin-owned) |
| --- |
| `DENY_UNWIRED_NULL_GUARDIAN` |
| `DENY_CHAT_ONLY_TOOL_FORBIDDEN` |
| `DENY_MAC_MISMATCH` |
| `DENY_TIMEOUT` |
| `DENY_CONSUME_BEFORE_STAMP` |
| `DENY_CONJUNCTION_LETHAL` |
| `DENY_CRED_SPENT_OR_UNKNOWN` |
| `DENY_MCP_PIN_FROZEN` |
| `DENY_MCP_PIN_MISS` |
| `DENY_UNIMPLEMENTED_CELL` |
| `DENY_SHADOW_REWRITE_BANNED` |
| `DENY_ROLE_SCOPE_MISS` |
| `DENY_FREEZE` |
| `DENY_POLICY` |

Echo `RELATED_ORIN_HOST_REASON_CODES` **must equal** this set exactly.
Legacy js/orind dual-track leftovers (`local_policy_denied`, `freeze_active`,
`effect_class_not_granted`, `intent_expired`, `no_state_witness`,
`unregistered_or_invalid_manifest`, `budget_exhausted`, …) are **banned from
RELATED only** — they must never re-enter the Orin `DENY_*` catalog set.
`BANNED_LEGACY_REASON_CODES` does **not** ban Echo short-code column values
(e.g. `consume_before_stamp` remains a valid SoT §2 `echo_reason_code`).

## §2 Orin → Echo short `reason_code` (Echo-owned)

| `orin_reason_code` | Echo short `reason_code` | `next_action` |
| --- | --- | --- |
| `DENY_UNWIRED_NULL_GUARDIAN` | `unwired_deny` | `enable_wired_or_chat_only` |
| `DENY_CHAT_ONLY_TOOL_FORBIDDEN` | `chat_only_tool_rejected` | `disable_chat_only_and_wire` |
| `DENY_MAC_MISMATCH` | `mac_mismatch` | `inspect_grants_args_lease` |
| `DENY_TIMEOUT` | `stamp_timeout` | `retry_not_same_code_in_turn` |
| `DENY_CONSUME_BEFORE_STAMP` | `consume_before_stamp` | `report_defect` |
| `DENY_CONJUNCTION_LETHAL` | `stamp_denied` | `inspect_orin_deny_fields` |
| `DENY_CRED_SPENT_OR_UNKNOWN` | `stamp_denied` | `inspect_orin_deny_fields` |
| `DENY_MCP_PIN_FROZEN` | `stamp_denied` | `inspect_orin_deny_fields` |
| `DENY_MCP_PIN_MISS` | `stamp_denied` | `inspect_orin_deny_fields` |
| `DENY_UNIMPLEMENTED_CELL` | `stamp_denied` | `inspect_orin_deny_fields` |
| `DENY_SHADOW_REWRITE_BANNED` | `stamp_denied` | `inspect_orin_deny_fields` |
| `DENY_ROLE_SCOPE_MISS` | `stamp_denied` | `inspect_orin_deny_fields` |
| `DENY_FREEZE` | `stamp_denied` | `inspect_orin_deny_fields` |
| `DENY_POLICY` | `stamp_denied` | `inspect_orin_deny_fields` |
| *(missing / empty `orin_reason_code` on stamp path)* | `stamp_denied` | `inspect_orin_deny_fields` |

Rules:

1. Preserve `orin_reason_code` as received (passthrough).
2. Emit Echo short `reason_code` from this table only.
3. Do not invent a second Orin `DENY_*` set in Echo.

## §3 Echo-pin `ProtocolDenyCode` (orthogonal)

DeepSeek V4 / Echo pin denials (`deepseek_v4.*`) are Echo-owned and stay
`host_orin_reason_code=None`. They are not Orin `DENY_*` values and must not
rewrite Orin codes. See `docs/echo/DEEPSEEK_V4_TOOL_EDIT_PROTOCOL.md`.
