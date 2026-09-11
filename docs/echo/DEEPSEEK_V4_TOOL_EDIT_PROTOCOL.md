# DeepSeek V4 tool/edit protocol pin

**Location (code):** `packages/echo-core/echo_core/deepseek_v4_protocol.py`  
**Architecture lock:** Echo/Orin scheme v0.4.1  
**Same-model family:** DeepSeek V4 (`deepseek-v4-flash`, `deepseek-v4-pro`)

This pin is Echo-owned. Orin GateKernel / `orin-guard` / `orin-proto` are out of
scope. Outer shell / Tauri / desktop are out of scope.

## What Echo feeds V4

| Concern | Pin |
| --- | --- |
| Wire format | OpenAI-compatible function calling (`type: function`) |
| Default edit protocol | `openai_function_file_edit` via tool `file_edit` |
| Required edit fields | `path`, `search`, `replace` (exact search→replace) |
| Default surface profile | **`harness_edit`** (lite, **len ≤5**) |
| Default tool surface | `file_read`, `file_search`, `file_edit` |
| Alternate lite profile | `file_read`, `file_search`, `shell` (documented only; **not** V4 default) |
| Expand-on-demand (meta) | `file_write`, `file_list`, `file_view`, `code_search`, `web_search` |
| Expand-on-demand (exec) | `shell`, `python` (opt-in only; never ambient on `harness_edit`) |
| Tool error return | `{success: false, error: str, output?: str, metadata?: object}` |
| Execution | Still D1: propose → issue(PENDING) → stamp → durable consume → exec |

Frozen v0.4.1 rule: **default boot surface length ≤5** and lite ⊆
`{file_read, file_search, code_search, shell, file_edit}`. Thick defaults that
pull `file_write` / `web_search` into the always-on set fail closed
(`ProtocolDenyCode.THICK_DEFAULT_SURFACE`).

## Model id expansion rule

Locked ids are **exact members** of `DEEPSEEK_V4_MODEL_IDS` only
(`deepseek-v4-flash`, `deepseek-v4-pro`), plus an optional single provider
prefix (`vendor/deepseek-v4-flash`). There is **no** `deepseek-v4-*` wildcard —
new SKUs must be added to the frozenset explicitly or `UNKNOWN_MODEL` denies.

## Competing protocols (must not be V4 default)

These may exist as transports for *other* providers, but must not be selected as
the DeepSeek V4 default:

- `anthropic_tool_use`
- `apply_patch`
- `xml_tool_call`
- `str_replace_editor`

Contract tests fail closed if a competing protocol is wired as the V4 default.
Deny reason codes (`ProtocolDenyCode`) never create allow-on-soft-fail.

## `ProtocolDenyCode` ↔ Host/Orin `reason_code`

**Orin SoT (authoritative):** `/workspace/orin-abcd/ORIN_ECHO_REASON_CODE_MAP_v0.1.md`  
**Echo citation copy:** [ORIN_ECHO_REASON_CODE_MAP_v0.1.md](./ORIN_ECHO_REASON_CODE_MAP_v0.1.md)  
**Echo code mirror:** `packages/echo-core/echo_core/deny_code_mapping.py`

Dual-track (v0.1):

1. Orin owns `DENY_*` as `orin_reason_code` — **passthrough; Echo must not rewrite**.
2. Echo owns the short `reason_code` column (SoT §2).
3. Echo-pin `ProtocolDenyCode` (`deepseek_v4.*`) stay Echo-only with
   `host_orin_reason_code=None` — orthogonal to Orin `DENY_*`.
4. Fail-closed: **unknown mapping = deny, never allow**. Missing
   `orin_reason_code` on the stamp path → Echo short `stamp_denied`.

### Echo-pin `ProtocolDenyCode` rows

| Echo `ProtocolDenyCode` | Host/Orin `reason_code` | Plane |
| --- | --- | --- |
| `deepseek_v4.unknown_model` | *(none — Echo-pin-only)* | `echo_pin` |
| `deepseek_v4.competing_default_protocol` | *(none — Echo-pin-only)* | `echo_pin` |
| `deepseek_v4.invalid_tool_schema` | *(none — Echo-pin-only)* | `echo_pin` |
| `deepseek_v4.invalid_edit_args` | *(none — Echo-pin-only)* | `echo_pin` |
| `deepseek_v4.invalid_error_shape` | *(none — Echo-pin-only)* | `echo_pin` |
| `deepseek_v4.ambient_exec_default` | *(none — Echo-pin-only)* | `echo_pin` |
| `deepseek_v4.thick_default_surface` | *(none — Echo-pin-only)* | `echo_pin` |

### Orin `DENY_*` catalog → Echo short `reason_code` (SoT §2)

`RELATED_ORIN_HOST_REASON_CODES` **must equal** this catalog (no legacy
js/orind strings). `BANNED_LEGACY_REASON_CODES` gates RELATED membership only —
Echo short codes such as `consume_before_stamp` remain valid SoT §2 values.

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
| *(missing on stamp path)* | `stamp_denied` | `inspect_orin_deny_fields` |

Lookup API: `passthrough_orin_reason_code`, `echo_short_reason_for_orin`,
`lookup_protocol_deny_mapping` / `assert_mapping_denies` — unknown codes raise
`DenyMappingError`.


## Host wiring

Echo Host adaptive advertising (`js/echo/turn_loop/schema.py`) imports the lite
core + expand-on-demand name sets from this pin so Minimal-vs-Echo harnesses
share one surface. Empty queries receive only the lite core.

Advertisement is not authority: expanding the advertised schema does not bypass
`EffectAuthority` / `EffectInterpreter`.

## Related

- Unified turn contract: [ECHO_UNIFIED_EXECUTION_CONTRACT.md](./ECHO_UNIFIED_EXECUTION_CONTRACT.md)
- Same-model scaffold: `benchmarks/bench_echo_vs_minimal_same_model.py`
- D1 contracts: `tests/contract/test_echo_effect_authority.py`,
  `tests/contract/test_deepseek_v4_protocol.py`
- Deny-code SSOT: `packages/echo-core/echo_core/deny_code_mapping.py`
  (cites `ORIN_ECHO_REASON_CODE_MAP_v0.1.md`)
