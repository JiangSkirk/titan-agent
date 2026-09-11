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

## `ProtocolDenyCode` ↔ Host/Orin `reason_code` (docs only)

| Echo `ProtocolDenyCode` | Meaning | Relation to Orin/Host |
| --- | --- | --- |
| `deepseek_v4.unknown_model` | Model outside V4 lock | Echo pin only; not an Orin GateKernel ticket |
| `deepseek_v4.competing_default_protocol` | Non-`file_edit` default wire format | Echo pin only |
| `deepseek_v4.thick_default_surface` | Default tool set >5 or includes meta expand names | Echo pin / Host advertising |
| `deepseek_v4.ambient_exec_default` | shell/python ambient on harness_edit | Echo pin; Host `echo_exec_tools` must stay opt-in |
| `deepseek_v4.invalid_*` | Schema/args/error envelope shape | Echo pin validation |

Orin GateKernel `reason_code` strings (MAC / empty-lease / chat_only) remain
Orin-owned. This table is a **mapping note only** — it does not invent a second
authority plane. A missing Orin `reason_code` must never soft-allow an Echo pin
denial.

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
