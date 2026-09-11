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
| Default tool surface | `file_read`, `file_write`, `file_list`, `file_search`, `file_edit`, `file_view`, `code_search`, `web_search` |
| Expand-on-demand | `shell`, `python` (opt-in only; never ambient default) |
| Tool error return | `{success: false, error: str, output?: str, metadata?: object}` |
| Execution | Still D1: propose → issue(PENDING) → stamp → durable consume → exec |

## Competing protocols (must not be V4 default)

These may exist as transports for *other* providers, but must not be selected as
the DeepSeek V4 default:

- `anthropic_tool_use`
- `apply_patch`
- `xml_tool_call`
- `str_replace_editor`

Contract tests fail closed if a competing protocol is wired as the V4 default.
Deny reason codes (`ProtocolDenyCode`) never create allow-on-soft-fail.

## Host wiring

Echo Host adaptive advertising (`js/echo/turn_loop/schema.py`) imports the core
and exec name sets from this pin so Minimal-vs-Echo harnesses share one surface.

Advertisement is not authority: expanding the advertised schema does not bypass
`EffectAuthority` / `EffectInterpreter`.

## Related

- Unified turn contract: [ECHO_UNIFIED_EXECUTION_CONTRACT.md](./ECHO_UNIFIED_EXECUTION_CONTRACT.md)
- Same-model scaffold: `benchmarks/bench_echo_vs_minimal_same_model.py`
- D1 contracts: `tests/contract/test_echo_effect_authority.py`,
  `tests/contract/test_deepseek_v4_protocol.py`
