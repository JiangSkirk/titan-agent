# Orin / Echo open-source package boundary

Frozen for third-party consumers of the **openable kernel surface**.
This is not a Stage B/C product claim and not a PyPI publish checklist.

## Open surface (three packages)

| Package | Role | Ships own `LICENSE` |
| --- | --- | --- |
| `echo-core` | Openable Echo kernel peer: lease / taint / sink vocabulary, `GuardianSPI`, ledger ports | `packages/echo-core/LICENSE` (MIT) |
| `orin-proto` | orin/v2 frames only — no I/O, no secrets, no runtime | `packages/orin-proto/LICENSE` (MIT) |
| `orin-guard` | GateKernel sidecar: stamp / MAC / conjunction / CredBroker / MCP pin | `packages/orin-guard/LICENSE` (MIT) |

Each package keeps a **standalone MIT** `LICENSE` (plus `THIRD_PARTY_NOTICES.md`
where present) so an independent publish does not depend on the monorepo
root license file.

## Dependency decision (honest peer, no stub)

`orin-guard` **requires** `echo-core` and `orin-proto` at install time
(`echo-core==3.0.0`, `orin-proto==2.0.0` in `packages/orin-guard/pyproject.toml`).

That is intentional. GateKernel policy imports Echo's taint/sink vocabulary
(`echo_core.taint`, `echo_core.sinks`) for grants / IFC / exec checks. A fake
in-tree stub would weaken fail-closed contracts and drift from the Echo
architect boundary (Echo proposes; Orin stamps; Host appends ledger).

Install all three together:

```bash
pip install ./packages/echo-core ./packages/orin-proto ./packages/orin-guard
# or from repo root
uv sync
```

`orin-proto` has **zero** `echo_core` / `orin_guard` imports and may be
installed alone for framing. A GateKernel host still needs the full triad.

## Not in the open surface

- `js.*` / AppShell / desktop packaging / Fleet / Bots / Gateway
- Host ledger append adapters that live under `js.echo`
- Stage C cells / product `orin.enforce` conjunction (`not_implemented`)
- Stage B product-default flip (`orin.enabled` / `orin.enforce=true`) —
  Host debt date **2026-10-01**

## Authority chain (unchanged)

```text
propose → issue(PENDING) → GuardianSPI.stamp(GateKernel)
  → Host LedgerAppendPort durable consume → Interpreter.exec
```

Orin does not write the Echo ledger and is not a second turn runtime.
