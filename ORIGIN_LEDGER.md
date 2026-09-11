# Origin Ledger

This file records the engineering-origin boundary for the Echo 2.0 Runtime work.

## Scope

- Package: `js/echo/ledger`
- Tests: `tests/echo/ledger`
- Smoke: Echo ledger smoke (`scripts/echo_ledger_smoke.py`)
- Architecture input: local design document `js agent架构方案 Pro.md`

## Clean-Room Boundary

Echo 2.0 is implemented with Echo-native names and state models. Public
research and open-source agent projects were used only for abstract risk and
design context. Echo 2.0 does not copy source code, prompt templates, class
hierarchies, API signatures, example flows, golden traces, or benchmark data
from those projects.

## Claimed Original Engineering Surface

- `PulseLoop`: bounded small-step runtime coordinator.
- `FrameLedger`: deterministic frame chain with record hash and MAC verification.
- `ScopeGate`: exact provider-bound authorization bound to owner, session, run, model, final messages hash, and tools schema hash.
- `BudgetClock`: token, tool, journal, and elapsed-time admission.
- `EffectOutbox`: permit-gated claim/receipt/merge recovery semantics.
- `ContextVault`: owner/session-scoped context selection for lower token cost.

## Non-Claims

The project does not claim legal originality, freedom to operate, patent clearance, or trademark clearance from this file. Those require external review before any stable public release.

The release gate also runs an engineering IP boundary scan. That scan blocks
obvious drift toward project-specific third-party API names and blocks public
claims that local tests cannot prove, such as legal originality, freedom to
operate, or absence of infringement.

## External Review Required Before Stable

- Legal FTO review.
- Trademark review for public naming.
- Clean-room reviewer sign-off.
- Dependency license review against the final lockfile and SBOM.

## Echo 3.0 / Orin 2.0 extraction

- Packages: `packages/echo-core`, `packages/orin-proto`, `packages/orin-guard`
- Tests: `tests/echo_core`, `tests/orin_proto`, `tests/orin_guard`
- Clean-room: concepts from OpenClaw / Hermes / CaMeL / FIDES / GEPA were
  used only as design constraints. No source, class names, or APIs were copied.

