# ADR 0010: Echo two-tier phylogeny

## Status

Accepted.

## Context

`js/evolution` is proposal-only. Hermes-style self-writing skills and
OpenClaw automatic self-learning are injection amplifiers unless widening
is gated. ICLR 2026 Misevolution shows unattended memory/tool evolution
erodes alignment.

## Decision

Evolution polarity is `tighten` / `note` / `widen` (`echo_core.phylogeny`):

- `tighten` and `note` (USER_TURN-only taint) may auto-commit. They never
  grant new power.
- `widen` (skills, tools, behaviour-changing memory, prompt, policy, code)
  never auto-commits. It requires owner bind + eval gate + guardian stamp.
- Eval gate and rollback have **no off switch**.
- Constitution prefixes (`echo_core/capability`, `echo_core/ledger`,
  `orin_guard/`, `prompts/stable/`) are not evolvable.
- `pulse()` remains observe-only (ADR 0005). Phylogeny runs after a turn
  reaches terminal state, never inside Exec.
- Online RL is out of scope; trajectory export may exist but is off by default.

## Consequences

- Matches the product two-tier autonomy choice without relaxing never-unattended.
- Quality unit `evolution` stays proposal-gated for widen.
- Orin policy lattice remains the veto on policy-shaped payloads.
