# ADR 0009: echo-core / orin-guard extraction

## Status

Accepted.

## Context

JS Agent's Echo runtime and Orin gatekeeper are mature but bound inside the
`js` package. Downstream researchers cannot consume them without the Host.
Echo currently imports `js.orin.taint` / `sinks`; Orin imports
`js.echo.capability` / `os_sandbox` — a bidirectional cycle that blocks
packaging. Production ledger release gates also import repo-root `desktop/`
and `scripts/`.

## Decision

1. Publish three workspace packages: `echo-core` (Echo 3.0), `orin-guard`
   (Orin 2.0), `orin-proto` (orin/v2 frames + no secrets).
2. Neutral taint/sink/lease vocabulary lives in `echo-core`. Policy stays in
   `orin-guard`. Echo proposes; a Host-wired `GuardianSPI` stamps. echo-core
   never imports orin-guard.
3. `js.echo` and `js.orin` become Host adapters / shims. Release-governance
   modules (`ledger/release_gates.py`, `evidence_export.py`, `final_evidence.py`)
   stay in js-agent and keep any `desktop/` / `scripts/` imports.
4. CI `scripts/import_firewall.py` forbids `import js` inside the three
   packages. Coverage floors migrate with the extracted trees; js.echo shims
   keep the existing 85% ratchet until adapters thin out.

## Consequences

- js-agent becomes a downstream consumer.
- Independent `pip install echo-core` / `orin-guard` is a later PyPI step.
  Today: path-install from this monorepo (`uv sync` or `pip install ./packages/...`).
- Stage C still must not be claimed until the conjunction in
  `js.orin.stage_c` is observed.
