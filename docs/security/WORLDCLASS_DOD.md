# World-class release DoD (Track D)

This checklist is fail-closed. Items that require third parties stay red
until evidence exists. Code cannot mark them green unilaterally.

## Independent packages

- [x] `echo-core` / `orin-proto` / `orin-guard` exist as workspace packages
- [x] import firewall forbids `js.*` inside the three packages
- [x] `self_dev_audit.py` dual method (import surface + cloc)
- [x] Monorepo source RC notes (`docs/release/ECHO3_ORIN2.md`)
- [ ] Public GitHub mirrors `echo-core` and `orin-guard` pushed
- [ ] PyPI publish of the three packages

## Stage C honesty

- [ ] Tool handlers out of the Echo process (Cells)
- [ ] Provider tokens only via CredBroker
- [ ] AppShell / Echo process split (`appshell_echo_separated`)
- [ ] External endorsement (TCC / red team)
- [ ] `orin.enforce=true` default **only after** the conjunction is observed

Until then: `orin.enforce` stays default false; closeout remains
`not_implemented`.

## Assurance

- [x] Conjunction kernel + ExecKernel + IFC + CredBroker + MCPGate
- [x] AgentDojo adapter tests in `tests/echo/test_agentdojo_adapter.py`
- [ ] AgentDojo 629-case CI job with block-rate ≥77% and utility drop <10%
- [x] OWASP Agentic Top 10 mapping
- [ ] External red-team report archived, high findings zero
- [ ] orin-guard mutmut surviving mutants <5%

## Supply chain

- [ ] SLSA provenance for release artifacts
- [ ] Sigstore/cosign keyless signature of wheels
- [ ] SBOM (SPDX) attached to the GitHub release
- [x] License evaluation recorded (`docs/legal/LICENSE_EVAL.md`)
- [ ] FTO / trademark review (`docs/legal/FTO_TRADEMARK.md` is the placeholder)
