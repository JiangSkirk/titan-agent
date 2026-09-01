# Echo 3.0 / Orin 2.0 — monorepo source RC

This is a **source release-candidate** inside `titan-agent`. It is not a
world-class stable public release, not a PyPI publish, and not a split of
independent GitHub mirrors.

## Versions

| Package | Version | Path |
| --- | --- | --- |
| echo-core | 3.0.0 | `packages/echo-core` |
| orin-proto | 2.0.0 | `packages/orin-proto` |
| orin-guard | 2.0.0 | `packages/orin-guard` |

`js-agent` pins the same versions as workspace members. `GuardianSPI` lives
in `echo_core.spi.guardian`, not in `orin-proto`.

## Install

From the repository root:

```bash
uv sync
# or, path installs
pip install ./packages/echo-core ./packages/orin-proto ./packages/orin-guard
```

`pip install echo-core` from PyPI is **not** available.

## Still red (do not claim)

- FTO / trademark — [docs/legal/FTO_TRADEMARK.md](../legal/FTO_TRADEMARK.md)
- PyPI publish of the three packages
- Independent GitHub mirrors (`echo-core` / `orin-guard` as their own remotes)
- SLSA provenance, Sigstore/cosign, SPDX SBOM on a GitHub Release
- AgentDojo 629-case CI (block-rate ≥77%, utility drop ≤10%)
- `orin.enforce=true` as the product default
- Stage C cells / process split (`not_implemented`)

## Tags

Do not push a hyphen-free `v*` tag (that runs `stable-release-gate`).
Pre-release tags must contain a hyphen, for example `v0.1.5-rc`.

## Host vs kernel

- Kernel: `packages/echo-core`, `packages/orin-guard`, `packages/orin-proto`
- Host shims: `js.echo`, `js.orin`
- Load-bearing boundary against an adversarial model remains **OS isolation**
  ([SECURITY.md](../../SECURITY.md)). Echo/Orin are authorization and depth.
