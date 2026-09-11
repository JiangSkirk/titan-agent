# echo-core 3.0

Standalone fail-closed agent runtime kernel: leases, ledger, pulse, phylogeny.

This package has **zero** `js.*` imports. Hosts (including js-agent) bind
`GuardianSPI`, model, and tool ports. Evolution polarity is `tighten` /
`note` / `widen`; **widen is never unattended**.

**Orin open surface peer:** `orin-guard` depends on this package for lease /
taint / sink vocabulary. Third parties installing GateKernel must path-install
`echo-core` + `orin-proto` + `orin-guard` together — see
[docs/orin-oss-boundary.md](../../docs/orin-oss-boundary.md). Do not stub
taint/sinks inside orin-guard.

PyPI is **not** published. Install from this monorepo.

## Install

From the repository root:

```bash
uv sync
# or
pip install ./packages/echo-core
# Orin GateKernel consumers:
pip install ./packages/echo-core ./packages/orin-proto ./packages/orin-guard
```

Data directory: `~/.echo-core/`.

## Quickstart

```bash
python packages/echo-core/examples/quickstart.py
```

`NullGuardian` refuses ambient execution. A Host must wire a real
`GuardianSPI` before tools or widen proposals can stamp.

## License

This package ships its own standalone MIT [LICENSE](LICENSE) for
independent publish (does not rely on the monorepo root license file).
See also [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
