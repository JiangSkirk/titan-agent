# echo-core 3.0

Standalone fail-closed agent runtime kernel: leases, ledger, pulse, phylogeny.

This package has **zero** `js.*` imports. Hosts (including js-agent) bind
`GuardianSPI`, model, and tool ports. Evolution polarity is `tighten` /
`note` / `widen`; **widen is never unattended**.

PyPI is **not** published. Install from this monorepo.

## Install

From the repository root:

```bash
uv sync
# or
pip install ./packages/echo-core
```

Data directory: `~/.echo-core/`.

## Quickstart

```bash
python packages/echo-core/examples/quickstart.py
```

`NullGuardian` refuses ambient execution. A Host must wire a real
`GuardianSPI` before tools or widen proposals can stamp.

## License

MIT. See [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
