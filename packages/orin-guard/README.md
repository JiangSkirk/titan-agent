# orin-guard 2.0

Standalone process-out agent security authority: GateKernel, IFC,
CredBroker, MCPGate.

Depends on workspace packages `echo-core` (lease/taint vocabulary) and
`orin-proto`. Does **not** import `js.*`.

The lethal trifecta `private.read ∩ web.read ∩ egress.send` is
structurally unsatisfiable. Tickets are single-use and expire.

PyPI is **not** published. Install from this monorepo.

## Install

From the repository root:

```bash
uv sync
# or
pip install ./packages/echo-core ./packages/orin-proto ./packages/orin-guard
```

Data directory: `~/.orin-guard/`.

## Quickstart

```bash
python packages/orin-guard/examples/quickstart.py
```

Stage C cells / `orin.enforce=true` as a product default are **not**
claimed by this package. Hosts that want enforcement wire GateKernel
themselves.

## License

MIT. See [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
