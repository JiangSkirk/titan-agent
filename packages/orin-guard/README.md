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

Stage C cells / process-split closeout are **not** claimed by this package.
Hosts that want GateKernel enforcement wire it themselves. Product Host
defaults may set `orin.enabled` / `orin.enforce` true for EffectAuthority D1
without claiming Stage C.

## License

MIT. See [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
