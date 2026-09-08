# Changelog

## 2.0.0

- First extracted workspace package of the Orin gate (GateKernel, IFC,
  CredBroker, MCPGate, conjunction).
- Tickets are single-use; `consume` rejects stored `expires_at`.
- GateKernel MAC binds `grants_digest`, `args_hash`, and `lease_id`.
- CredBroker `exchange` pops the secret after one use.
- Lethal trifecta is structurally unsatisfiable.
- Not published to PyPI. Install from the titan-agent monorepo.
