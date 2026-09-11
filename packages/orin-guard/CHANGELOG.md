# Changelog

## 2.0.0

- First extracted workspace package of the Orin gate (GateKernel, IFC,
  CredBroker, MCPGate, conjunction).
- Tickets are single-use; `consume` rejects stored `expires_at`.
- GateKernel MAC binds `grants_digest`, `args_hash`, and `lease_id`.
- Empty `lease_id` denied for tool/connector; `chat_only:{lease_id}` pin.
- CredBroker `exchange` pops the secret after one use.
- Lethal trifecta is structurally unsatisfiable; no
  `ORIN_ALLOW_AMBIENT` / YOLO / timeout→allow hatch.
- Openable README/API surface for third-party hosts (no JS Agent / desktop
  private paths). Stage B product-default flip remains Host debt
  (2026-10-01); Stage C cells stay `not_implemented`.
- Not published to PyPI. Install from the titan-agent monorepo.
