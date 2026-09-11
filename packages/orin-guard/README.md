# orin-guard 2.0

Standalone **GateKernel** security authority for Echo hosts.

Orin is an Echo **sidecar**, not a second runtime:

| Owns | Does **not** own |
| --- | --- |
| Stamp / MAC / conjunction | Echo turn loop / Interpreter.exec |
| CredBroker (opaque, single-use) | Host ledger append / durable consume |
| MCP definition pin | Orchestration / Fleet / Bots |
| Lease-bound tool/connector tickets | Desktop / JS Agent private paths |

Authority chain (Host wires ports; this package only stamps):

```text
propose → issue(PENDING) → GuardianSPI.stamp(GateKernel)
  → Host LedgerAppendPort durable consume → Interpreter.exec
```

Depends on workspace packages `echo-core` (lease/taint vocabulary) and
`orin-proto`. Does **not** import `js.*`.

The lethal trifecta `private.read ∩ web.read ∩ egress.send` is
structurally unsatisfiable. There is **no** YOLO / timeout /
`ORIN_ALLOW_AMBIENT` hatch that can flip deny → allow. Tickets are
single-use and expire; presented `expires_at` is ignored in favor of
the stored stamp.

PyPI is **not** published. Install from this monorepo.

## Install

From the repository root:

```bash
uv sync
# or
pip install ./packages/echo-core ./packages/orin-proto ./packages/orin-guard
```

Data directory: `~/.orin-guard/` (never writes into JS Agent state dirs).

## Public API (minimal)

```python
from orin_guard import (
    GateKernel,
    PolicyPlane,
    ConjunctionDenied,
    check_conjunction,
    require_conjunction,
    CredBroker,
    CredBrokerDenied,
    MCPGate,
    MCPGateDenied,
    EffectTicket,
    TicketDenied,
    KernelUnavailable,
    grants_digest,
    CHAT_ONLY_TICKET_PREFIX,
)
```

| Surface | Contract |
| --- | --- |
| `GateKernel.issue` | MAC binds `grants_digest` + `args_hash` + `lease_id` |
| tool / connector | empty `lease_id` → deny |
| `chat_only:{lease_id}` | ticket id pinned exactly to that string |
| `GateKernel.consume` | single-use; fail-closed on MAC / expiry / order |
| `CredBroker.exchange` | pop (single-use); replay → deny |
| `MCPGate` | definition pin by hash; no `--force` bypass |
| conjunction | lethal triad always deny |

Host-replaceable ports (`Signer`, `NetGuard`) live in `orin_guard.ports`.
Daemon / Stage C cells remain Host-side (`js.orind`); this package ships
placeholders only.

## Quickstart

```bash
python packages/orin-guard/examples/quickstart.py
```

```python
from orin_guard import GateKernel, PolicyPlane

kernel = GateKernel(b"k" * 32)  # enforce=True by default
plane = PolicyPlane("owner", "session", "run", "tool", frozenset({"private.read"}), 1)
ticket = kernel.issue(plane, lease_id="lease-1", args_hash="sha256:…")
receipt = kernel.consume(ticket, owner="owner", run="run")
```

## Not claimed (debt)

- Stage B product default flip (`orin.enabled` / `orin.enforce=true`):
  Host config debt date **2026-10-01** — not flipped in this package.
- Stage C cells / process split / product `orin.enforce` conjunction:
  `not_implemented` (see repo `docs/security/orin/ORIN_STAGE_C_CLOSEOUT.md`).
- PyPI publish / independent GitHub mirrors.

## License

MIT. See [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
