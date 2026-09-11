# orin-proto 2.0

orin/v2 wire frames and shared kinds. **No I/O, no secrets, no runtime.**

This package has **zero** `js.*` / `echo_core` / `orin_guard` imports. It
is the openable wire vocabulary for hosts that speak orin/v2 to a
GateKernel sidecar; it does not stamp, ledger, or execute.

PyPI is **not** published. Install from this monorepo.

## Install

From the repository root:

```bash
uv sync
# or
pip install ./packages/orin-proto
```

## Public API

```python
from orin_proto import (
    PROTOCOL_VERSION,  # 2
    MAX_FRAME_BYTES,   # 64 KiB
    KNOWN_KINDS,
    FrameError,
    pack,
    unpack,
)
```

Framing: 4-byte big-endian length + JSON (deliberately not a WebSocket
gateway). Unknown `type` values and trailing bytes fail closed.

| Kind family | Examples |
| --- | --- |
| v1 | `hello`, `issue`, `consume`, `revoke`, `error` (+ acks) |
| v2 | `exec.plan`, `exec.check`, `ifc.evaluate`, `cred.issue`, `cred.exchange`, `mcp.pin`, `conjunction.check` |

`GuardianSPI` lives in `echo-core`, not here.

## License

MIT. See [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
