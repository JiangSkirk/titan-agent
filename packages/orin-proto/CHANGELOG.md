# Changelog

## 2.0.0

- First extracted workspace package of orin/v2 frames.
- No runtime, no secrets, no I/O.
- Documented openable `pack` / `unpack` / `KNOWN_KINDS` surface for
  GateKernel sidecar hosts (GuardianSPI stays in echo-core).
- Standalone package `LICENSE` (MIT) for independent publish; see
  `docs/orin-oss-boundary.md`.
- Not published to PyPI. Install from the titan-agent monorepo.
