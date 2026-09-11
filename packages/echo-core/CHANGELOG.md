# Changelog

## 3.0.0

- First extracted workspace package of the Echo kernel (leases, ledger,
  pulse, phylogeny, OS sandbox).
- `GuardianSPI` is host-wired; `NullGuardian` is fail-closed.
- Evolution polarity: `tighten` / `note` auto-commit only with
  USER_TURN-only taint; `widen` never auto-commits.
- Not published to PyPI. Install from the titan-agent monorepo.
