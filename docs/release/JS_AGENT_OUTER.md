# JS Agent outer shell — packaging cut #3

This document freezes the **outer-shell** releasable packaging surface so a
later release can tag `js-agent-outer-2026.09` on the authority line.

It is **not** a PyPI publish, not notarization / Developer ID, and **not** a
republish of kernel triad internals (`echo-core` / `orin-proto` / `orin-guard`).

## Cut map

| Cut | Surface | Tag / freeze |
| --- | --- | --- |
| Kernel open triad | `packages/echo-core`, `packages/orin-proto`, `packages/orin-guard` | See [ECHO3_ORIN2.md](ECHO3_ORIN2.md) + [orin-oss-boundary.md](../orin-oss-boundary.md) |
| **#3 Outer shell** | Host pip package + desktop/Tauri + release scripts + root `LICENSE` | Proposed: **`js-agent-outer-2026.09`** |

Outer shell **depends on** the kernel triad at install / sidecar freeze time.
It does **not** vendor or re-license Orin GateKernel sources into the Host
sdist, and it does not claim Stage B/C product defaults.

## What is in the outer shell

| Area | Paths | Artifact |
| --- | --- | --- |
| Host Python package | `js/`, `js_work/`, `resources/`, root `pyproject.toml` | `js_agent-0.1.5-py3-none-any.whl` + sdist |
| Host entry | `[project.scripts] js` / `js-work`; `js appshell`; `js/web/local_host.py` | CLI / AppShell Host |
| Desktop / Tauri | `desktop/` (`src-tauri/`, `sidecar/host.py`, `build_driver.py`) | Unsigned macOS `.app` + zip (`PRODUCT_VERSION` **0.1.0**) |
| Release governance | `scripts/release_smoke.py`, `verify_installed_artifact.py`, `run_desktop_build_gate.py`, `run_tauri_webview_gate.py`; `js/echo/ledger/release_gates.py` | Gates / evidence (not pip package data) |
| Outer license | root `LICENSE` (MIT) + `THIRD_PARTY_NOTICES.md` | Ships in Host sdist |

Intentionally **outside** the Host sdist/wheel: `desktop/`, `scripts/`,
`packages/`, `docs/`. Desktop is a separate offline macOS build, not
`pip install` package data. Optional extra `[desktop]` is only Darwin
`pyobjc` — not the Tauri app.

## Version dual-track (intentional)

| Identity | Version | Notes |
| --- | --- | --- |
| Host (`js-agent`) | **0.1.5** | `pyproject.toml`, `__version__`, Host wheel/sdist |
| Desktop product | **0.1.0** | `desktop/build_driver.PRODUCT_VERSION`, Tauri/`Cargo.toml`/`package.json` |
| Kernel peers | echo-core **3.0.0**, orin-proto **2.0.0**, orin-guard **2.0.0** | Workspace pins; outer cut does not bump them |

Do not force-align desktop → 0.1.5 inside cut #3; document both numbers on
the outer tag.

## Relation to tag `js-agent-outer-2026.09`

- Calendar-style outer tag (hyphenated). It is **not** a hyphen-free `v*`
  stable tag and does **not** by itself trigger `stable-release-gate` /
  `release-smoke.yml` `tags: ["v*"]`.
- Marks the monorepo authority line where Host + desktop packaging docs and
  dry-run recipes are frozen for a later release engineer to cut artifacts.
- Does **not** republish or re-tag kernel packages; kernel remains path-install
  / co-built wheels beside the Host wheel.

## Dry-run (Host pip artifacts)

From repo root (kernel wheels **must** sit beside the Host wheel — peers are
not on PyPI yet):

```bash
uv sync --frozen --extra dev --extra echo-tokenizer
uv run python -m build --outdir dist
uv run python -m build --wheel --outdir dist packages/echo-core
uv run python -m build --wheel --outdir dist packages/orin-proto
uv run python -m build --wheel --outdir dist packages/orin-guard
uv run python scripts/verify_installed_artifact.py --artifact-dir dist
uv run python scripts/release_smoke.py --all
```

`python -m build` alone does not produce a clean-venv-installable Host wheel
without the three workspace wheels next to it.

## Dry-run (desktop — local macOS only)

Not run in GitHub Actions today. Requires offline tool pins via env
(`JS_AGENT_PNPM_EXECUTABLE`, `JS_AGENT_CARGO_EXECUTABLE`,
`JS_AGENT_NODE_EXECUTABLE`, `JS_AGENT_CARGO_HOME`, `JS_AGENT_PNPM_STORE`,
`JS_AGENT_BUILD_NUMBER`):

```bash
.venv/bin/python scripts/run_desktop_build_gate.py --evidence-dir <evidence>
# then, against the built .app:
.venv/bin/python scripts/run_tauri_webview_gate.py ...
```

## Non-claims

- PyPI publish of `js-agent` or the kernel triad
- Apple notarization / Developer ID / official TCC (`official_tcc_packaging`)
- Independent GitHub mirrors for outer or kernel
- Stage B product-default flip / Stage C conjunction
- Rewriting Orin GateKernel or expanding `packages/orin-*`

## Authority chain (unchanged)

```text
propose → issue(PENDING) → GuardianSPI.stamp(GateKernel)
  → Host LedgerAppendPort durable consume → Interpreter.exec
```

Outer shell is the Host + desktop packaging surface that binds that chain for
operators; it is not a second turn runtime.
