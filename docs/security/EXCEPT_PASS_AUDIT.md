# `except Exception: pass` audit (Track C0)

Inventory generated against the js-agent tree. This is an audit, not a claim
that every site has been rewritten. Security-bearing sites that swallowed
errors without a log were treated as defects; remaining sites are classified.

## Policy

- Production security paths must not use bare `except: pass`.
- `except Exception:` must log, re-raise, or map to an explicit fail-closed
  verdict. Best-effort telemetry (metrics, optional UI) may warn-and-continue.
- Extracted `echo-core` / `orin-guard` kernels must not add new silent passes.

## Classification

| Class | Meaning | Action |
| --- | --- | --- |
| S | Security-bearing (auth, lease, sandbox, keybox, MAC) | Must log or fail closed |
| T | Telemetry / UX best-effort | Warning log acceptable |
| I | Idempotent cleanup (close fd, ignore missing file) | Keep, document |

Round C0 closed the production KeyBox silent `production→dev` fallback
(now fail-closed) and the OS sandbox isolation wrap fail-open return.

Remaining `except Exception:` sites in Host adapters (`js/web`, `js/models`,
`js/config`) stay in class T and must not be copied into echo-core/orin-guard.
