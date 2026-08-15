# Public Beta Contract

This is a **controlled-trial contract**, not a release-gates switch.
It does not define `public_beta_ready`, and it does not change
`internal_ready`, `product_internal_ready`, or `stable_ready`.

`stable_ready` remains: internal evidence is green **and** the four
external approvals are present and valid. This document does not
satisfy Freedom-to-Operate, clean-room, external audit, or red-team
sign-off.

## Scope

The public beta is responsible only for:

- macOS arm64
- literal loopback bind (`127.0.0.1` or `::1`)
- personal trial use

It is **not** responsible for GitHub stable, notarized distribution,
legal FTO completion, or any platform other than macOS arm64.

## Package story

There is one version number. The shipped package is `0.1.5`.
The integration branch name `0.2.0-beta.1` is an engineering track,
not the package version.

## What a stranger can expect

1. After install, the window opens and the local Host becomes ready
   inside the startup SLO. The onedir-packaged target is a clean-machine
   cold start p95 of 8–12 seconds, with 0 `ready_timeout` results in 10
   launches. That SLO is a beta measurement, not a `release_gates.py`
   boolean.
2. One local conversation can complete. Non-model network egress stays
   fail-closed by default.
3. After quit, there are no orphan Host processes and no leftover
   listeners.
4. The build is **not notarized**. Gatekeeper may block or delay it.
   The first Host start may wait. Closing the window with the red
   traffic-light button hides the window; it is **not** Quit / `Cmd+Q`.

## What this contract does not say

- GitHub stable
- Apple notarization or Developer ID production signing
- Legal FTO complete
- Clean-room, external security audit, or red-team approval
- Multi-platform support

Do not write placeholder `LEGAL_FTO_REVIEW` (or the other three
external approvals) to make `stable_ready` look green.
