"""Measure onedir Host-ready cold starts. Not a release_gates readiness boolean.

Launches the bundled ``js-agent-host`` launcher the same way Tauri does
(``--source-digest`` + one stdin bootstrap token) and times the
``JSAgentHostReadyV1`` sentinel. The public-beta contract target is a
clean-machine p95 of 8-12 seconds with 0 ``ready_timeout`` results in 10
launches. Faster than 8s is recorded as a hit on the upper bound only.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import secrets
import signal
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

READY_SCHEMA = "JSAgentHostReadyV1"
READY_DEADLINE_SECONDS = 90.0
DEFAULT_RUNS = 10
SLO_P95_LOW_SECONDS = 8.0
SLO_P95_HIGH_SECONDS = 12.0


def _percentile(values: list[float], fraction: float) -> float:
    if not values:
        raise ValueError("no samples")
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(fraction * len(ordered)) - 1))
    return float(ordered[index])


def _launcher_path(app_path: Path) -> Path:
    launcher = app_path / "Contents" / "MacOS" / "js-agent-host"
    if not launcher.is_file():
        raise FileNotFoundError(f"bundled host launcher is missing: {launcher}")
    return launcher


def _terminate_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            return
        process.wait(timeout=5)


def _one_cold_start(
    *,
    launcher: Path,
    source_digest: str,
    home: Path,
) -> dict[str, Any]:
    token = secrets.token_hex(32)
    env = {
        "HOME": str(home),
        "PATH": "/usr/bin:/bin",
        "TMPDIR": str(home / "tmp"),
    }
    (home / "tmp").mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    process = subprocess.Popen(
        [str(launcher), "--source-digest", source_digest],
        cwd=str(home),
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    assert process.stdin is not None
    process.stdin.write((token + "\n").encode("ascii"))
    process.stdin.close()
    assert process.stdout is not None
    try:
        line = process.stdout.readline()
        elapsed = time.monotonic() - started
        if elapsed > READY_DEADLINE_SECONDS:
            return {
                "ok": False,
                "error": "ready_timeout",
                "elapsed_seconds": elapsed,
                "returncode": process.poll(),
            }
        if process.poll() is not None and not line:
            stderr = b""
            if process.stderr is not None:
                stderr = process.stderr.read()
            return {
                "ok": False,
                "error": "sidecar_exit",
                "elapsed_seconds": elapsed,
                "returncode": process.returncode,
                "stderr_code": stderr.decode("utf-8", errors="replace").strip()[:200],
            }
        ready = json.loads(line.decode("utf-8"))
        if ready.get("schema") != READY_SCHEMA:
            return {
                "ok": False,
                "error": "invalid_sentinel",
                "elapsed_seconds": elapsed,
            }
        return {
            "ok": True,
            "error": None,
            "elapsed_seconds": elapsed,
            "port": ready.get("port"),
        }
    finally:
        _terminate_group(process)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Measure desktop Host-ready cold starts (not a readiness gate)"
    )
    parser.add_argument("--app-path", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--runs", type=int, default=DEFAULT_RUNS)
    parser.add_argument("--source-digest", default="")
    args = parser.parse_args(argv)

    if args.runs < 1:
        print("[FAIL] desktop_cold_start: --runs must be >= 1", file=sys.stderr)
        return 1

    app_path = args.app_path.expanduser().resolve()
    try:
        launcher = _launcher_path(app_path)
    except FileNotFoundError as exc:
        print(f"[FAIL] desktop_cold_start: {exc}", file=sys.stderr)
        return 1

    source_digest = args.source_digest.strip()
    if not source_digest:
        from js.echo.ledger.release_gates import release_source_digest

        source_digest = release_source_digest(Path(".").resolve())

    runs: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="js-agent-cold-start-") as raw_home:
        home_root = Path(raw_home)
        for index in range(args.runs):
            run_home = home_root / f"run-{index:02d}"
            run_home.mkdir()
            result = _one_cold_start(
                launcher=launcher,
                source_digest=source_digest,
                home=run_home,
            )
            result["index"] = index
            runs.append(result)
            status = "ok" if result["ok"] else result["error"]
            print(
                f"[cold-start {index + 1}/{args.runs}] {status} "
                f"{result['elapsed_seconds']:.3f}s"
            )

    successes = [item["elapsed_seconds"] for item in runs if item["ok"]]
    timeout_count = sum(1 for item in runs if item.get("error") == "ready_timeout")
    p95 = _percentile(successes, 0.95) if successes else None
    mean = statistics.fmean(successes) if successes else None
    slo_upper_ok = timeout_count == 0 and p95 is not None and p95 <= SLO_P95_HIGH_SECONDS
    slo_band_hit = (
        timeout_count == 0
        and p95 is not None
        and SLO_P95_LOW_SECONDS <= p95 <= SLO_P95_HIGH_SECONDS
    )
    payload = {
        "schema": "JSAgentDesktopColdStartV1",
        "source_digest": source_digest,
        "app_path": str(app_path),
        "runs": args.runs,
        "ready_deadline_seconds": READY_DEADLINE_SECONDS,
        "ready_timeout_count": timeout_count,
        "success_count": len(successes),
        "p95_seconds": p95,
        "mean_seconds": mean,
        "slo_p95_low_seconds": SLO_P95_LOW_SECONDS,
        "slo_p95_high_seconds": SLO_P95_HIGH_SECONDS,
        "slo_upper_ok": slo_upper_ok,
        "slo_band_hit": slo_band_hit,
        "samples": runs,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"[cold-start] wrote {args.output}")
    if timeout_count:
        print(
            f"[FAIL] desktop_cold_start: {timeout_count} ready_timeout",
            file=sys.stderr,
        )
        return 1
    if not successes:
        print("[FAIL] desktop_cold_start: no successful ready sentinels", file=sys.stderr)
        return 1
    if not slo_upper_ok:
        print(
            f"[WARN] desktop_cold_start: p95 {p95:.3f}s exceeds {SLO_P95_HIGH_SECONDS}s",
            file=sys.stderr,
        )
        return 2
    print(f"[OK] desktop_cold_start p95={p95:.3f}s timeouts=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
