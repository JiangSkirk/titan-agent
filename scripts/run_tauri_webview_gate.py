"""Gate wrapper for tauri_webview_lifecycle: runs the real Tauri WKWebView harness.

Outputs a release_markers result line so the gate receipt runner can parse it.

The harness must be packaged as:
  <evidence>/harness/JS Agent UI Test Harness.app
with bundle id local.js-agent.ui-test-harness. A bare binary is not accepted.
"""

from __future__ import annotations

import hashlib
import math
import os
import plistlib
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

from js.echo.ledger.release_gates import format_release_result_line
from js.echo.ledger.strict_json import StrictJSONError, strict_load_object

_HARNESS_APP_NAME = "JS Agent UI Test Harness.app"
_HARNESS_EXEC = "Contents/MacOS/js-agent-ui-test-harness"
_HARNESS_SOURCE = Path("desktop/tests/harness/tauri_webview_harness.swift")
_HARNESS_MANIFEST_SCHEMA = "JSAgentTauriHarnessProvenanceV1"
_HARNESS_BUNDLE_IDENTIFIER = "local.js-agent.ui-test-harness"
_AX_EXIT = 10
_HARNESS_TIMEOUT_SECONDS = 600
RESULT_SCHEMA_VERSION = "js-agent-tauri-webview-result-v1"
EXPECTED_BUNDLE_IDENTIFIER = "com.titan.js-agent"
REQUIRED_SCENARIOS = frozenset(
    {
        "accessibility_probe",
        "cold_start_controlled_env",
        "process_tree_one_app_one_sidecar",
        "webview_shows_content",
        "bootstrap_fragment_cleared",
        "http_api_status",
        "bootstrap_token_single_use",
        "ui_mode_switch_personal_work_personal",
        "sidecar_crash_recovery",
        "clean_quit_no_orphans",
        "restart_simplified_flow",
    }
)
_RESULT_FIELDS = frozenset(
    {
        "schema_version",
        "ok",
        "status",
        "nonce",
        "scenarios",
        "app_sha256",
        "app_tree_sha256",
        "harness_sha256",
        "desktop_manifest_sha256",
        "bundle_identifier",
        "accessibility_authorized",
        "target_pid",
        "started_utc",
        "finished_utc",
    }
)
_SCENARIO_FIELDS = frozenset({"passed", "status", "detail", "duration_ms", "error_code"})
_PS_ROW = re.compile(r"\s*(\d+)\s+(\d+)\s+(\d+)\s+(.*)")


def _default_harness_path(evidence_dir: Path) -> Path:
    return (evidence_dir / "harness" / _HARNESS_APP_NAME).resolve()


def _harness_executable(harness_path: Path) -> Path:
    if harness_path.is_dir() and harness_path.name.endswith(".app"):
        return harness_path / _HARNESS_EXEC
    return harness_path


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def process_rows_from_ps(output: str) -> dict[int, tuple[int, int, str]]:
    """Parse `ps -axo pid=,ppid=,pgid=,command=` into {pid: (ppid, pgid, cmd)}."""
    rows: dict[int, tuple[int, int, str]] = {}
    for raw in output.splitlines():
        match = _PS_ROW.match(raw)
        if match:
            rows[int(match.group(1))] = (
                int(match.group(2)),
                int(match.group(3)),
                match.group(4),
            )
    return rows


def descendants_of(root_pid: int, rows: dict[int, tuple[int, int, str]]) -> set[int]:
    found: set[int] = set()
    changed = True
    while changed:
        changed = False
        for pid, (parent, _group, _command) in rows.items():
            if pid not in found and (parent == root_pid or parent in found):
                found.add(pid)
                changed = True
    return found


def expand_sidecar_process_groups(
    tree: set[int], rows: dict[int, tuple[int, int, str]]
) -> set[int]:
    """Include members of process groups whose leaders already sit in *tree*.

    Mirrors the Swift harness ``processTreePids`` contract: Host is launched with
    ``process_group(0)``, so onefile children may own LISTEN while the ready
    sentinel reports the leader pid. Never expands the parent's inherited pgid.
    """
    found = set(tree)
    leader_pgids = {
        pid for pid in found if (row := rows.get(pid)) is not None and row[1] == pid and pid > 0
    }
    if not leader_pgids:
        return found
    for pid, (_ppid, pgid, _cmd) in rows.items():
        if pgid in leader_pgids:
            found.add(pid)
    return found


def owned_process_tree(root_pid: int, rows: dict[int, tuple[int, int, str]]) -> set[int]:
    return expand_sidecar_process_groups(
        descendants_of(root_pid, rows) | {root_pid},
        rows,
    )


def _signal_pid(pid: int, sig: int) -> None:
    try:
        os.kill(pid, sig)
    except (ProcessLookupError, PermissionError, OSError):
        pass


def _signal_pgid(pgid: int, sig: int) -> None:
    if pgid <= 0:
        return
    try:
        os.killpg(pgid, sig)
    except (ProcessLookupError, PermissionError, OSError):
        pass


def _default_ps_rows() -> dict[int, tuple[int, int, str]]:
    try:
        output = subprocess.check_output(
            ["/bin/ps", "-axo", "pid=,ppid=,pgid=,command="],
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return {}
    return process_rows_from_ps(output)


def reap_owned_tree(
    root_pid: int,
    *,
    rows_provider: Callable[[], dict[int, tuple[int, int, str]]] | None = None,
    grace_seconds: float = 2.0,
    kill_wait_seconds: float = 5.0,
) -> set[int]:
    """TERM then KILL the owned harness tree, including sidecar process groups.

    Snapshot the ppid/pgid closure **before** killing the root so desktop+host
    remain visible as descendants. Returns the set of pids that were targeted.
    """
    provider = rows_provider or _default_ps_rows
    rows = provider()
    owned = owned_process_tree(root_pid, rows)
    leader_pgids = {
        pid for pid in owned if (row := rows.get(pid)) is not None and row[1] == pid and pid > 0
    }

    for pgid in leader_pgids:
        _signal_pgid(pgid, signal.SIGTERM)
    for pid in sorted(owned, reverse=True):
        _signal_pid(pid, signal.SIGTERM)

    deadline = time.monotonic() + grace_seconds
    while time.monotonic() < deadline:
        live_rows = provider()
        alive = {pid for pid in owned if pid in live_rows}
        if not alive:
            return owned
        time.sleep(0.1)

    live_rows = provider()
    alive = {pid for pid in owned if pid in live_rows}
    for pgid in leader_pgids:
        if any(live_rows.get(pid, (0, -1, ""))[1] == pgid for pid in alive):
            _signal_pgid(pgid, signal.SIGKILL)
    for pid in sorted(alive, reverse=True):
        _signal_pid(pid, signal.SIGKILL)

    kill_deadline = time.monotonic() + kill_wait_seconds
    while time.monotonic() < kill_deadline:
        live_rows = provider()
        if not any(pid in live_rows for pid in owned):
            break
        time.sleep(0.1)
    return owned


def _salvage_partial_result(result_path: Path, published_result: Path) -> bool:
    """Copy mid-run harness result.json before private_dir is removed.

    On outer TimeoutExpired the harness may already have flushed completed
    scenarios. Preserve that evidence at the durable published path so S1–Sn
    are not lost with the ephemeral private_dir.
    """
    try:
        result_stat = result_path.lstat()
        if not stat.S_ISREG(result_stat.st_mode) or result_stat.st_nlink != 1:
            return False
        # Validate it is parseable JSON object; do not require full pass schema.
        strict_load_object(result_path)
    except (OSError, ValueError, StrictJSONError):
        return False
    try:
        published_result.parent.mkdir(parents=True, exist_ok=True)
        # replace is atomic on same filesystem (private_dir lives under result_dir).
        os.replace(result_path, published_result)
    except OSError:
        try:
            shutil.copy2(result_path, published_result)
        except OSError:
            return False
    return True


_LISTENER_WAIT_EVIDENCE_KEYS = (
    "app_running",
    "tree_pids",
    "host_count",
    "host_pids",
    "listener_count",
    "listeners",
    "ps",
    "lsof",
    "stdout_tail",
    "stderr_tail",
)


def parse_listener_wait_evidence(detail: str) -> dict[str, str]:
    """Extract durable cold-start timeout fields from a scenario detail string.

    Harness appends ``key=value`` tokens after ``|``. ``host_count`` /
    ``host_pids`` are js-agent-host **process** inventory (PyInstaller onefile
    often yields parent+child = 2). ``listener_count`` / ``listeners`` are
    independent lsof TCP LISTEN inventory: 0 = not Ready, 1 = unique bind,
    2+ = real double-open. Never treat host_count as listener_count. Missing
    keys are omitted; values keep brackets (e.g. ``[25654,25656]``).
    """
    if not isinstance(detail, str) or not detail:
        return {}
    payload = detail.split("|", 1)[-1].strip() if "|" in detail else detail.strip()
    out: dict[str, str] = {}
    for token in payload.split():
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        if key in _LISTENER_WAIT_EVIDENCE_KEYS:
            out[key] = value
    return out


def _run_harness(
    cmd: list[str],
    *,
    timeout: float = _HARNESS_TIMEOUT_SECONDS,
) -> subprocess.CompletedProcess[str]:
    """Run the harness; on timeout, reap desktop+sidecar before failing."""
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        # Snapshot+reap while parent relationships are still intact. Plain
        # kill of the harness alone leaves JS Agent.app + js-agent-host as
        # ppid=1 orphans that poison later outer-smoke runs.
        try:
            reap_owned_tree(proc.pid)
        finally:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        raise subprocess.TimeoutExpired(
            cmd=exc.cmd,
            timeout=exc.timeout,
            output=exc.output,
            stderr=exc.stderr,
        ) from exc
    return subprocess.CompletedProcess(
        args=cmd,
        returncode=proc.returncode if proc.returncode is not None else -1,
        stdout=stdout or "",
        stderr=stderr or "",
    )


def _default_harness_path(evidence_dir: Path) -> Path:
    return (evidence_dir / "harness" / _HARNESS_APP_NAME).resolve()


def _harness_executable(harness_path: Path) -> Path:
    if harness_path.is_dir() and harness_path.name.endswith(".app"):
        return harness_path / _HARNESS_EXEC
    return harness_path


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _trusted_harness_hash(
    *, harness_bundle: Path, harness_exec: Path, repo_root: Path
) -> str | None:
    manifest_path = harness_bundle.parent / "manifest.json"
    expected_fields = {
        "schema_version",
        "source_path",
        "source_sha256",
        "executable_path",
        "executable_sha256",
        "bundle_identifier",
    }
    try:
        manifest = strict_load_object(manifest_path)
        source = (repo_root / _HARNESS_SOURCE).resolve(strict=True)
        info = plistlib.loads((harness_bundle / "Contents/Info.plist").read_bytes())
        executable_relative = harness_exec.relative_to(harness_bundle).as_posix()
        actual_executable_sha = _sha256_file(harness_exec)
    except (OSError, RuntimeError, TypeError, ValueError, StrictJSONError):
        return None
    if (
        set(manifest) != expected_fields
        or manifest.get("schema_version") != _HARNESS_MANIFEST_SCHEMA
        or manifest.get("source_path") != _HARNESS_SOURCE.as_posix()
        or manifest.get("source_sha256") != _sha256_file(source)
        or manifest.get("executable_path") != f"{harness_bundle.name}/{executable_relative}"
        or manifest.get("executable_sha256") != actual_executable_sha
        or manifest.get("bundle_identifier") != _HARNESS_BUNDLE_IDENTIFIER
        or info.get("CFBundleIdentifier") != _HARNESS_BUNDLE_IDENTIFIER
        or info.get("CFBundleExecutable") != harness_exec.name
    ):
        return None
    return actual_executable_sha


def _parse_utc(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _manifest_bindings(
    *, app_path: Path, manifest_path: Path, repo_root: Path
) -> dict[str, str] | None:
    from desktop.build_driver import _sha256_tree, verify_manifest

    if verify_manifest(manifest_path, repo_root=repo_root):
        return None
    try:
        manifest = strict_load_object(manifest_path)
        artifacts = manifest["artifacts"]
        rust_main = artifacts["rust_main"]
        app_tree = artifacts["app_tree"]
        info = plistlib.loads((app_path / "Contents/Info.plist").read_bytes())
        executable_name = info["CFBundleExecutable"]
        bundle_identifier = info["CFBundleIdentifier"]
        executable = app_path / "Contents/MacOS" / executable_name
        actual_executable = _sha256_file(executable)
        actual_tree = _sha256_tree(app_path)
    except (KeyError, OSError, TypeError, ValueError, StrictJSONError, RuntimeError):
        return None
    output_root = manifest_path.parent.resolve()
    expected_app = (output_root / str(app_tree.get("path", ""))).resolve()
    expected_executable = (output_root / str(rust_main.get("path", ""))).resolve()
    if (
        expected_app != app_path.resolve()
        or expected_executable != executable.resolve()
        or bundle_identifier != EXPECTED_BUNDLE_IDENTIFIER
        or rust_main.get("sha256") != actual_executable
        or app_tree.get("sha256") != actual_tree
    ):
        return None
    return {
        "app_sha256": actual_executable,
        "app_tree_sha256": actual_tree,
        "desktop_manifest_sha256": _sha256_file(manifest_path),
        "bundle_identifier": bundle_identifier,
    }


def _valid_scenarios(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != REQUIRED_SCENARIOS:
        return False
    for scenario in value.values():
        if not isinstance(scenario, dict) or set(scenario) != _SCENARIO_FIELDS:
            return False
        duration = scenario.get("duration_ms")
        if (
            scenario.get("passed") is not True
            or scenario.get("status") != "passed"
            or not isinstance(scenario.get("detail"), str)
            or not isinstance(duration, int | float)
            or isinstance(duration, bool)
            or not math.isfinite(float(duration))
            or float(duration) < 0
            or scenario.get("error_code") is not None
        ):
            return False
    return True


def _valid_result(
    result: object,
    *,
    nonce: str,
    invocation_started: datetime,
    invocation_finished: datetime,
    bindings: dict[str, str],
    harness_sha256: str,
) -> bool:
    if not isinstance(result, dict) or set(result) != _RESULT_FIELDS:
        return False
    started = _parse_utc(result.get("started_utc"))
    finished = _parse_utc(result.get("finished_utc"))
    if started is None or finished is None:
        return False
    allowed_skew = timedelta(seconds=5)
    if (
        result.get("schema_version") != RESULT_SCHEMA_VERSION
        or result.get("ok") is not True
        or result.get("status") != "passed"
        or result.get("nonce") != nonce
        or result.get("accessibility_authorized") is not True
        or not isinstance(result.get("target_pid"), int)
        or isinstance(result.get("target_pid"), bool)
        or int(result["target_pid"]) <= 0
        or started > finished
        or started < invocation_started - allowed_skew
        or finished > invocation_finished + allowed_skew
        or not _valid_scenarios(result.get("scenarios"))
    ):
        return False
    for field, expected in bindings.items():
        actual = result.get(field)
        if not isinstance(actual, str) or not secrets.compare_digest(actual, expected):
            return False
    actual_harness = result.get("harness_sha256")
    return isinstance(actual_harness, str) and secrets.compare_digest(
        actual_harness, harness_sha256
    )


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Tauri WebView lifecycle gate")
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--app-path", type=Path, required=True)
    parser.add_argument("--harness-path", type=Path, default=None)
    args = parser.parse_args(argv)

    app_path = args.app_path.resolve()
    if not app_path.is_dir():
        print(f"[FAIL] tauri_webview_lifecycle: app not found: {app_path}", file=sys.stderr)
        print(format_release_result_line(gate="tauri_webview_lifecycle", ok=False))
        return 1

    harness_bundle = (args.harness_path or _default_harness_path(args.evidence_dir)).resolve()
    harness_exec = _harness_executable(harness_bundle)
    if not harness_exec.is_file():
        print(
            f"[FAIL] tauri_webview_lifecycle: harness executable not found: {harness_exec} "
            f"(expected packaged {_HARNESS_APP_NAME})",
            file=sys.stderr,
        )
        print(format_release_result_line(gate="tauri_webview_lifecycle", ok=False))
        return 1

    # Reject bare binaries for final gate runs when caller did not pass an explicit path
    # that is already an .app (defense in depth for default layout).
    if args.harness_path is None and not harness_bundle.name.endswith(".app"):
        print(
            "[FAIL] tauri_webview_lifecycle: bare harness binary rejected; package Harness.app",
            file=sys.stderr,
        )
        print(format_release_result_line(gate="tauri_webview_lifecycle", ok=False))
        return 1

    result_dir = args.evidence_dir.resolve() / "tauri-webview"
    result_dir.mkdir(parents=True, exist_ok=True)
    published_result = result_dir / "result.json"
    try:
        published_result.unlink(missing_ok=True)
    except OSError as exc:
        print(f"[FAIL] tauri_webview_lifecycle: cannot remove stale result: {exc}", file=sys.stderr)
        print(format_release_result_line(gate="tauri_webview_lifecycle", ok=False))
        return 1

    manifest_path = args.evidence_dir.resolve() / "desktop-build/manifest.json"
    bindings = _manifest_bindings(
        app_path=app_path,
        manifest_path=manifest_path,
        repo_root=Path.cwd().resolve(),
    )
    if bindings is None:
        print(
            "[FAIL] tauri_webview_lifecycle: desktop manifest/app binding invalid", file=sys.stderr
        )
        print(format_release_result_line(gate="tauri_webview_lifecycle", ok=False))
        return 1
    harness_sha256 = _trusted_harness_hash(
        harness_bundle=harness_bundle,
        harness_exec=harness_exec,
        repo_root=Path.cwd().resolve(),
    )
    if harness_sha256 is None:
        print(
            "[FAIL] tauri_webview_lifecycle: harness provenance binding invalid",
            file=sys.stderr,
        )
        print(format_release_result_line(gate="tauri_webview_lifecycle", ok=False))
        return 1

    nonce = secrets.token_hex(32)
    private_dir = Path(tempfile.mkdtemp(prefix=f"run-{nonce}-", dir=result_dir))
    result_path = private_dir / "result.json"

    cmd = [
        str(harness_exec),
        "--app-path",
        str(app_path),
        "--result-path",
        str(result_path),
        "--nonce",
        nonce,
        "--app-tree-sha256",
        bindings["app_tree_sha256"],
        "--desktop-manifest-path",
        str(manifest_path),
    ]

    invocation_started = datetime.now(tz=UTC)
    try:
        completed = _run_harness(cmd, timeout=_HARNESS_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        # Reap already ran inside _run_harness. Preserve any mid-run flush
        # BEFORE deleting private_dir (the hang root cause of missing evidence).
        salvaged = _salvage_partial_result(result_path, published_result)
        print(
            f"[FAIL] tauri_webview_lifecycle: harness timed out after "
            f"{_HARNESS_TIMEOUT_SECONDS}s (owned .app + sidecar reaped)",
            file=sys.stderr,
        )
        if salvaged:
            try:
                partial = strict_load_object(published_result)
                scenarios = partial.get("scenarios", {}) if isinstance(partial, dict) else {}
                recorded = sorted(scenarios) if isinstance(scenarios, dict) else []
            except (OSError, ValueError, StrictJSONError):
                recorded = []
            print(
                f"[FAIL] tauri_webview_lifecycle: preserved partial result.json "
                f"scenarios={recorded}",
                file=sys.stderr,
            )
        else:
            print(
                "[FAIL] tauri_webview_lifecycle: no durable partial result.json "
                "(harness never flushed)",
                file=sys.stderr,
            )
        print(format_release_result_line(gate="tauri_webview_lifecycle", ok=False))
        shutil.rmtree(private_dir, ignore_errors=True)
        return 1
    invocation_finished = datetime.now(tz=UTC)

    if completed.returncode == _AX_EXIT:
        print(
            "[FAIL] tauri_webview_lifecycle: accessibility_not_authorized "
            "(grant Accessibility only to JS Agent UI Test Harness.app)",
            file=sys.stderr,
        )
        if completed.stderr:
            print(completed.stderr, file=sys.stderr)
        _salvage_partial_result(result_path, published_result)
        print(format_release_result_line(gate="tauri_webview_lifecycle", ok=False))
        shutil.rmtree(private_dir, ignore_errors=True)
        return 1

    if completed.returncode != 0:
        print(
            f"[FAIL] tauri_webview_lifecycle: harness exit={completed.returncode}",
            file=sys.stderr,
        )
        if completed.stderr:
            print(completed.stderr, file=sys.stderr)
        if completed.stdout:
            # Harness may emit JSON result on stdout for diagnostics.
            print(completed.stdout[:4000], file=sys.stderr)
        # Scenario hard-timeout exits EXIT_ASSERT after flushing result.json —
        # preserve that evidence the same way as outer TimeoutExpired.
        salvaged = _salvage_partial_result(result_path, published_result)
        if salvaged:
            try:
                partial = strict_load_object(published_result)
                scenarios = partial.get("scenarios", {}) if isinstance(partial, dict) else {}
                recorded = sorted(scenarios) if isinstance(scenarios, dict) else []
            except (OSError, ValueError, StrictJSONError):
                recorded = []
            print(
                f"[FAIL] tauri_webview_lifecycle: preserved result.json "
                f"scenarios={recorded}",
                file=sys.stderr,
            )
        print(format_release_result_line(gate="tauri_webview_lifecycle", ok=False))
        shutil.rmtree(private_dir, ignore_errors=True)
        return 1

    try:
        result_stat = result_path.lstat()
        if not stat.S_ISREG(result_stat.st_mode) or result_stat.st_nlink != 1:
            raise OSError("result must be a single-link regular file")
        result = strict_load_object(result_path)
    except (OSError, ValueError, StrictJSONError) as exc:
        print(f"[FAIL] tauri_webview_lifecycle: cannot read result: {exc}", file=sys.stderr)
        print(format_release_result_line(gate="tauri_webview_lifecycle", ok=False))
        shutil.rmtree(private_dir, ignore_errors=True)
        return 1

    if result.get("status") == "accessibility_not_authorized":
        print(
            "[FAIL] tauri_webview_lifecycle: accessibility_not_authorized",
            file=sys.stderr,
        )
        print(format_release_result_line(gate="tauri_webview_lifecycle", ok=False))
        shutil.rmtree(private_dir, ignore_errors=True)
        return 1

    current_bindings = _manifest_bindings(
        app_path=app_path,
        manifest_path=manifest_path,
        repo_root=Path.cwd().resolve(),
    )
    current_harness_sha = _trusted_harness_hash(
        harness_bundle=harness_bundle,
        harness_exec=harness_exec,
        repo_root=Path.cwd().resolve(),
    )
    ok = (
        current_bindings == bindings
        and current_harness_sha is not None
        and secrets.compare_digest(current_harness_sha, harness_sha256)
        and _valid_result(
            result,
            nonce=nonce,
            invocation_started=invocation_started,
            invocation_finished=invocation_finished,
            bindings=bindings,
            harness_sha256=harness_sha256,
        )
    )
    scenarios = result.get("scenarios", {}) if isinstance(result, dict) else {}
    passed_count = sum(1 for v in scenarios.values() if isinstance(v, dict) and v.get("passed"))
    total_count = len(scenarios)

    if ok:
        os.replace(result_path, published_result)
        print(f"[OK] tauri_webview_lifecycle scenarios={passed_count}/{total_count}")
    else:
        failed = [k for k, v in scenarios.items() if not (isinstance(v, dict) and v.get("passed"))]
        print(f"[FAIL] tauri_webview_lifecycle failed={failed}", file=sys.stderr)

    shutil.rmtree(private_dir, ignore_errors=True)
    marker_bindings = None
    if ok:
        marker_bindings = {
            "desktop_manifest_sha256": bindings["desktop_manifest_sha256"],
            "app_tree_sha256": bindings["app_tree_sha256"],
            "app_sha256": bindings["app_sha256"],
            "result_sha256": _sha256_file(published_result),
            "harness_sha256": harness_sha256,
        }
    print(
        format_release_result_line(
            gate="tauri_webview_lifecycle",
            ok=ok,
            bindings=marker_bindings,
        )
    )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
