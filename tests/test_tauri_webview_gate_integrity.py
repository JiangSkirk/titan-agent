from __future__ import annotations

import hashlib
import json
import plistlib
import shutil
import signal
import subprocess
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from js.echo.ledger.release_gates import (
    _valid_local_gate_receipt,
    format_release_result_line,
    parse_gate_stdout,
    release_source_digest,
    validate_final_local_gate_evidence,
    write_toolchain_lock,
)
from scripts import run_tauri_webview_gate as gate
from tests.test_local_gate_receipt_round85 import (
    _ensure_repo_toolchain,
    _valid_receipt_payload,
    _write_capture,
)

ResultMutation = Callable[[dict[str, object], list[str]], object]
SetupMutation = Callable[[Path], object]
FormalMutation = Callable[[dict[str, object], Path], object]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _fixture(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    evidence = tmp_path / "evidence"
    app = evidence / "desktop-build/artifacts/JS Agent.app"
    executable = app / "Contents/MacOS/js-agent-desktop"
    executable.parent.mkdir(parents=True, exist_ok=True)
    executable.write_bytes(b"app-v1")
    info = app / "Contents/Info.plist"
    info.write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.titan.js-agent</string>
<key>CFBundleExecutable</key><string>js-agent-desktop</string>
<key>CFBundleShortVersionString</key><string>0.1.0</string>
<key>CFBundleVersion</key><string>2026081101</string>
</dict></plist>
""",
        encoding="utf-8",
    )
    harness = (
        evidence / "harness/JS Agent UI Test Harness.app/Contents/MacOS/js-agent-ui-test-harness"
    )
    harness.parent.mkdir(parents=True, exist_ok=True)
    harness.write_bytes(b"harness-v1")
    harness.chmod(0o755)
    harness_contents = harness.parent.parent
    (harness_contents / "Info.plist").write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>local.js-agent.ui-test-harness</string>
<key>CFBundleExecutable</key><string>js-agent-ui-test-harness</string>
</dict></plist>
""",
        encoding="utf-8",
    )
    source = (
        Path(__file__).resolve().parents[1] / "desktop/tests/harness/tauri_webview_harness.swift"
    )
    harness_manifest = evidence / "harness/manifest.json"
    harness_manifest.write_text(
        json.dumps(
            {
                "schema_version": "JSAgentTauriHarnessProvenanceV1",
                "source_path": "desktop/tests/harness/tauri_webview_harness.swift",
                "source_sha256": _sha256(source),
                "executable_path": (
                    "JS Agent UI Test Harness.app/Contents/MacOS/js-agent-ui-test-harness"
                ),
                "executable_sha256": _sha256(harness),
                "bundle_identifier": "local.js-agent.ui-test-harness",
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    from desktop.build_driver import _sha256_tree

    manifest = evidence / "desktop-build/manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema": "JSAgentDesktopProvenanceV4",
                "source_digest": "a" * 64,
                "arch": "aarch64-apple-darwin",
                "product_version": "0.1.0",
                "build_number": "2026081101",
                "artifacts": {
                    "rust_main": {
                        "path": "artifacts/JS Agent.app/Contents/MacOS/js-agent-desktop",
                        "sha256": _sha256(executable),
                    },
                    "app_tree": {
                        "path": "artifacts/JS Agent.app",
                        "sha256": _sha256_tree(app),
                    },
                },
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return evidence, app, harness.parent.parent.parent, manifest


def _valid_result(
    *,
    nonce: str,
    app: Path,
    harness_exec: Path,
    manifest: Path,
    started: datetime | None = None,
) -> dict[str, object]:
    from desktop.build_driver import _sha256_tree

    started_at = started or datetime.now(tz=UTC)
    scenarios = {
        name: {
            "passed": True,
            "status": "passed",
            "detail": "fixture",
            "duration_ms": 1.0,
            "error_code": None,
        }
        for name in gate.REQUIRED_SCENARIOS
    }
    return {
        "schema_version": gate.RESULT_SCHEMA_VERSION,
        "ok": True,
        "status": "passed",
        "nonce": nonce,
        "scenarios": scenarios,
        "app_sha256": _sha256(app / "Contents/MacOS/js-agent-desktop"),
        "app_tree_sha256": _sha256_tree(app),
        "harness_sha256": _sha256(harness_exec),
        "desktop_manifest_sha256": _sha256(manifest),
        "bundle_identifier": "com.titan.js-agent",
        "accessibility_authorized": True,
        "target_pid": 123,
        "started_utc": started_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "finished_utc": (started_at + timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def _run(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    mutate: ResultMutation | None = None,
    setup_mutate: SetupMutation | None = None,
    returncode: int = 0,
) -> tuple[int, Path, Path, Path]:
    evidence, app, harness_bundle, manifest = _fixture(tmp_path)
    if setup_mutate is not None:
        setup_mutate(evidence)
    harness_exec = harness_bundle / "Contents/MacOS/js-agent-ui-test-harness"
    monkeypatch.setattr("desktop.build_driver.verify_manifest", lambda *_a, **_kw: [])

    def fake_run(cmd: list[str], **_kwargs: object) -> SimpleNamespace:
        nonce = cmd[cmd.index("--nonce") + 1]
        result_path = Path(cmd[cmd.index("--result-path") + 1])
        payload = _valid_result(
            nonce=nonce,
            app=app,
            harness_exec=harness_exec,
            manifest=manifest,
        )
        if mutate is not None:
            mutate(payload, cmd)
        result_path.write_text(json.dumps(payload), encoding="utf-8")
        return SimpleNamespace(returncode=returncode, stdout="", stderr="")

    monkeypatch.setattr(gate, "_run_harness", fake_run)
    rc = gate.main(
        [
            "--evidence-dir",
            str(evidence),
            "--app-path",
            str(app),
            "--harness-path",
            str(harness_bundle),
        ]
    )
    return rc, evidence, app, manifest


def test_wrapper_ignores_stale_fixed_result_and_publishes_current_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    evidence, _, _, _ = _fixture(tmp_path)
    stale = evidence / "tauri-webview/result.json"
    stale.parent.mkdir(parents=True)
    stale.write_text('{"ok":true,"scenarios":{}}', encoding="utf-8")

    rc, evidence, _, _ = _run(monkeypatch, tmp_path)

    assert rc == 0
    published = json.loads((evidence / "tauri-webview/result.json").read_text())
    assert published["schema_version"] == gate.RESULT_SCHEMA_VERSION
    assert published["nonce"]
    assert set(published["scenarios"]) == gate.REQUIRED_SCENARIOS


@pytest.mark.parametrize(
    "mutation",
    [
        lambda result, _cmd: result.update(scenarios={}),
        lambda result, _cmd: result["scenarios"].pop(next(iter(gate.REQUIRED_SCENARIOS))),
        lambda result, _cmd: result["scenarios"].update(
            {"unexpected_scenario": dict(next(iter(result["scenarios"].values())))}
        ),
        lambda result, _cmd: result.update(nonce="wrong-nonce"),
        lambda result, _cmd: result.update(
            started_utc="2020-01-01T00:00:00Z", finished_utc="2020-01-01T00:00:01Z"
        ),
        lambda result, _cmd: result.update(app_sha256="0" * 64),
        lambda result, _cmd: result.update(app_tree_sha256="0" * 64),
        lambda result, _cmd: result.update(harness_sha256="0" * 64),
        lambda result, _cmd: result.update(bundle_identifier="local.js-agent.ui-test-harness"),
        lambda result, _cmd: result.update(desktop_manifest_sha256="0" * 64),
        lambda result, _cmd: result.update(accessibility_authorized=False),
        lambda result, _cmd: result.update(unexpected=True),
        lambda result, _cmd: next(iter(result["scenarios"].values())).update(status="failed"),
    ],
    ids=[
        "empty-scenarios",
        "missing-scenario",
        "extra-scenario",
        "wrong-nonce",
        "stale-time",
        "wrong-app-executable",
        "wrong-app-tree",
        "wrong-harness",
        "wrong-bundle",
        "wrong-manifest",
        "accessibility-not-authorized",
        "extra-result-field",
        "scenario-status-not-passed",
    ],
)
def test_wrapper_rejects_forged_result(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    mutation: ResultMutation,
) -> None:
    rc, _, _, _ = _run(monkeypatch, tmp_path, mutate=mutation)
    assert rc == 1


def test_wrapper_rejects_replaced_app_after_manifest_validation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def replace_app(result: dict[str, object], cmd: list[str]) -> None:
        app = Path(cmd[cmd.index("--app-path") + 1])
        (app / "Contents/MacOS/js-agent-desktop").write_bytes(b"replaced")

    rc, _, _, _ = _run(monkeypatch, tmp_path, mutate=replace_app)
    assert rc == 1


def test_wrapper_rejects_harness_not_bound_to_current_source(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def tamper(evidence: Path) -> None:
        path = evidence / "harness/manifest.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["source_sha256"] = "0" * 64
        path.write_text(json.dumps(payload), encoding="utf-8")

    rc, _, _, _ = _run(monkeypatch, tmp_path, setup_mutate=tamper)
    assert rc == 1


def test_swift_harness_contract_has_real_replay_mode_readback_and_term_first() -> None:
    source = (
        Path(__file__).resolve().parents[1] / "desktop/tests/harness/tauri_webview_harness.swift"
    ).read_text(encoding="utf-8")

    assert '"--nonce"' in source
    assert '"/api/appshell/desktop-bootstrap"' in source
    assert "409" in source
    assert '"/api/appshell/capabilities"' in source
    assert '"active_mode"' in source
    assert "SELECT epoch FROM appshell_sessions" in source
    assert "pressedWork && pressedPersonal" in source
    assert 'Data("JSAgentTreeDigestV2\\0".utf8)' in source
    assert "posixPermissions" in source
    assert 'entryType: "directory"' in source
    clean_quit = source.index('scenario("clean_quit_no_orphans"')
    restart = source.index('"restart_simplified_flow"')
    clean_block = source[clean_quit:restart]
    assert "SIGKILL" not in clean_block
    assert "terminateOwned" not in clean_block


def test_swift_harness_ax_walks_are_bounded() -> None:
    """Regression: unbounded WKWebView AX walks hung the 600s outer smoke gate."""
    source = (
        Path(__file__).resolve().parents[1] / "desktop/tests/harness/tauri_webview_harness.swift"
    ).read_text(encoding="utf-8")

    assert "AXUIElementSetMessagingTimeout" in source
    assert "AX_TREE_MAX_NODES" in source
    assert "collectAxTreeBounded" in source
    assert "AxWalkBudget" in source
    assert "processTreePids" in source
    # Scenario paths must use the bounded helper, not an open-ended walk.
    assert "collectAxTree(win)" not in source
    assert "collectAxTree(appElement)" not in source
    assert "maxDepth: Int = 8" not in source
    assert "budget.expired" in source
    assert "AX_MESSAGING_TIMEOUT_SECONDS" in source


def test_swift_harness_per_scenario_timeout_and_mid_run_flush() -> None:
    """One wedged AX scenario must not burn the whole 600s; flush before exit/reap."""
    source = (
        Path(__file__).resolve().parents[1] / "desktop/tests/harness/tauri_webview_harness.swift"
    ).read_text(encoding="utf-8")

    assert "SCENARIO_HARD_TIMEOUT_SECONDS" in source
    assert "SCENARIO_LAUNCH_TIMEOUT_SECONDS" in source
    assert "func flushResult" in source
    assert "scenario_timeout" in source
    assert 'status: "timeout"' in source
    assert "DispatchSource.makeTimerSource" in source
    # Mid-run flush must happen after each scenario outcome, and watchdog must
    # flush BEFORE exit so Python TimeoutExpired can still salvage evidence.
    assert "flushResult()" in source
    assert "flushResult(markFinished: true)" in source
    assert source.index("flushResult(markFinished: true)") < source.index(
        "exit(Int32(EXIT_ASSERT))"
    )


def test_swift_harness_cold_start_timeout_records_host_and_listener_evidence() -> None:
    """S2 timeout detail must keep host process inventory separate from LISTEN."""
    source = (
        Path(__file__).resolve().parents[1] / "desktop/tests/harness/tauri_webview_harness.swift"
    ).read_text(encoding="utf-8")

    assert "func listenerWaitEvidence" in source
    assert "func listenerWaitEvidenceFromSnapshot" in source
    assert "func probeListeners" in source
    assert "func probeProcessRows" in source
    assert "func probeProcessRowsRecover" in source
    assert "func probeProcessRowsNarrowed" in source
    assert "host_count=" in source
    assert "host_pids=" in source
    assert "listener_count=" in source
    assert "listeners=" in source
    assert "tree_pids=" in source
    assert "stdout_tail=" in source
    assert "stderr_tail=" in source
    assert "ps=" in source
    assert "lsof=" in source
    # Probe failure must not lie with measured zeros.
    assert 'host_count=unknown' in source
    assert 'listener_count=unknown' in source
    assert "psInventoryReliable" in source
    assert "lsofInventoryReliable" in source
    # Host PIDs must not be treated as listeners (onefile parent+child).
    assert "never treat host_count as listener_count" in source
    assert "Gate on LISTEN count only" in source
    assert "found.count == 1" in source
    # Watchdog detail must append the evidence blob, not only the bare timeout text.
    assert "scenario hard timeout after \\(Int(timeout))s | \\(evidence)" in source
    assert "no single loopback listener within" in source
    assert "rememberListenerWaitEvidence" in source
    assert "appStdoutLogPath" in source
    assert "appStderrLogPath" in source
    # Cold-start must flush target_pid before wait so salvage keeps it on wedge.
    cold = source.split('scenario(\n    "cold_start_controlled_env"', 1)[1]
    cold = cold.split('scenario("process_tree_one_app_one_sidecar")', 1)[0]
    assert "flushResult()" in cold
    assert cold.index("result.target_pid") < cold.index("try waitForSingleListener")
    assert cold.index("flushResult()") < cold.index("try waitForSingleListener")
    assert cold.index("appStdoutLogPath = outLog") < cold.index("try waitForSingleListener")


def test_parse_listener_wait_evidence_keeps_host_pids_separate_from_listens() -> None:
    """host_count=2 is onefile inventory; only listener_count diagnoses Ready/double-open."""
    # 2026091202-shaped: two host PIDs, zero LISTENs → sidecar not Ready (not double-open).
    not_ready = (
        "scenario hard timeout after 120s | app_running=true "
        "tree_pids=[25649,25654,25656] host_count=2 host_pids=[25654,25656] "
        "listener_count=0 listeners=[] ps=ok lsof=ok stdout_tail= stderr_tail="
    )
    not_ready_parsed = gate.parse_listener_wait_evidence(not_ready)
    assert not_ready_parsed["host_count"] == "2"
    assert not_ready_parsed["host_pids"] == "[25654,25656]"
    assert not_ready_parsed["listener_count"] == "0"
    assert not_ready_parsed["listeners"] == "[]"
    assert not_ready_parsed["host_count"] != not_ready_parsed["listener_count"]

    # Onefile parent+child with exactly one LISTEN — normal Ready, not double-open.
    onefile_ready = (
        "pid=25649 listener=127.0.0.1:54321 | app_running=true "
        "tree_pids=[25649,25654,25656] host_count=2 host_pids=[25654,25656] "
        "listener_count=1 listeners=[127.0.0.1:54321] ps=ok lsof=ok "
        "stdout_tail= stderr_tail="
    )
    ready_parsed = gate.parse_listener_wait_evidence(onefile_ready)
    assert ready_parsed["host_count"] == "2"
    assert ready_parsed["listener_count"] == "1"
    assert ready_parsed["listeners"] == "[127.0.0.1:54321]"

    # Two distinct LISTEN addresses — real double-open (independent of host_count).
    double_open = (
        "no single loopback listener within 100s | app_running=true "
        "tree_pids=[25649,25654,25656] host_count=2 host_pids=[25654,25656] "
        "listener_count=2 listeners=[127.0.0.1:4001,127.0.0.1:4002] "
        "ps=ok lsof=ok stdout_tail= stderr_tail="
    )
    double_parsed = gate.parse_listener_wait_evidence(double_open)
    assert double_parsed["host_count"] == "2"
    assert double_parsed["listener_count"] == "2"
    assert double_parsed["listeners"] == "[127.0.0.1:4001,127.0.0.1:4002]"

    # Successful empty probe may still report measured zeros.
    none_host = (
        "no single loopback listener within 100s | app_running=true "
        "tree_pids=[25649] host_count=0 host_pids=[] "
        "listener_count=0 listeners=[] ps=ok lsof=ok stdout_tail=x stderr_tail=y"
    )
    none_parsed = gate.parse_listener_wait_evidence(none_host)
    assert none_parsed["host_count"] == "0"
    assert none_parsed["host_pids"] == "[]"
    assert none_parsed["listener_count"] == "0"
    assert none_parsed["listeners"] == "[]"

    # Official post-#16 lie shape: ps timed out / lsof skipped → unknown, not 0.
    hung = (
        "scenario hard timeout after 120s | app_running=unknown tree_pids=[25649] "
        "host_count=unknown host_pids=unknown listener_count=unknown listeners=unknown "
        "ps=timeout lsof=skipped stdout_tail= stderr_tail="
    )
    hung_parsed = gate.parse_listener_wait_evidence(hung)
    assert hung_parsed["ps"] == "timeout"
    assert hung_parsed["lsof"] == "skipped"
    assert hung_parsed["host_count"] == "unknown"
    assert hung_parsed["host_pids"] == "unknown"
    assert hung_parsed["listener_count"] == "unknown"
    assert hung_parsed["listeners"] == "unknown"
    assert hung_parsed["host_count"] != "0"
    assert hung_parsed["listener_count"] != "0"

    # lsof timeout with measured hosts → host counts stay numeric; listeners unknown.
    lsof_hung = (
        "scenario hard timeout after 120s | app_running=true "
        "tree_pids=[25649,25654,25656] host_count=2 host_pids=[25654,25656] "
        "listener_count=unknown listeners=unknown ps=ok lsof=timeout "
        "stdout_tail= stderr_tail="
    )
    lsof_parsed = gate.parse_listener_wait_evidence(lsof_hung)
    assert lsof_parsed["host_count"] == "2"
    assert lsof_parsed["listener_count"] == "unknown"
    assert lsof_parsed["listeners"] == "unknown"
    assert lsof_parsed["lsof"] == "timeout"


def test_probe_timeout_detail_must_not_claim_measured_zero() -> None:
    """Contract: timeout/skipped probes emit unknown; measured empty may be 0."""
    source = (
        Path(__file__).resolve().parents[1] / "desktop/tests/harness/tauri_webview_harness.swift"
    ).read_text(encoding="utf-8")
    # Formatting path must gate counts on reliability helpers.
    assert 'host_count=unknown' in source
    assert 'listener_count=unknown' in source
    assert 'host_pids=unknown' in source
    assert 'listeners=unknown' in source
    assert "psReliable ?" in source
    assert "lsofReliable" in source
    assert "probeProcessRowsRecover" in source
    assert "probeProcessRowsNarrowed" in source
    # Pass still requires exactly one loopback LISTEN — do not relax.
    wait = source.split("func waitForSingleListener", 1)[1].split("// Scenarios", 1)[0]
    assert "found.count == 1" in wait
    # 120s scenario watchdog constant must remain the launch timeout.
    assert "SCENARIO_LAUNCH_TIMEOUT_SECONDS: TimeInterval = 120" in source


def test_wrapper_preserves_cold_start_timeout_evidence_fields(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Salvage path must keep host_count and listener_count as separate fields."""

    detail = (
        "scenario hard timeout after 120s | app_running=true "
        "tree_pids=[25649,25654,25656] host_count=2 host_pids=[25654,25656] "
        "listener_count=0 listeners=[] ps=ok lsof=ok stdout_tail= stderr_tail="
    )

    def mutate(result: dict[str, object], _cmd: list[str]) -> None:
        result["ok"] = False
        result["status"] = "failed"
        result["target_pid"] = 25649
        scenarios = result["scenarios"]
        assert isinstance(scenarios, dict)
        scenarios["cold_start_controlled_env"] = {
            "passed": False,
            "status": "timeout",
            "detail": detail,
            "duration_ms": 120098.0,
            "error_code": "scenario_timeout",
        }

    rc, evidence, _, _ = _run(monkeypatch, tmp_path, mutate=mutate, returncode=2)
    assert rc == 1
    published = evidence / "tauri-webview/result.json"
    assert published.is_file()
    payload = json.loads(published.read_text(encoding="utf-8"))
    cold = payload["scenarios"]["cold_start_controlled_env"]
    assert cold["error_code"] == "scenario_timeout"
    parsed = gate.parse_listener_wait_evidence(cold["detail"])
    assert parsed["host_count"] == "2"
    assert parsed["host_pids"] == "[25654,25656]"
    assert parsed["listener_count"] == "0"
    assert parsed["listeners"] == "[]"
    # Explicit contract: two host PIDs are not two listeners.
    assert parsed["host_count"] != parsed["listener_count"]
    err = capsys.readouterr().err
    assert "preserved result.json" in err


def test_process_tree_expands_sidecar_leader_group_only() -> None:
    rows = {
        100: (1, 100, "js-agent-ui-test-harness"),
        200: (100, 100, "JS Agent"),
        300: (200, 300, "js-agent-host"),  # process_group(0) leader
        301: (300, 300, "js-agent-host"),  # onefile child / LISTEN owner
        999: (1, 999, "unrelated"),
        400: (1, 100, "sibling-same-inherited-pgid"),
    }
    tree = gate.owned_process_tree(200, rows)
    assert tree == {200, 300, 301}
    assert 100 not in tree
    assert 400 not in tree
    assert 999 not in tree


def test_reap_owned_tree_signals_sidecar_group_before_root_disappears(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Timeout cleanup must target desktop+host while ppid links still exist."""
    live = {
        100: (1, 100, "harness"),
        200: (100, 100, "JS Agent"),
        300: (200, 300, "js-agent-host"),
        301: (300, 300, "js-agent-host"),
    }
    signals: list[tuple[str, int, int]] = []

    def provider() -> dict[int, tuple[int, int, str]]:
        return dict(live)

    def fake_kill(pid: int, sig: int) -> None:
        signals.append(("pid", pid, sig))
        live.pop(pid, None)

    def fake_killpg(pgid: int, sig: int) -> None:
        signals.append(("pgid", pgid, sig))
        for pid, (_ppid, group, _cmd) in list(live.items()):
            if group == pgid:
                live.pop(pid, None)

    monkeypatch.setattr(gate.os, "kill", fake_kill)
    monkeypatch.setattr(gate.os, "killpg", fake_killpg)

    targeted = gate.reap_owned_tree(
        100,
        rows_provider=provider,
        grace_seconds=0.0,
        kill_wait_seconds=0.0,
    )
    assert targeted == {100, 200, 300, 301}
    assert ("pgid", 100, signal.SIGTERM) in signals or ("pgid", 300, signal.SIGTERM) in signals
    assert ("pgid", 300, signal.SIGTERM) in signals
    assert live == {}


def test_wrapper_timeout_reaps_owned_tree(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    evidence, app, harness_bundle, _manifest = _fixture(tmp_path)
    monkeypatch.setattr("desktop.build_driver.verify_manifest", lambda *_a, **_kw: [])
    reaped: list[int] = []

    class FakePopen:
        def __init__(self, *_a: object, **_kw: object) -> None:
            self.pid = 4242

        def communicate(self, timeout: float | None = None) -> tuple[str, str]:
            raise subprocess.TimeoutExpired(cmd=["harness"], timeout=timeout or 1)

        def kill(self) -> None:
            return None

        def wait(self, timeout: float | None = None) -> int:
            return -9

    monkeypatch.setattr(subprocess, "Popen", FakePopen)

    def fake_reap(root_pid: int, **_kwargs: object) -> set[int]:
        reaped.append(root_pid)
        return {root_pid}

    monkeypatch.setattr(gate, "reap_owned_tree", fake_reap)

    rc = gate.main(
        [
            "--evidence-dir",
            str(evidence),
            "--app-path",
            str(app),
            "--harness-path",
            str(harness_bundle),
        ]
    )
    assert rc == 1
    assert reaped == [4242]
    # No mid-run flush → nothing durable published.
    assert not (evidence / "tauri-webview/result.json").exists()


def test_wrapper_timeout_preserves_partial_result(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """On outer TimeoutExpired, salvage mid-run result.json before private_dir rmtree."""
    evidence, app, harness_bundle, manifest = _fixture(tmp_path)
    harness_exec = harness_bundle / "Contents/MacOS/js-agent-ui-test-harness"
    monkeypatch.setattr("desktop.build_driver.verify_manifest", lambda *_a, **_kw: [])
    reaped: list[int] = []

    class FakePopen:
        def __init__(self, cmd: list[str], *_a: object, **_kw: object) -> None:
            self.pid = 4242
            self._cmd = cmd

        def communicate(self, timeout: float | None = None) -> tuple[str, str]:
            result_path = Path(self._cmd[self._cmd.index("--result-path") + 1])
            nonce = self._cmd[self._cmd.index("--nonce") + 1]
            # Simulate harness flush after early scenarios, then AX wedge.
            partial = {
                "schema_version": gate.RESULT_SCHEMA_VERSION,
                "ok": False,
                "status": "running",
                "nonce": nonce,
                "scenarios": {
                    "accessibility_probe": {
                        "passed": True,
                        "status": "passed",
                        "detail": "authorized",
                        "duration_ms": 1.0,
                        "error_code": None,
                    },
                    "cold_start_controlled_env": {
                        "passed": True,
                        "status": "passed",
                        "detail": "launched",
                        "duration_ms": 10.0,
                        "error_code": None,
                    },
                    "webview_shows_content": {
                        "passed": False,
                        "status": "timeout",
                        "detail": "scenario hard timeout after 90s",
                        "duration_ms": 90000.0,
                        "error_code": "scenario_timeout",
                    },
                },
                "app_sha256": _sha256(app / "Contents/MacOS/js-agent-desktop"),
                "app_tree_sha256": "a" * 64,
                "harness_sha256": _sha256(harness_exec),
                "desktop_manifest_sha256": _sha256(manifest),
                "bundle_identifier": "com.titan.js-agent",
                "accessibility_authorized": True,
                "target_pid": 99,
                "started_utc": datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "finished_utc": datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
            result_path.parent.mkdir(parents=True, exist_ok=True)
            result_path.write_text(json.dumps(partial), encoding="utf-8")
            raise subprocess.TimeoutExpired(cmd=self._cmd, timeout=timeout or 1)

        def kill(self) -> None:
            return None

        def wait(self, timeout: float | None = None) -> int:
            return -9

    monkeypatch.setattr(subprocess, "Popen", FakePopen)

    def fake_reap(root_pid: int, **_kwargs: object) -> set[int]:
        reaped.append(root_pid)
        return {root_pid}

    monkeypatch.setattr(gate, "reap_owned_tree", fake_reap)

    rc = gate.main(
        [
            "--evidence-dir",
            str(evidence),
            "--app-path",
            str(app),
            "--harness-path",
            str(harness_bundle),
        ]
    )
    assert rc == 1
    assert reaped == [4242]
    published = evidence / "tauri-webview/result.json"
    assert published.is_file()
    payload = json.loads(published.read_text(encoding="utf-8"))
    assert payload["ok"] is False
    assert "accessibility_probe" in payload["scenarios"]
    assert "cold_start_controlled_env" in payload["scenarios"]
    assert payload["scenarios"]["webview_shows_content"]["error_code"] == "scenario_timeout"
    # Ephemeral private run dir must be gone; durable evidence stays.
    assert list(evidence.glob("tauri-webview/run-*")) == []
    err = capsys.readouterr().err
    assert "preserved partial result.json" in err
    assert "accessibility_probe" in err


def test_wrapper_scenario_hard_timeout_exit_preserves_result(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Watchdog exit(EXIT_ASSERT) after flush must still publish durable evidence."""

    def mutate(result: dict[str, object], _cmd: list[str]) -> None:
        result["ok"] = False
        result["status"] = "failed"
        scenarios = result["scenarios"]
        assert isinstance(scenarios, dict)
        scenarios["webview_shows_content"] = {
            "passed": False,
            "status": "timeout",
            "detail": "scenario hard timeout after 90s",
            "duration_ms": 90000.0,
            "error_code": "scenario_timeout",
        }

    rc, evidence, _, _ = _run(monkeypatch, tmp_path, mutate=mutate, returncode=2)
    assert rc == 1
    published = evidence / "tauri-webview/result.json"
    assert published.is_file()
    payload = json.loads(published.read_text(encoding="utf-8"))
    assert payload["scenarios"]["webview_shows_content"]["error_code"] == "scenario_timeout"
    err = capsys.readouterr().err
    assert "preserved result.json" in err
    assert "harness exit=2" in err


def test_salvage_partial_result_rejects_unreadable(
    tmp_path: Path,
) -> None:
    published = tmp_path / "result.json"
    missing = tmp_path / "missing.json"
    assert gate._salvage_partial_result(missing, published) is False
    bad = tmp_path / "bad.json"
    bad.write_text("not-json", encoding="utf-8")
    assert gate._salvage_partial_result(bad, published) is False
    assert not published.exists()


def _artifact_bindings(
    *, evidence: Path, app: Path, harness_bundle: Path, manifest: Path, tauri: bool
) -> dict[str, str]:
    from desktop.build_driver import _sha256_tree

    bindings = {
        "desktop_manifest_sha256": _sha256(manifest),
        "app_tree_sha256": _sha256_tree(app),
        "app_sha256": _sha256(app / "Contents/MacOS/js-agent-desktop"),
    }
    if tauri:
        bindings.update(
            {
                "result_sha256": _sha256(evidence / "tauri-webview/result.json"),
                "harness_sha256": _sha256(
                    harness_bundle / "Contents/MacOS/js-agent-ui-test-harness"
                ),
            }
        )
    return bindings


def _bound_receipt(
    tmp_path: Path,
    *,
    gate_name: str,
    manifest_mutation: FormalMutation | None = None,
) -> tuple[dict[str, object], Path, Path]:
    from desktop import build_driver
    from desktop.tests.test_build_driver import (
        BUILD_NUMBER,
        _offline_build_inputs,
        _write_info_plist,
        _write_release_inputs,
        _write_zip_from_app,
    )

    root = tmp_path / "repo"
    root.mkdir()
    _write_release_inputs(root)
    harness_source = (
        Path(__file__).resolve().parents[1] / "desktop/tests/harness/tauri_webview_harness.swift"
    )
    root_harness_source = root / "desktop/tests/harness/tauri_webview_harness.swift"
    root_harness_source.parent.mkdir(parents=True)
    root_harness_source.write_bytes(harness_source.read_bytes())
    evidence, _old_app, harness_bundle, _old_manifest = _fixture(tmp_path)
    shutil.rmtree(evidence / "desktop-build")
    run = build_driver.prepare_build_run(
        output_dir=evidence / "desktop-build",
        repo_root=root,
    )
    artifacts = run.root / "artifacts"
    app = artifacts / "JS Agent.app"
    executable = app / "Contents/MacOS/js-agent-desktop"
    bundled_sidecar = app / "Contents/MacOS/js-agent-host"
    standalone = artifacts / build_driver.SIDECAR_NAME
    for path, content in (
        (executable, b"app-v1"),
        (bundled_sidecar, b"sidecar-v1"),
        (standalone, b"sidecar-v1"),
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    _write_info_plist(app / "Contents/Info.plist", build_number=BUILD_NUMBER)
    build_driver.normalize_app_bundle_permissions(app)
    standalone.chmod(0o755)
    source_digest = release_source_digest(root)
    zip_path = artifacts / (
        f"JS-Agent-0.1.0-macos-arm64-unsigned-{source_digest[:16]}.zip"
    )
    _write_zip_from_app(app, zip_path)
    manifest = build_driver.generate_manifest(
        source_digest=source_digest,
        build_number=BUILD_NUMBER,
        sidecar_path=standalone,
        app_path=app,
        zip_path=zip_path,
        run=run,
        repo_root=root,
        offline_inputs=_offline_build_inputs(tmp_path / "formal-inputs"),
    )
    manifest_payload = json.loads(manifest.read_text(encoding="utf-8"))
    if manifest_mutation is not None:
        manifest_mutation(manifest_payload, app)
    manifest.write_text(json.dumps(manifest_payload, sort_keys=True), encoding="utf-8")
    harness_exec = harness_bundle / "Contents/MacOS/js-agent-ui-test-harness"
    result_dir = evidence / "tauri-webview"
    result_dir.mkdir()
    result = _valid_result(
        nonce="1" * 64,
        app=app,
        harness_exec=harness_exec,
        manifest=manifest,
    )
    (result_dir / "result.json").write_text(json.dumps(result), encoding="utf-8")
    bindings = _artifact_bindings(
        evidence=evidence,
        app=app,
        harness_bundle=harness_bundle,
        manifest=manifest,
        tauri=gate_name == "tauri_webview_lifecycle",
    )
    stdout = evidence / "gates" / f"{gate_name}.stdout.txt"
    stderr = evidence / "gates" / f"{gate_name}.stderr.txt"
    stdout_sha = _write_capture(
        stdout,
        "[OK] fixture\n"
        + format_release_result_line(gate=gate_name, ok=True, bindings=bindings)
        + "\n",
    )
    stderr_sha = _write_capture(stderr, "")
    _ensure_repo_toolchain(root)
    write_toolchain_lock(evidence, root)
    receipt = _valid_receipt_payload(
        root=root,
        evidence_dir=evidence,
        gate_name=gate_name,
        stdout_path=stdout,
        stderr_path=stderr,
        stdout_sha256=stdout_sha,
        stderr_sha256=stderr_sha,
    )
    return receipt, root, evidence


@pytest.mark.parametrize("gate_name", ["desktop_build", "tauri_webview_lifecycle"])
def test_success_marker_requires_exact_artifact_bindings(gate_name: str) -> None:
    fields = {
        "desktop_manifest_sha256": "1" * 64,
        "app_tree_sha256": "2" * 64,
        "app_sha256": "3" * 64,
    }
    if gate_name == "tauri_webview_lifecycle":
        fields.update(result_sha256="4" * 64, harness_sha256="5" * 64)
    line = format_release_result_line(gate=gate_name, ok=True, bindings=fields)
    assert all(value in line for value in fields.values())
    unbound = format_release_result_line(gate=gate_name, ok=True)
    assert not parse_gate_stdout(
        "release_markers",
        unbound,
        exit_code=0,
        require_exit_code_zero=True,
        expected_gate=gate_name,
    )["ok"]


def test_tauri_receipt_fails_after_result_replacement(tmp_path: Path) -> None:
    receipt, root, evidence = _bound_receipt(tmp_path, gate_name="tauri_webview_lifecycle")
    digest = release_source_digest(root)
    assert _valid_local_gate_receipt(
        receipt,
        root=root,
        expected_source_digest=digest,
        evidence_dir=evidence,
    )
    final_dir = evidence / "final"
    final_dir.mkdir()
    (final_dir / "tauri_webview_lifecycle.receipt.json").write_text(
        json.dumps(receipt), encoding="utf-8"
    )
    before = validate_final_local_gate_evidence(
        root,
        final_dir=final_dir,
        evidence_dir=evidence,
        expected_source_digest=digest,
    )
    assert "tauri_webview_lifecycle" in before.passed_gates
    (evidence / "tauri-webview/result.json").write_text("{}", encoding="utf-8")
    assert not _valid_local_gate_receipt(
        receipt,
        root=root,
        expected_source_digest=digest,
        evidence_dir=evidence,
    )
    after = validate_final_local_gate_evidence(
        root,
        final_dir=final_dir,
        evidence_dir=evidence,
        expected_source_digest=digest,
    )
    assert "tauri_webview_lifecycle" not in after.passed_gates
    assert "tauri_webview_lifecycle:invalid_receipt" in after.blockers


def test_desktop_receipt_fails_after_app_replacement(tmp_path: Path) -> None:
    receipt, root, evidence = _bound_receipt(tmp_path, gate_name="desktop_build")
    digest = release_source_digest(root)
    assert _valid_local_gate_receipt(
        receipt,
        root=root,
        expected_source_digest=digest,
        evidence_dir=evidence,
    )
    app_exec = evidence / "desktop-build/artifacts/JS Agent.app/Contents/MacOS/js-agent-desktop"
    app_exec.write_bytes(b"replacement")
    assert not _valid_local_gate_receipt(
        receipt,
        root=root,
        expected_source_digest=digest,
        evidence_dir=evidence,
    )


def test_desktop_receipt_fails_after_executable_permission_drift(tmp_path: Path) -> None:
    receipt, root, evidence = _bound_receipt(tmp_path, gate_name="desktop_build")
    digest = release_source_digest(root)
    assert _valid_local_gate_receipt(
        receipt,
        root=root,
        expected_source_digest=digest,
        evidence_dir=evidence,
    )
    app_exec = evidence / "desktop-build/artifacts/JS Agent.app/Contents/MacOS/js-agent-desktop"
    app_exec.chmod(0o600)

    assert not _valid_local_gate_receipt(
        receipt,
        root=root,
        expected_source_digest=digest,
        evidence_dir=evidence,
    )


def test_desktop_receipt_fails_after_zip_replacement(tmp_path: Path) -> None:
    receipt, root, evidence = _bound_receipt(tmp_path, gate_name="desktop_build")
    digest = release_source_digest(root)
    assert _valid_local_gate_receipt(
        receipt,
        root=root,
        expected_source_digest=digest,
        evidence_dir=evidence,
    )
    manifest = json.loads(
        (evidence / "desktop-build/manifest.json").read_text(encoding="utf-8")
    )
    zip_relative = manifest["artifacts"]["zip"]["path"]
    zip_path = evidence / "desktop-build" / zip_relative
    zip_path.write_bytes(zip_path.read_bytes() + b"forged-zip-suffix")

    assert not _valid_local_gate_receipt(
        receipt,
        root=root,
        expected_source_digest=digest,
        evidence_dir=evidence,
    )


def _mutate_formal_manifest_schema(payload: dict[str, object], _app: Path) -> None:
    payload["schema"] = "forged-schema"


def _mutate_formal_product_version(payload: dict[str, object], _app: Path) -> None:
    payload["product_version"] = "9.9.9"


def _mutate_formal_build_number(payload: dict[str, object], _app: Path) -> None:
    payload["build_number"] = "2026081102"


def _mutate_formal_plist_version(payload: dict[str, object], app: Path) -> None:
    from desktop.build_driver import _sha256_tree

    info_path = app / "Contents/Info.plist"
    info = plistlib.loads(info_path.read_bytes())
    info["CFBundleVersion"] = "2026081102"
    info_path.write_bytes(plistlib.dumps(info, fmt=plistlib.FMT_XML, sort_keys=True))
    artifacts = payload["artifacts"]
    assert isinstance(artifacts, dict)
    app_tree = artifacts["app_tree"]
    assert isinstance(app_tree, dict)
    app_tree["sha256"] = _sha256_tree(app)


@pytest.mark.parametrize(
    "mutation",
    [
        _mutate_formal_manifest_schema,
        _mutate_formal_product_version,
        _mutate_formal_build_number,
        _mutate_formal_plist_version,
    ],
    ids=["schema", "product-version", "build-number", "plist-version"],
)
def test_formal_desktop_receipt_rejects_self_consistent_invalid_manifest(
    tmp_path: Path,
    mutation: FormalMutation,
) -> None:
    receipt, root, evidence = _bound_receipt(
        tmp_path,
        gate_name="desktop_build",
        manifest_mutation=mutation,
    )

    assert not _valid_local_gate_receipt(
        receipt,
        root=root,
        expected_source_digest=release_source_digest(root),
        evidence_dir=evidence,
    )
