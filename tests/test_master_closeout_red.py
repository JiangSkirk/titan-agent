"""MASTER_CLOSEOUT official tests: seven attack rounds plus B1/B2 probes.

Synthetic fixtures only. Does not read ~/.js, Keychain, or chat.jsonl.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import stat
import time
from pathlib import Path
from typing import Any

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_round1_attachments_parse_out_of_process() -> None:
    attachments = (ROOT / "js/utils/attachments.py").read_text(encoding="utf-8")
    bounded = (ROOT / "js/security/bounded_parse.py").read_text(encoding="utf-8")
    worker = (ROOT / "js/security/parse_worker.py").read_text(encoding="utf-8")
    assert "PdfReader" not in attachments
    assert "read_excel" not in attachments
    assert "run_bounded_document_parse" in bounded
    assert "start_new_session=True" in bounded
    assert "js.security.parse_worker" in bounded
    assert "_extract_pdf" in worker
    assert "_extract_xlsx" in worker


def test_round1_work_pdf_uses_killable_worker() -> None:
    source = (ROOT / "js_work/documents.py").read_text(encoding="utf-8")
    assert "extract_work_pdf" in source or "run_bounded_document_parse" in source
    assert "PdfReader(str(source))" not in source


@pytest.mark.asyncio
async def test_round2_search_rejects_oversize_content_length() -> None:
    from js.security.bounded_http import ResponseBudgetError, read_bounded_response

    class _Resp:
        status_code = 200
        headers = httpx.Headers({"content-length": "999999999"})

        async def aiter_bytes(self) -> Any:
            yield b"x" * 64

    with pytest.raises(ResponseBudgetError, match="content-length"):
        await read_bounded_response(_Resp(), deadline_monotonic=time.monotonic() + 5)


@pytest.mark.asyncio
async def test_round2_search_caps_streamed_body() -> None:
    from js.security.bounded_http import (
        MAX_RESPONSE_BYTES,
        ResponseBudgetError,
        read_bounded_response,
    )

    class _Resp:
        status_code = 200
        headers = httpx.Headers({})

        async def aiter_bytes(self) -> Any:
            chunk = b"x" * 65_536
            sent = 0
            while sent <= MAX_RESPONSE_BYTES:
                yield chunk
                sent += len(chunk)

    with pytest.raises(ResponseBudgetError, match="byte budget"):
        await read_bounded_response(_Resp(), deadline_monotonic=time.monotonic() + 5)


def test_round2_search_json_depth_budget() -> None:
    from js.security.bounded_http import ResponseBudgetError, loads_bounded_json

    nested: Any = "leaf"
    for _ in range(16):
        nested = [nested]
    with pytest.raises(ResponseBudgetError, match="depth"):
        loads_bounded_json(json.dumps(nested).encode("utf-8"))


def _search_json_response(payload: bytes) -> Any:
    from js.security.bounded_http import BoundedResponse

    return BoundedResponse(
        status_code=200,
        headers=httpx.Headers({"content-type": "application/json"}),
        content=payload,
        elapsed_seconds=0.0,
    )


@pytest.mark.asyncio
async def test_round2_search_accepts_exactly_1048576_response_bytes() -> None:
    from js.security.bounded_http import read_bounded_response

    payload = b"x" * 1_048_576

    class _Resp:
        status_code = 200
        headers = httpx.Headers({"content-length": "1048576"})

        async def aiter_bytes(self) -> Any:
            yield payload

    result = await read_bounded_response(_Resp(), deadline_monotonic=time.monotonic() + 5)
    assert result.content == payload
    assert len(result.content) == 1_048_576


@pytest.mark.asyncio
async def test_round2_search_rejects_1048577_response_bytes() -> None:
    from js.security.bounded_http import ResponseBudgetError, read_bounded_response

    class _Resp:
        status_code = 200
        headers = httpx.Headers({})

        async def aiter_bytes(self) -> Any:
            yield b"x" * 1_048_577

    with pytest.raises(ResponseBudgetError, match="byte budget"):
        await read_bounded_response(_Resp(), deadline_monotonic=time.monotonic() + 5)


@pytest.mark.asyncio
async def test_round2_search_rejects_content_length_1048577_before_body() -> None:
    from js.security.bounded_http import ResponseBudgetError, read_bounded_response

    body_read = False

    class _Resp:
        status_code = 200
        headers = httpx.Headers({"content-length": "1048577"})

        async def aiter_bytes(self) -> Any:
            nonlocal body_read
            body_read = True
            yield b"x"

    with pytest.raises(ResponseBudgetError, match="content-length"):
        await read_bounded_response(_Resp(), deadline_monotonic=time.monotonic() + 5)
    assert body_read is False


@pytest.mark.asyncio
async def test_round2_search_rejects_stream_accumulated_to_1048577() -> None:
    from js.security.bounded_http import ResponseBudgetError, read_bounded_response

    class _Resp:
        status_code = 200
        headers = httpx.Headers({})

        async def aiter_bytes(self) -> Any:
            yield b"x" * 1_048_576
            yield b"x"

    with pytest.raises(ResponseBudgetError, match="byte budget"):
        await read_bounded_response(_Resp(), deadline_monotonic=time.monotonic() + 5)


def test_round2_search_json_array_256_accepted_257_rejected() -> None:
    from js.security.bounded_http import ResponseBudgetError

    accepted = _search_json_response(json.dumps([0] * 256).encode("utf-8")).json()
    assert accepted == [0] * 256
    with pytest.raises(ResponseBudgetError, match="array"):
        _search_json_response(json.dumps([0] * 257).encode("utf-8")).json()


def test_round2_search_json_object_256_accepted_257_rejected() -> None:
    from js.security.bounded_http import ResponseBudgetError

    legal = {f"k{i:03d}": 0 for i in range(256)}
    assert _search_json_response(json.dumps(legal).encode("utf-8")).json() == legal
    over = {f"k{i:03d}": 0 for i in range(257)}
    with pytest.raises(ResponseBudgetError, match="object"):
        _search_json_response(json.dumps(over).encode("utf-8")).json()


def test_round2_search_json_string_8192_accepted_8193_rejected() -> None:
    from js.security.bounded_http import ResponseBudgetError

    legal = "x" * 8_192
    assert _search_json_response(json.dumps(legal).encode("utf-8")).json() == legal
    with pytest.raises(ResponseBudgetError, match="string"):
        _search_json_response(json.dumps("x" * 8_193).encode("utf-8")).json()


def test_round2_search_json_rejects_over_1048576_bytes_with_legal_item_counts() -> None:
    from js.security.bounded_http import ResponseBudgetError

    obj = {f"k{i:03d}": ("v" * 5_500) for i in range(200)}
    assert len(obj) <= 256
    assert all(len(key) <= 8_192 for key in obj)
    assert all(len(value) <= 8_192 for value in obj.values())
    payload = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    assert len(payload) > 1_048_576
    with pytest.raises(ResponseBudgetError, match="byte budget"):
        _search_json_response(payload).json()


def test_round2_search_json_accepts_aggregate_under_1048576_bytes() -> None:
    obj = {f"k{i:03d}": ("v" * 100) for i in range(200)}
    payload = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    assert len(payload) <= 1_048_576
    assert len(obj) <= 256
    assert _search_json_response(payload).json() == obj


@pytest.mark.asyncio
async def test_round2_tavily_json_entry_rejects_8193_string(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from js.search.engines import TavilyEngine
    from js.security.bounded_http import BoundedResponse, ResponseBudgetError

    engine = TavilyEngine(api_key="synthetic-test-key")
    payload = json.dumps("x" * 8_193).encode("utf-8")

    async def fake_post(*_args: Any, **_kwargs: Any) -> BoundedResponse:
        return BoundedResponse(
            status_code=200,
            headers=httpx.Headers({}),
            content=payload,
            elapsed_seconds=0.0,
        )

    monkeypatch.setattr(engine._client, "post", fake_post)
    with pytest.raises(RuntimeError, match="Tavily search failed") as exc_info:
        await engine.search("q")
    assert isinstance(exc_info.value.__cause__, ResponseBudgetError)
    assert "string" in str(exc_info.value.__cause__)


def test_round2_search_client_streams_and_keeps_b2c_invariants() -> None:
    pinned = (ROOT / "js/search/engines.py").read_text(encoding="utf-8")
    block = pinned.split("class _PinnedSearchClient", 1)[1].split("class SearchEngine", 1)[0]
    assert "read_bounded_response" in block
    assert "follow_redirects=False" in block
    assert "follow_redirects=True" not in block
    assert block.index("authorize_network_egress") < block.index("resolve_and_validate")
    assert "client.stream(" in block or "stream(" in block


@pytest.mark.asyncio
async def test_round3_file_tools_reject_hardlink(tmp_path: Path) -> None:
    from js.config import ToolLimits
    from js.security.guard import SecurityDecisionType
    from js.tools.files import FileTools

    class _Allow:
        def check_path_operation(self, path: str, op: str) -> Any:
            return type("D", (), {"decision": SecurityDecisionType.ALLOW, "reason": ""})()

        def register_script_artifact(self, path: str) -> None:
            return None

    tools = FileTools(tmp_path, ToolLimits(), _Allow())  # type: ignore[arg-type]
    outside = tmp_path.parent / "master-closeout-secret.txt"
    outside.write_text("secret", encoding="utf-8")
    linked = tmp_path / "linked.txt"
    os.link(outside, linked)
    assert linked.stat().st_nlink == 2
    result = await tools.read("linked.txt")
    assert result.success is False
    assert result.error is not None
    write_result = await tools.write("linked.txt", "overwrite")
    assert write_result.success is False


@pytest.mark.asyncio
async def test_round3_office_csv_write_rejects_hardlink(tmp_path: Path) -> None:
    from js.config import ToolLimits
    from js.security.guard import SecurityDecisionType
    from js.tools.office import OfficeTools

    class _Allow:
        def check_path_operation(self, path: str, op: str) -> Any:
            return type("D", (), {"decision": SecurityDecisionType.ALLOW, "reason": ""})()

    tools = OfficeTools(tmp_path, ToolLimits(), _Allow())  # type: ignore[arg-type]
    target = tmp_path / "rows.csv"
    target.write_text("a,b\n", encoding="utf-8")
    outside = tmp_path.parent / "master-closeout-csv-secret.txt"
    outside.write_text("secret", encoding="utf-8")
    os.unlink(target)
    os.link(outside, target)
    result = await tools.csv_write("rows.csv", data='[["1","2"]]')
    assert result.success is False
    assert outside.read_text(encoding="utf-8") == "secret"


def test_round3_safe_output_rejects_hardlinked_stage(tmp_path: Path) -> None:
    from js_work.safe_output import create_staged

    target = tmp_path / "out.bin"
    staged = create_staged(target)
    metadata = os.lstat(staged)
    assert stat.S_ISREG(metadata.st_mode)
    assert metadata.st_nlink == 1
    source = (ROOT / "js_work/safe_output.py").read_text(encoding="utf-8")
    assert "st_nlink" in source
    assert "must not be hardlinked" in source or "nlink" in source.lower()


def test_round4_sandbox_monitors_process_tree() -> None:
    from js.echo.os_sandbox import MAX_SANDBOX_PIDS, _tree_rss_and_pids

    source = (ROOT / "js/echo/os_sandbox.py").read_text(encoding="utf-8")
    assert "_tree_rss_and_pids" in source
    assert "children(recursive=True)" in source
    assert "MAX_SANDBOX_PIDS" in source
    assert MAX_SANDBOX_PIDS <= 16
    rss, pids = _tree_rss_and_pids(os.getpid())
    assert pids >= 1
    assert rss >= 0.0


def test_round5_hermes_does_not_import_host_skills_guard() -> None:
    from js.skills.hermes_bridge import _try_hermes_guard_scan

    source = (ROOT / "js/skills/hermes_bridge.py").read_text(encoding="utf-8")
    assert "sys.path.insert" not in source
    assert "from skills_guard import scan_skill" not in source
    assert _try_hermes_guard_scan(ROOT) is None


def test_round5_community_code_skill_is_dangerous(tmp_path: Path) -> None:
    from js.skills.manager import SkillManager
    from js.skills.spec import SkillSpec, SkillType, TrustLevel
    from js.tools.registry import ToolSpec

    manager = SkillManager(tmp_path / "state", tmp_path / "workspace")
    spec = SkillSpec(
        id="community-code",
        name="community-code",
        type=SkillType.CODE,
        trust_level=TrustLevel.COMMUNITY,
        path=tmp_path,
    )
    tool_spec, _handler = manager._tool_registration(spec, object(), 1)
    assert isinstance(tool_spec, ToolSpec)
    assert tool_spec.dangerous is True
    prompt = SkillSpec(
        id="community-prompt",
        name="community-prompt",
        type=SkillType.PROMPT,
        trust_level=TrustLevel.COMMUNITY,
        path=tmp_path,
    )
    prompt_spec, _ = manager._tool_registration(prompt, object(), 1)
    assert prompt_spec.dangerous is False
    executor = (ROOT / "js/skills/executor.py").read_text(encoding="utf-8")
    assert "workspace_writable" in executor
    sandbox = (ROOT / "js/echo/os_sandbox.py").read_text(encoding="utf-8")
    assert "workspace_writable" in sandbox


def test_round6_capabilities_hide_work_handle_without_role() -> None:
    source = (ROOT / "js/appshell/routers.py").read_text(encoding="utf-8")
    assert "work" in source
    assert "work_workspace_handle" in source
    assert 'if "work" in principal.mode_roles' in source or "work not in principal.mode_roles" in source


def test_round6_cleartext_bind_rejects_non_loopback() -> None:
    from js.security.loopback_bind import CleartextBindError, require_literal_loopback_bind

    assert require_literal_loopback_bind("127.0.0.1") == "127.0.0.1"
    assert require_literal_loopback_bind("::1") == "::1"
    with pytest.raises(CleartextBindError):
        require_literal_loopback_bind("0.0.0.0")
    with pytest.raises(CleartextBindError):
        require_literal_loopback_bind("localhost")
    cli = (ROOT / "js/ui/cli.py").read_text(encoding="utf-8")
    launcher = (ROOT / "js/appshell/launcher.py").read_text(encoding="utf-8")
    work_cli = (ROOT / "js_work/cli.py").read_text(encoding="utf-8")
    work_web = (ROOT / "js_work/web.py").read_text(encoding="utf-8")
    for source in (cli, launcher, work_cli, work_web):
        assert "require_literal_loopback_bind" in source
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    readme_en = (ROOT / "README_en.md").read_text(encoding="utf-8")
    assert "js web --host 0.0.0.0" not in readme
    assert "js web --host 0.0.0.0" not in readme_en
    assert "-b 0.0.0.0:8000" not in readme
    assert "-b 0.0.0.0:8000" not in readme_en


def test_round6_echo_entrypoints_cover_cron_pipeline_mcp() -> None:
    source = (ROOT / "tests/echo/test_all_entrypoints_use_echo_runtime.py").read_text(
        encoding="utf-8"
    )
    assert "js" in source and "cron" in source
    assert "pipeline" in source
    assert "mcp" in source


def test_round7_schema_backfill_does_not_swallow() -> None:
    source = (ROOT / "js/memory/enhanced_store.py").read_text(encoding="utf-8")
    marker = "PRAGMA user_version"
    assert marker in source
    start = source.index("# One-time backfill")
    end = source.index("CREATE TABLE IF NOT EXISTS memory_audit_log", start)
    block = source[start:end]
    assert "except Exception:\n                    pass" not in block
    assert "rollback" in block


def test_round7_git_bound_digest_and_ci_and_installer() -> None:
    gates = (ROOT / "js/echo/ledger/release_gates.py").read_text(encoding="utf-8")
    assert "def require_git_bound_release_digest" in gates
    desktop_gate = (ROOT / "scripts/run_desktop_build_gate.py").read_text(encoding="utf-8")
    assert "require_git_bound_release_digest" in desktop_gate
    ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "permissions:" in ci
    assert "contents: read" in ci
    assert "actions/checkout@v4" not in ci
    assert "actions/setup-python@v5" not in ci
    assert re.search(r"actions/checkout@[0-9a-f]{40}", ci)
    assert re.search(r"actions/setup-python@[0-9a-f]{40}", ci)
    install = (ROOT / "scripts/install.sh").read_text(encoding="utf-8")
    assert "com.jsagent.app" not in install
    assert "com.titan.js-agent.source-legacy" in install
    assert "JS Agent Source.app" in install
    macos = (ROOT / "scripts/macos_start.sh").read_text(encoding="utf-8")
    assert "uv sync --frozen --offline" in macos
    assert "pip install" not in macos
    assert "0.0.0.0" not in macos
    deploy = (ROOT / "scripts/deploy.sh").read_text(encoding="utf-8")
    assert "0.0.0.0" not in deploy
    sbom = (ROOT / "scripts/generate_release_evidence.py").read_text(encoding="utf-8")
    assert "Cargo.lock" in sbom
    assert "pnpm-lock.yaml" in sbom
    driver = (ROOT / "desktop/build_driver.py").read_text(encoding="utf-8")
    assert "def require_production_signing_identity" in driver
    assert "python_executable is None" in driver


def test_round7_python_runtime_requires_explicit_executable(tmp_path: Path) -> None:
    from desktop.build_driver import (
        require_production_signing_identity,
        verify_desktop_python_runtime,
    )

    with pytest.raises(RuntimeError, match="explicit|isolated|signing"):
        verify_desktop_python_runtime(tmp_path / "uv.lock")
    with pytest.raises(RuntimeError, match="signing identity"):
        require_production_signing_identity(production_release=True)


def test_b1b2_regression_probes_keep_closed_findings() -> None:
    egress = (ROOT / "js/security/egress.py").read_text(encoding="utf-8")
    assert "attempt_id" in egress
    assert "payload_digest" in egress
    net_guard = (ROOT / "js/security/net_guard.py").read_text(encoding="utf-8")
    assert "PinnedTransport" in net_guard
    approvals = (ROOT / "js/security/approvals.py").read_text(encoding="utf-8")
    assert "cas" in approvals.lower() or "exactly" in approvals.lower() or "compare" in approvals
    providers = (ROOT / "js/models/providers.py").read_text(encoding="utf-8")
    assert "scrub" in providers.lower() or "redact" in providers.lower()


@pytest.mark.asyncio
async def test_round2_deadline_kills_slow_body() -> None:
    from js.security.bounded_http import ResponseBudgetError, read_bounded_response

    class _Resp:
        status_code = 200
        headers = httpx.Headers({})

        async def aiter_bytes(self) -> Any:
            await asyncio.sleep(0.2)
            yield b"late"

    with pytest.raises(ResponseBudgetError, match="deadline"):
        await read_bounded_response(_Resp(), deadline_monotonic=time.monotonic() + 0.01)
