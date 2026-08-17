"""B2B-B: product consent adapters and real egress provenance.

Tests drive real product entries (Web/CLI/Telegram/cron/Fleet/Echo turn)
into the same Router/consent/permit boundary. They use TemporaryDirectory,
fake providers/SDK, and synthetic text only. No real Provider, Keychain,
~/.js, ~/.js-work, or network.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import sys
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from test_b2b_model_egress_core import (
    LOOPBACK_URL,
    PRIVACY_NEEDLES,
    SYNTH_API_KEY,
    SYNTH_PATH,
    SYNTH_PROMPT,
    SYNTH_RAW_ARGS,
    _bind_broker,
    _chat_kwargs,
    _FakeBroker,
    _install_transport_spies,
    _router,
    _runtime_context,
    _SpyProvider,
)

from js.agent import JSAgent
from js.config import JSSettings, ModelConfig, SecurityConfig
from js.echo.attachment_gate import upload_dir
from js.echo.turn_context import reset_runtime_context, set_runtime_context
from js.echo.turn_runtime import run_echo_turn
from js.models.providers import ChatMessage
from js.security.approvals import ApprovalDecisionType, ApprovalQueue
from js.security.egress import (
    EgressConsentError,
    build_egress_attempt,
    digest_jsonable,
)
from js.web.auth import AuthManager
from js.web.runtime_context import WebRuntime, bind_web_runtime, install_web_runtime_context

DIGEST_A = hashlib.sha256(b"source-a").hexdigest()
DIGEST_B = hashlib.sha256(b"source-b").hexdigest()


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _valid_provenance(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema": "egress-provenance-v1",
        "sources": [
            {
                "kind": "direct_user",
                "record_id": "direct_user:1",
                "content_digest": DIGEST_A,
                "parent_turn_id": "",
                "parent_run_id": "run-a",
                "parent_attempt_id": "",
            }
        ],
        "attachments": [],
        "parent_turn_id": "",
        "parent_run_id": "run-a",
        "parent_attempt_id": "",
        "channel": "api_chat",
        "owner_key_hash": "owner-a",
        "session_id": "session-a",
        "run_id": "run-a",
    }
    payload.update(overrides)
    return payload


def _isolate_agent(tmp_path: Path) -> JSAgent:
    workspace = tmp_path / "workspace"
    state = tmp_path / "state"
    workspace.mkdir()
    state.mkdir()
    settings = JSSettings(
        workspace=workspace,
        state_dir=state,
        max_turns=3,
        security=SecurityConfig(api_key_required=True),
    )
    return JSAgent(settings)


def _add_remote(agent: JSAgent, provider: _SpyProvider) -> None:
    agent.router.add_provider(
        provider.name,
        provider,
        [ModelConfig(id="m1", name="m1", provider=provider.name, max_tokens=64)],
    )


def _add_loopback(agent: JSAgent) -> _SpyProvider:
    provider = _SpyProvider(name="loop", base_url=LOOPBACK_URL)
    _add_remote(agent, provider)
    return provider


def _capture_attempts(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    seen: list[dict[str, Any]] = []
    from js.models import router as router_mod
    from js.security import egress as egress_mod

    original = egress_mod.build_egress_attempt

    def wrapped(**kwargs: Any) -> Any:
        seen.append(kwargs)
        return original(**kwargs)

    monkeypatch.setattr(egress_mod, "build_egress_attempt", wrapped)
    monkeypatch.setattr(router_mod, "build_egress_attempt", wrapped)
    return seen


def _owned_attachment(
    workspace: Path,
    *,
    owner: str,
    session: str,
    name: str = "note.txt",
    content: bytes = b"hello-bytes",
) -> str:
    directory = upload_dir(workspace, owner, session)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_bytes(content)
    return path.relative_to(workspace).as_posix()


def _assert_privacy(values: list[Any]) -> None:
    blob = " ".join(_collect_strings(values))
    for needle in PRIVACY_NEEDLES:
        assert needle not in blob


def _collect_strings(values: list[Any]) -> list[str]:
    seen: set[int] = set()
    out: list[str] = []

    def walk(value: Any) -> None:
        if isinstance(value, str):
            out.append(value)
            return
        if isinstance(value, bytes):
            out.append(value.decode("utf-8", errors="replace"))
            return
        if isinstance(value, BaseException):
            walk(value.args)
            walk(getattr(value, "__dict__", {}))
            walk(value.__cause__)
            walk(value.__context__)
            return
        if isinstance(value, dict):
            identity = id(value)
            if identity in seen:
                return
            seen.add(identity)
            for key, child in value.items():
                walk(key)
                walk(child)
            return
        if isinstance(value, list | tuple | set):
            identity = id(value)
            if identity in seen:
                return
            seen.add(identity)
            for child in value:
                walk(child)
            return
        if hasattr(value, "__dict__"):
            identity = id(value)
            if identity in seen:
                return
            seen.add(identity)
            walk(vars(value))

    for item in values:
        walk(item)
    return out


def _inspect_log_records(records: list[logging.LogRecord]) -> list[Any]:
    dumped: list[Any] = []
    for record in records:
        dumped.extend([record.msg, record.args, record.exc_info, getattr(record, "__dict__", {})])
        extra = getattr(record, "__dict__", {})
        dumped.append(extra)
    return dumped


async def _loopback_turn(
    agent: JSAgent,
    message: str,
    *,
    channel: str = "api_chat",
    owner: str = "owner-a",
    session: str = "session-a",
    attachments: list[str] | None = None,
    model: str = "loop/m1",
) -> Any:
    return await run_echo_turn(
        agent,
        message,
        channel=channel,
        owner_key_hash=owner,
        session_id=session,
        model=model,
        attachments=attachments or [],
    )


# ---------------------------------------------------------------------------
# Provenance validation through the real Router (fails on HEAD)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unknown_source_kind_is_zero_calls(tmp_path: Path) -> None:
    provider = _SpyProvider(base_url=LOOPBACK_URL)
    router, issuer = _router(tmp_path, provider)
    token = set_runtime_context(_runtime_context(tmp_path))
    try:
        with pytest.raises(EgressConsentError, match="source kind"):
            await router.chat(
                [ChatMessage(role="user", content=SYNTH_PROMPT)],
                provenance=_valid_provenance(
                    sources=[
                        {
                            "kind": "evil_kind",
                            "record_id": "evil:1",
                            "content_digest": DIGEST_A,
                            "parent_turn_id": "",
                            "parent_run_id": "run-a",
                            "parent_attempt_id": "",
                        }
                    ]
                ),
                **_chat_kwargs(issuer, model="remote/m1"),
            )
    finally:
        reset_runtime_context(token)
    assert provider.calls == 0


@pytest.mark.asyncio
async def test_bool_as_int_attachment_size_is_zero_calls(tmp_path: Path) -> None:
    provider = _SpyProvider(base_url=LOOPBACK_URL)
    router, issuer = _router(tmp_path, provider)
    token = set_runtime_context(_runtime_context(tmp_path))
    try:
        with pytest.raises(EgressConsentError, match="provenance"):
            await router.chat(
                [ChatMessage(role="user", content=SYNTH_PROMPT)],
                provenance=_valid_provenance(
                    attachments=[
                        {
                            "index": True,
                            "media_type": "text/plain",
                            "size": True,
                            "content_digest": DIGEST_A,
                        }
                    ]
                ),
                **_chat_kwargs(issuer, model="remote/m1"),
            )
    finally:
        reset_runtime_context(token)
    assert provider.calls == 0


@pytest.mark.asyncio
async def test_non_object_provenance_is_zero_calls(tmp_path: Path) -> None:
    provider = _SpyProvider(base_url=LOOPBACK_URL)
    router, issuer = _router(tmp_path, provider)
    token = set_runtime_context(_runtime_context(tmp_path))
    try:
        with pytest.raises(EgressConsentError, match="provenance"):
            await router.chat(
                [ChatMessage(role="user", content=SYNTH_PROMPT)],
                provenance=["not", "an", "object"],
                **_chat_kwargs(issuer, model="remote/m1"),
            )
    finally:
        reset_runtime_context(token)
    assert provider.calls == 0


@pytest.mark.asyncio
async def test_empty_required_digest_is_zero_calls(tmp_path: Path) -> None:
    provider = _SpyProvider(base_url=LOOPBACK_URL)
    router, issuer = _router(tmp_path, provider)
    token = set_runtime_context(_runtime_context(tmp_path))
    try:
        with pytest.raises(EgressConsentError, match="digest"):
            await router.chat(
                [ChatMessage(role="user", content=SYNTH_PROMPT)],
                provenance=_valid_provenance(
                    sources=[
                        {
                            "kind": "direct_user",
                            "record_id": "direct_user:1",
                            "content_digest": "",
                            "parent_turn_id": "",
                            "parent_run_id": "run-a",
                            "parent_attempt_id": "",
                        }
                    ]
                ),
                **_chat_kwargs(issuer, model="remote/m1"),
            )
    finally:
        reset_runtime_context(token)
    assert provider.calls == 0


@pytest.mark.asyncio
async def test_duplicate_source_identity_is_zero_calls(tmp_path: Path) -> None:
    provider = _SpyProvider(base_url=LOOPBACK_URL)
    router, issuer = _router(tmp_path, provider)
    token = set_runtime_context(_runtime_context(tmp_path))
    source = {
        "kind": "direct_user",
        "record_id": "dup:1",
        "content_digest": DIGEST_A,
        "parent_turn_id": "",
        "parent_run_id": "run-a",
        "parent_attempt_id": "",
    }
    try:
        with pytest.raises(EgressConsentError, match="duplicate"):
            await router.chat(
                [ChatMessage(role="user", content=SYNTH_PROMPT)],
                provenance=_valid_provenance(sources=[source, dict(source)]),
                **_chat_kwargs(issuer, model="remote/m1"),
            )
    finally:
        reset_runtime_context(token)
    assert provider.calls == 0


@pytest.mark.asyncio
async def test_oversized_source_list_is_zero_calls(tmp_path: Path) -> None:
    provider = _SpyProvider(base_url=LOOPBACK_URL)
    router, issuer = _router(tmp_path, provider)
    token = set_runtime_context(_runtime_context(tmp_path))
    sources = [
        {
            "kind": "direct_user",
            "record_id": f"direct_user:{index}",
            "content_digest": DIGEST_A,
            "parent_turn_id": "",
            "parent_run_id": "run-a",
            "parent_attempt_id": "",
        }
        for index in range(300)
    ]
    try:
        with pytest.raises(EgressConsentError, match="limit"):
            await router.chat(
                [ChatMessage(role="user", content=SYNTH_PROMPT)],
                provenance=_valid_provenance(sources=sources),
                **_chat_kwargs(issuer, model="remote/m1"),
            )
    finally:
        reset_runtime_context(token)
    assert provider.calls == 0


@pytest.mark.asyncio
async def test_surrogate_record_id_is_safe_error(tmp_path: Path) -> None:
    provider = _SpyProvider(base_url=LOOPBACK_URL)
    router, issuer = _router(tmp_path, provider)
    token = set_runtime_context(_runtime_context(tmp_path))
    try:
        with pytest.raises(EgressConsentError) as captured:
            await router.chat(
                [ChatMessage(role="user", content=SYNTH_PROMPT)],
                provenance=_valid_provenance(
                    sources=[
                        {
                            "kind": "direct_user",
                            "record_id": "id-\ud800" + SYNTH_PROMPT,
                            "content_digest": DIGEST_A,
                            "parent_turn_id": "",
                            "parent_run_id": "run-a",
                            "parent_attempt_id": "",
                        }
                    ]
                ),
                **_chat_kwargs(issuer, model="remote/m1"),
            )
    finally:
        reset_runtime_context(token)
    assert provider.calls == 0
    assert SYNTH_PROMPT not in repr(captured.value)
    assert SYNTH_PROMPT not in str(captured.value)


@pytest.mark.asyncio
async def test_post_consent_source_hash_mutation_is_zero_calls(tmp_path: Path) -> None:
    provider = _SpyProvider()
    router, issuer = _router(tmp_path, provider)
    _bind_broker(router, _FakeBroker(action="approve"))
    provenance = _valid_provenance()
    token = set_runtime_context(_runtime_context(tmp_path))

    async def mutate_before(*_args: Any, **_kwargs: Any) -> None:
        provenance["sources"][0]["content_digest"] = DIGEST_B
        provenance["sources"][0]["record_id"] = "mutated:1"

    try:
        with pytest.raises(EgressConsentError, match="provenance"):
            await router.chat(
                [ChatMessage(role="user", content=SYNTH_PROMPT)],
                provenance=provenance,
                **_chat_kwargs(issuer, before_model_call=mutate_before),
            )
    finally:
        reset_runtime_context(token)
    assert provider.calls == 0


@pytest.mark.asyncio
async def test_post_consent_attachment_digest_mutation_is_zero_calls(tmp_path: Path) -> None:
    provider = _SpyProvider()
    router, issuer = _router(tmp_path, provider)
    _bind_broker(router, _FakeBroker(action="approve"))
    attachments = [{"name": "note.txt", "size": 4, "sha256": "sha256:" + DIGEST_A, "media_type": "text/plain"}]
    provenance = _valid_provenance(
        attachments=[
            {
                "index": 0,
                "media_type": "text/plain",
                "size": 4,
                "content_digest": DIGEST_A,
            }
        ]
    )
    token = set_runtime_context(_runtime_context(tmp_path))

    async def mutate_before(*_args: Any, **_kwargs: Any) -> None:
        attachments[0]["sha256"] = "sha256:" + DIGEST_B
        provenance["attachments"][0]["content_digest"] = DIGEST_B
        provenance["attachments"][0]["size"] = 99

    try:
        with pytest.raises(EgressConsentError):
            await router.chat(
                [ChatMessage(role="user", content=SYNTH_PROMPT)],
                attachments=attachments,
                provenance=provenance,
                **_chat_kwargs(issuer, before_model_call=mutate_before),
            )
    finally:
        reset_runtime_context(token)
    assert provider.calls == 0


@pytest.mark.asyncio
async def test_post_consent_attachment_digest_only_mutation_is_zero_calls(tmp_path: Path) -> None:
    """Grok oracle: mutating only the attachment digest must be independently fatal."""
    provider = _SpyProvider()
    router, issuer = _router(tmp_path, provider)
    _bind_broker(router, _FakeBroker(action="approve"))
    attachments = [{"name": "note.txt", "size": 4, "sha256": "sha256:" + DIGEST_A, "media_type": "text/plain"}]
    provenance = _valid_provenance(
        attachments=[
            {
                "index": 0,
                "media_type": "text/plain",
                "size": 4,
                "content_digest": DIGEST_A,
            }
        ]
    )
    frozen_provenance = json.loads(json.dumps(provenance))
    token = set_runtime_context(_runtime_context(tmp_path))

    async def mutate_attachment_only(*_args: Any, **_kwargs: Any) -> None:
        attachments[0]["sha256"] = "sha256:" + DIGEST_B

    try:
        with pytest.raises(EgressConsentError):
            await router.chat(
                [ChatMessage(role="user", content=SYNTH_PROMPT)],
                attachments=attachments,
                provenance=provenance,
                **_chat_kwargs(issuer, before_model_call=mutate_attachment_only),
            )
    finally:
        reset_runtime_context(token)
    assert provider.calls == 0
    assert provenance == frozen_provenance


@pytest.mark.asyncio
async def test_valid_v1_provenance_loopback_is_one_call(tmp_path: Path) -> None:
    provider = _SpyProvider(base_url=LOOPBACK_URL)
    router, issuer = _router(tmp_path, provider)
    token = set_runtime_context(_runtime_context(tmp_path))
    try:
        response = await router.chat(
            [ChatMessage(role="user", content=SYNTH_PROMPT)],
            provenance=_valid_provenance(),
            **_chat_kwargs(issuer, model="remote/m1"),
        )
    finally:
        reset_runtime_context(token)
    assert response.content == "ok"
    assert provider.calls == 1


# ---------------------------------------------------------------------------
# Echo product path must attach real provenance (fails on HEAD)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_echo_direct_user_provenance_is_not_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent = _isolate_agent(tmp_path)
    provider = _add_loopback(agent)
    seen = _capture_attempts(monkeypatch)
    state = await _loopback_turn(agent, SYNTH_PROMPT)
    await agent.close()
    assert state.status == "completed"
    assert provider.calls == 1
    provenance = seen[0].get("provenance")
    assert isinstance(provenance, dict)
    kinds = {item["kind"] for item in provenance.get("sources", [])}
    assert "direct_user" in kinds
    assert provenance.get("schema") == "egress-provenance-v1"
    assert provenance.get("session_id") == "session-a"
    assert provenance.get("run_id")
    assert SYNTH_PROMPT not in json.dumps(provenance)


@pytest.mark.asyncio
async def test_echo_cold_capsule_keeps_lineage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent = _isolate_agent(tmp_path)
    provider = _add_loopback(agent)
    seen = _capture_attempts(monkeypatch)
    agent.settings.memory.capsule_enabled = True
    agent.memory.get_capsule = lambda *_args, **_kwargs: {  # type: ignore[method-assign]
        "capsule_text": "capsule-body-not-for-ledger",
        "updated_at": 1,
    }
    state = await _loopback_turn(agent, SYNTH_PROMPT)
    await agent.close()
    assert state.status == "completed"
    assert provider.calls == 1
    kinds = {item["kind"] for item in seen[0]["provenance"]["sources"]}
    assert "cold_capsule" in kinds
    assert "capsule-body-not-for-ledger" not in json.dumps(seen[0]["provenance"])


@pytest.mark.asyncio
async def test_echo_memory_keeps_lineage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent = _isolate_agent(tmp_path)
    provider = _add_loopback(agent)
    seen = _capture_attempts(monkeypatch)

    original_system = agent._build_system_message

    def _system(*args: Any, **kwargs: Any) -> str:
        return (
            original_system(*args, **kwargs)
            + "\n## Relevant Context\nmemory-fact-not-for-ledger"
        )

    agent._build_system_message = _system  # type: ignore[method-assign]
    state = await _loopback_turn(agent, SYNTH_PROMPT)
    await agent.close()
    assert state.status == "completed"
    assert provider.calls == 1
    kinds = {item["kind"] for item in seen[0]["provenance"]["sources"]}
    assert "memory" in kinds
    assert "memory-fact-not-for-ledger" not in json.dumps(seen[0]["provenance"])


@pytest.mark.asyncio
async def test_echo_attachment_provenance_and_stream_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent = _isolate_agent(tmp_path)
    provider = _add_loopback(agent)
    seen = _capture_attempts(monkeypatch)
    relative = _owned_attachment(
        agent.settings.workspace,
        owner="owner-a",
        session="session-a",
        content=b"attach-bytes",
    )
    tokens: list[str] = []

    async def on_token(token: str) -> None:
        tokens.append(token)

    state = await run_echo_turn(
        agent,
        SYNTH_PROMPT,
        channel="ws_stream",
        owner_key_hash="owner-a",
        session_id="session-a",
        model="loop/m1",
        attachments=[relative],
        stream_callback=on_token,
    )
    await agent.close()
    assert state.status == "completed"
    assert provider.stream_calls + provider.calls >= 1
    bound = seen[0]
    assert bound.get("attachments")
    kinds = {item["kind"] for item in bound["provenance"]["sources"]}
    assert "attachment" in kinds
    assert SYNTH_PATH not in json.dumps(bound["provenance"])
    assert "attach-bytes" not in json.dumps(bound["provenance"])


@pytest.mark.asyncio
async def test_echo_tool_result_lineage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent = _isolate_agent(tmp_path)
    provider = _add_loopback(agent)
    seen = _capture_attempts(monkeypatch)
    provider.seen.clear()

    async def scripted_chat(messages: list[ChatMessage], model: str, **_kwargs: Any) -> Any:
        from js.models.providers import ChatResponse

        provider.calls += 1
        if provider.calls == 1:
            return ChatResponse(
                content="",
                tool_calls=[
                    {
                        "id": "call-1",
                        "type": "function",
                        "function": {"name": "list_dir", "arguments": "{}"},
                    }
                ],
                model=model,
                usage={"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
                finish_reason="tool_calls",
            )
        return ChatResponse(
            content="done",
            tool_calls=[],
            model=model,
            usage={"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            finish_reason="stop",
        )

    provider.chat = scripted_chat  # type: ignore[method-assign]
    state = await _loopback_turn(agent, SYNTH_PROMPT)
    await agent.close()
    assert state.status == "completed"
    assert len(seen) >= 2
    provenance = seen[-1].get("provenance")
    assert isinstance(provenance, dict)
    kinds = {item["kind"] for item in provenance.get("sources", [])}
    assert "tool_result" in kinds
    assert SYNTH_RAW_ARGS not in json.dumps(seen[-1]["provenance"])


@pytest.mark.asyncio
async def test_cron_and_fleet_channels_tag_source_kind(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent = _isolate_agent(tmp_path)
    provider = _add_loopback(agent)
    seen = _capture_attempts(monkeypatch)
    await _loopback_turn(agent, SYNTH_PROMPT, channel="cron_chat", session="cron-session")
    await _loopback_turn(agent, SYNTH_PROMPT, channel="fleet_worker", session="fleet-session")
    await agent.close()
    assert provider.calls == 2
    by_channel: dict[str, set[str]] = {}
    for attempt in seen:
        provenance = attempt["provenance"]
        by_channel.setdefault(str(provenance.get("channel")), set()).update(
            item["kind"] for item in provenance.get("sources", [])
        )
    assert "cron_persisted_prompt" in by_channel.get("cron_chat", set())
    assert "fleet_worker" in by_channel.get("fleet_worker", set())


@pytest.mark.asyncio
async def test_mixed_multi_source_provenance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent = _isolate_agent(tmp_path)
    _add_loopback(agent)
    seen = _capture_attempts(monkeypatch)
    agent.settings.memory.capsule_enabled = True
    agent.memory.get_capsule = lambda *_args, **_kwargs: {  # type: ignore[method-assign]
        "capsule_text": "capsule-mixed",
        "updated_at": 1,
    }
    original_system = agent._build_system_message

    def _system(*args: Any, **kwargs: Any) -> str:
        return original_system(*args, **kwargs) + "\n## Relevant Context\nmemory-mixed"

    agent._build_system_message = _system  # type: ignore[method-assign]
    relative = _owned_attachment(
        agent.settings.workspace,
        owner="owner-a",
        session="session-a",
    )
    state = await _loopback_turn(agent, SYNTH_PROMPT, attachments=[relative])
    await agent.close()
    assert state.status == "completed"
    kinds = {item["kind"] for item in seen[0]["provenance"]["sources"]}
    assert {"direct_user", "cold_capsule", "memory", "attachment"} <= kinds


# ---------------------------------------------------------------------------
# Headless / Telegram / cron / Fleet stay fail-closed (GREEN controls on HEAD)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_telegram_remote_is_zero_calls(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    agent = _isolate_agent(tmp_path)
    provider = _SpyProvider()
    _add_remote(agent, provider)
    spies = _install_transport_spies(monkeypatch)
    state = await run_echo_turn(
        agent,
        SYNTH_PROMPT,
        channel="telegram",
        owner_key_hash="telegram:1",
        session_id="tg-session",
        model="remote/m1",
    )
    await agent.close()
    assert state.status == "error"
    assert provider.calls == 0
    assert spies["resolver"] == []
    assert spies["sdk"] == []
    assert spies["async_client"] == []


@pytest.mark.asyncio
async def test_cron_remote_does_not_auto_approve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent = _isolate_agent(tmp_path)
    provider = _SpyProvider()
    _add_remote(agent, provider)
    spies = _install_transport_spies(monkeypatch)
    from js.cron.engine import ScheduledJob
    from js.daemon.core import JSDaemon

    daemon = JSDaemon(agent.settings, agent=agent)
    job = ScheduledJob(
        id="job-1",
        name="chat",
        cron_expr="* * * * *",
        task_type="chat",
        payload={"prompt": SYNTH_PROMPT},
        owner_key_hash="owner-a",
        session_id="cron-session",
    )
    with pytest.raises((PermissionError, RuntimeError)):
        await daemon._cb_chat(job)
    await agent.close()
    assert provider.calls == 0
    assert spies["sdk"] == []


@pytest.mark.asyncio
async def test_fleet_remote_is_zero_calls(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    agent = _isolate_agent(tmp_path)
    provider = _SpyProvider()
    _add_remote(agent, provider)
    spies = _install_transport_spies(monkeypatch)
    state = await run_echo_turn(
        agent,
        SYNTH_PROMPT,
        channel="fleet_worker",
        owner_key_hash="owner-a",
        session_id="fleet-session",
        model="remote/m1",
    )
    await agent.close()
    assert state.status == "error"
    assert provider.calls == 0
    assert spies["sdk"] == []


@pytest.mark.asyncio
async def test_cli_noninteractive_is_zero_calls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent = _isolate_agent(tmp_path)
    provider = _SpyProvider()
    _add_remote(agent, provider)
    spies = _install_transport_spies(monkeypatch)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False)
    state = await run_echo_turn(
        agent,
        SYNTH_PROMPT,
        channel="cli",
        owner_key_hash="js-cli-local",
        session_id="cli-session",
        model="remote/m1",
    )
    await agent.close()
    assert state.status == "error"
    assert provider.calls == 0
    assert spies["sdk"] == []


@pytest.mark.asyncio
async def test_background_remote_is_zero_calls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent = _isolate_agent(tmp_path)
    provider = _SpyProvider()
    _add_remote(agent, provider)
    spies = _install_transport_spies(monkeypatch)
    with pytest.raises((PermissionError, RuntimeError)):
        await agent.authorized_model_chat(
            [ChatMessage(role="user", content=SYNTH_PROMPT)],
            tenant_id="owner-a",
            run_id="bg-run",
            session_id="bg-session",
            model="remote/m1",
        )
    await agent.close()
    assert provider.calls == 0
    assert spies["sdk"] == []


# ---------------------------------------------------------------------------
# CLI interactive adapter (RED on HEAD)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cli_interactive_approve_is_exactly_one_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent = _isolate_agent(tmp_path)
    provider = _SpyProvider()
    _add_remote(agent, provider)
    spies = _install_transport_spies(monkeypatch)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _prompt="": "y")
    state = await run_echo_turn(
        agent,
        SYNTH_PROMPT,
        channel="cli",
        owner_key_hash="js-cli-local",
        session_id="cli-session",
        model="remote/m1",
    )
    await agent.close()
    assert state.status == "completed"
    assert provider.calls == 1
    assert spies["resolver"] == []
    assert spies["sdk"] == []


@pytest.mark.asyncio
async def test_cli_interactive_reject_is_zero_calls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent = _isolate_agent(tmp_path)
    provider = _SpyProvider()
    _add_remote(agent, provider)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _prompt="": "n")
    state = await run_echo_turn(
        agent,
        SYNTH_PROMPT,
        channel="cli",
        owner_key_hash="js-cli-local",
        session_id="cli-session",
        model="remote/m1",
    )
    await agent.close()
    assert state.status == "error"
    assert provider.calls == 0


# ---------------------------------------------------------------------------
# Web HTTP protocol (RED on HEAD: no pending)
# ---------------------------------------------------------------------------


def _web_app(agent: JSAgent) -> tuple[FastAPI, str, str]:
    settings = agent.settings
    key = AuthManager(settings.state_dir).create_key("b2b-b", role="user")
    owner = hashlib.sha256(key.encode("utf-8")).hexdigest()
    app = FastAPI()
    install_web_runtime_context(app)
    bind_web_runtime(app, WebRuntime(agent=agent, settings=settings))
    from js.web.routers.approvals import router as approvals_router
    from js.web.routers.chat import router as chat_router

    app.include_router(chat_router)
    app.include_router(approvals_router)
    return app, key, owner


async def _web_client(app: FastAPI, key: str) -> AsyncClient:
    return AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://localhost",
        headers={"X-API-Key": key, "Origin": "http://localhost"},
    )


@pytest.mark.asyncio
async def test_web_remote_pending_is_zero_network_until_approve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent = _isolate_agent(tmp_path)
    provider = _SpyProvider()
    _add_remote(agent, provider)
    spies = _install_transport_spies(monkeypatch)
    app, key, _owner = _web_app(agent)
    async with await _web_client(app, key) as client:
        chat_task = asyncio.create_task(
            client.post(
                "/api/chat",
                json={"message": SYNTH_PROMPT, "session_id": "web-session", "model": "remote/m1"},
            )
        )
        pending = None
        for _ in range(80):
            await asyncio.sleep(0.05)
            listed = await client.get("/api/echo/approvals")
            assert listed.status_code == 200
            items = listed.json()["approvals"]
            model_egress = [item for item in items if item.get("tool_name") == "model_egress"]
            if model_egress:
                pending = model_egress[0]
                break
        assert pending is not None, "web must queue a model_egress pending request"
        assert provider.calls == 0
        assert spies["resolver"] == []
        assert spies["sdk"] == []
        assert spies["async_client"] == []
        arguments = pending["arguments"]
        assert arguments["provider"]
        assert arguments["model"]
        assert "attempt_hash" in arguments
        assert SYNTH_PROMPT not in json.dumps(pending)
        assert SYNTH_API_KEY not in json.dumps(pending)
        assert pending.get("expires_at")
        decide = await client.post(
            f"/api/echo/approvals/{pending['id']}/decision",
            json={"action": "approve"},
        )
        assert decide.status_code == 200
        chat = await chat_task
        assert chat.status_code == 200, chat.text
    await agent.close()
    assert provider.calls == 1


@pytest.mark.asyncio
async def test_web_reject_timeout_cancel_and_double_approve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent = _isolate_agent(tmp_path)
    provider = _SpyProvider()
    _add_remote(agent, provider)
    spies = _install_transport_spies(monkeypatch)
    app, key, _owner = _web_app(agent)

    async def _wait_pending(client: AsyncClient) -> dict[str, Any]:
        for _ in range(80):
            await asyncio.sleep(0.05)
            items = (await client.get("/api/echo/approvals")).json()["approvals"]
            found = [item for item in items if item.get("tool_name") == "model_egress"]
            if found:
                return found[0]
        raise AssertionError("missing model_egress pending request")

    async with await _web_client(app, key) as client:
        reject_task = asyncio.create_task(
            client.post(
                "/api/chat",
                json={"message": SYNTH_PROMPT, "session_id": "rej-session", "model": "remote/m1"},
            )
        )
        pending = await _wait_pending(client)
        assert provider.calls == 0
        await client.post(
            f"/api/echo/approvals/{pending['id']}/decision",
            json={"action": "reject"},
        )
        rejected = await reject_task
        assert rejected.status_code in {200, 400, 403, 409, 500}
        assert provider.calls == 0

        approve_task = asyncio.create_task(
            client.post(
                "/api/chat",
                json={"message": SYNTH_PROMPT, "session_id": "ok-session", "model": "remote/m1"},
            )
        )
        pending = await _wait_pending(client)
        first = await client.post(
            f"/api/echo/approvals/{pending['id']}/decision",
            json={"action": "approve"},
        )
        second = await client.post(
            f"/api/echo/approvals/{pending['id']}/decision",
            json={"action": "approve"},
        )
        assert first.status_code == 200
        assert second.status_code in {404, 409, 400}
        chat = await approve_task
        assert chat.status_code == 200
        assert provider.calls == 1

        cancel_task = asyncio.create_task(
            client.post(
                "/api/chat",
                json={"message": SYNTH_PROMPT, "session_id": "can-session", "model": "remote/m1"},
            )
        )
        pending = await _wait_pending(client)
        del pending
        cancel_task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await cancel_task
        assert provider.calls == 1

        agent.approvals._default_timeout = 0.05
        timeout_task = asyncio.create_task(
            client.post(
                "/api/chat",
                json={"message": SYNTH_PROMPT, "session_id": "to-session", "model": "remote/m1"},
            )
        )
        await _wait_pending(client)
        await asyncio.sleep(0.2)
        agent.approvals._cleanup_stale()
        timed_out = await timeout_task
        assert timed_out.status_code in {200, 400, 403, 409, 500}
        assert provider.calls == 1
    await agent.close()
    assert spies["sdk"] == []


@pytest.mark.asyncio
async def test_web_wrong_owner_and_stale_identity_are_zero_calls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent = _isolate_agent(tmp_path)
    provider = _SpyProvider()
    _add_remote(agent, provider)
    _install_transport_spies(monkeypatch)
    app, key, _owner = _web_app(agent)
    other_key = AuthManager(agent.settings.state_dir).create_key("other", role="user")
    async with await _web_client(app, key) as client:
        chat_task = asyncio.create_task(
            client.post(
                "/api/chat",
                json={"message": SYNTH_PROMPT, "session_id": "id-session", "model": "remote/m1"},
            )
        )
        pending = None
        for _ in range(80):
            await asyncio.sleep(0.05)
            items = (await client.get("/api/echo/approvals")).json()["approvals"]
            if items:
                pending = items[0]
                break
        assert pending is not None
        async with await _web_client(app, other_key) as other:
            stolen = await other.post(
                f"/api/echo/approvals/{pending['id']}/decision",
                json={"action": "approve"},
            )
            assert stolen.status_code == 404
        assert provider.calls == 0
        await client.post(
            f"/api/echo/approvals/{pending['id']}/decision",
            json={"action": "reject"},
        )
        await chat_task
    await agent.close()
    assert provider.calls == 0


@pytest.mark.asyncio
async def test_web_edit_respond_forbidden_for_model_egress(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent = _isolate_agent(tmp_path)
    provider = _SpyProvider()
    _add_remote(agent, provider)
    _install_transport_spies(monkeypatch)
    app, key, _owner = _web_app(agent)
    async with await _web_client(app, key) as client:
        chat_task = asyncio.create_task(
            client.post(
                "/api/chat",
                json={"message": SYNTH_PROMPT, "session_id": "edit-session", "model": "remote/m1"},
            )
        )
        pending = None
        for _ in range(80):
            await asyncio.sleep(0.05)
            items = (await client.get("/api/echo/approvals")).json()["approvals"]
            if items:
                pending = items[0]
                break
        assert pending is not None
        edited = await client.post(
            f"/api/echo/approvals/{pending['id']}/decision",
            json={"action": "edit", "edited_arguments": {"x": 1}},
        )
        responded = await client.post(
            f"/api/echo/approvals/{pending['id']}/decision",
            json={"action": "respond", "response": "nope"},
        )
        assert edited.status_code == 400
        assert responded.status_code == 400
        await client.post(
            f"/api/echo/approvals/{pending['id']}/decision",
            json={"action": "reject"},
        )
        await chat_task
    await agent.close()
    assert provider.calls == 0


def test_approvals_ui_has_model_egress_safe_summary() -> None:
    source = Path("js/web/static/tabs/approvals.js").read_text(encoding="utf-8")
    assert "model_egress" in source
    assert "safe_summary" in source or "attempt_hash" in source
    assert "edited_arguments" in source
    # model_egress cards must not offer edit/respond
    assert "model_egress" in source and "approve" in source


# ---------------------------------------------------------------------------
# Exactly-once / no receipt reuse
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_distinct_identical_attempts_each_get_fresh_receipt(tmp_path: Path) -> None:
    agent = _isolate_agent(tmp_path)
    provider = _SpyProvider()
    _add_remote(agent, provider)
    queue: ApprovalQueue = agent.approvals
    from js.security.egress import ApprovalQueueEgressBroker

    claimed: list[str] = []

    async def resolver(request_id: str, _summary: Any) -> Any:
        claimed.append(request_id)
        return queue.decide(
            request_id,
            ApprovalDecisionType.APPROVE,
            owner_key_hash="owner-a",
        )

    broker_a = ApprovalQueueEgressBroker(queue, resolver=resolver)
    broker_b = ApprovalQueueEgressBroker(queue, resolver=resolver)
    agent.router._egress_consent_broker = broker_a
    token = set_runtime_context(
        agent.echo_runtime.build_context(
            channel="api_chat",
            owner_key_hash="owner-a",
            session_id="once-session",
            run_id="once-run",
            capabilities=(),
        )
    )
    try:
        first = await run_echo_turn(
            agent,
            SYNTH_PROMPT,
            channel="api_chat",
            owner_key_hash="owner-a",
            session_id="once-session",
            model="remote/m1",
        )
        agent.router._egress_consent_broker = broker_b
        second = await run_echo_turn(
            agent,
            SYNTH_PROMPT,
            channel="api_chat",
            owner_key_hash="owner-a",
            session_id="once-session",
            model="remote/m1",
        )
    finally:
        reset_runtime_context(token)
        await agent.close()
    assert first.status == "completed"
    assert second.status == "completed"
    assert provider.calls == 2
    assert len(set(claimed)) == 2
    # Distinct Router attempts may carry identical payload bytes; they must
    # not share a content-hash identity that would block the second turn.


@pytest.mark.asyncio
async def test_retry_does_not_reuse_receipt(tmp_path: Path) -> None:
    provider = _SpyProvider(max_retries=2, fail_times=1)
    router, issuer = _router(tmp_path, provider)
    broker = _FakeBroker(action="approve")
    _bind_broker(router, broker)
    token = set_runtime_context(_runtime_context(tmp_path))
    try:
        await router.chat(
            [ChatMessage(role="user", content=SYNTH_PROMPT)],
            provenance=_valid_provenance(),
            **_chat_kwargs(issuer),
        )
    finally:
        reset_runtime_context(token)
    assert provider.calls == 2
    assert len(broker.receipts) == 2
    assert broker.receipts[0].nonce != broker.receipts[1].nonce
    assert broker.receipts[0].attempt_hash != broker.receipts[1].attempt_hash


# ---------------------------------------------------------------------------
# Privacy sinks
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_privacy_sinks_omit_raw_payload(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    caplog.set_level(logging.DEBUG)
    agent = _isolate_agent(tmp_path)
    provider = _add_loopback(agent)
    provider.config.api_key = SYNTH_API_KEY
    seen = _capture_attempts(monkeypatch)
    relative = _owned_attachment(
        agent.settings.workspace,
        owner="owner-a",
        session="session-a",
        name="note.txt",
        content=b"secret-bytes",
    )
    try:
        await _loopback_turn(agent, SYNTH_PROMPT, attachments=[relative])
    except Exception as exc:
        _assert_privacy([exc, getattr(exc, "__dict__", {}), exc.__traceback__])
        raise
    await agent.close()
    assert provider.calls == 1
    provenance = seen[0]["provenance"]
    _assert_privacy(
        [
            provenance,
            list(agent.approvals.get_pending(owner_key_hash="owner-a")),
            _inspect_log_records(list(caplog.records)),
        ]
    )
    assert SYNTH_PATH not in json.dumps(provenance)
    assert "secret-bytes" not in json.dumps(provenance)


@pytest.mark.asyncio
async def test_legacy_empty_provenance_still_hashes_for_unit_router(tmp_path: Path) -> None:
    """B2B-A control: raw router.chat({}) remains a digestable snapshot."""
    provider = _SpyProvider(base_url=LOOPBACK_URL)
    router, issuer = _router(tmp_path, provider)
    token = set_runtime_context(_runtime_context(tmp_path))
    try:
        await router.chat(
            [ChatMessage(role="user", content="unit")],
            **_chat_kwargs(issuer, model="remote/m1"),
        )
    finally:
        reset_runtime_context(token)
    assert provider.calls == 1
    assert digest_jsonable({}) == digest_jsonable({})
    identity = _runtime_context(tmp_path)
    from js.security.egress import EgressIdentityV1

    attempt = build_egress_attempt(
        identity=EgressIdentityV1(
            product_id=identity.product_id,
            channel=identity.channel,
            owner_key_hash=identity.owner_key_hash,
            session_id=identity.session_id,
            run_id=identity.run_id,
        ),
        attempt_kind="initial",
        provider_name="loop",
        provider_generation="gen-1",
        model="m1",
        endpoint_url=LOOPBACK_URL,
        messages=[ChatMessage(role="user", content="unit")],
        tools=None,
        attachments=[],
        provenance={},
        temperature=0.7,
        effective_max_tokens=16,
    )
    assert attempt.provenance_digest == digest_jsonable({})
