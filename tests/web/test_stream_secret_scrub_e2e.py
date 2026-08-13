"""F-13 e2e: WS ``type=stream`` must not leak provider secrets anywhere."""

from __future__ import annotations

import base64
import json
import logging
import re
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch
from urllib.parse import quote, quote_plus

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocket, WebSocketDisconnect

from js.agent import JSAgent
from js.config import JSSettings, ModelConfig, ModelProviderConfig, SecurityConfig
from js.models.providers import OpenAICompatibleProvider
from js.models.stream_events import StreamEvent
from js.web.auth import AuthManager
from js.web.runtime_context import WebRuntime, bind_web_runtime

_SECRET = "xYz-NOT_A_SK_PREFIX_9876543210!@#"
_MODEL = ModelConfig(id="leak-model", name="Leak Model", context_window=4096)


def _leaky_message(secret: str = _SECRET) -> str:
    return (
        f"Client error '401' for url "
        f"'https://generativelanguage.googleapis.com/v1beta/models?key={secret}' "
        f"For more information check: detail={secret}"
    )


def _assert_secret_absent(secret: str, *values: Any) -> None:
    seen: set[int] = set()

    def strings(value: object) -> list[str]:
        if isinstance(value, str):
            return [value]
        if isinstance(value, bytes):
            return [value.decode("utf-8", errors="replace")]
        if isinstance(value, dict):
            identity = id(value)
            if identity in seen:
                return []
            seen.add(identity)
            return [
                item
                for key, child in value.items()
                for item in (*strings(key), *strings(child))
            ]
        if isinstance(value, list | tuple | set):
            identity = id(value)
            if identity in seen:
                return []
            seen.add(identity)
            return [item for child in value for item in strings(child)]
        if isinstance(value, BaseException):
            return [
                *strings(value.args),
                *strings(vars(value)),
                *strings(value.__cause__),
                *strings(value.__context__),
            ]
        if hasattr(value, "__dict__"):
            identity = id(value)
            if identity in seen:
                return []
            seen.add(identity)
            return strings(vars(value))
        return []

    observed = [item for value in values for item in strings(value)]
    for form in _secret_forms(secret):
        assert all(form not in item for item in observed)


def _percent_lower(value: str) -> str:
    return re.sub(r"%[0-9A-Fa-f]{2}", lambda match: match.group(0).lower(), value)


def _secret_forms(secret: str) -> tuple[str, ...]:
    raw = secret.encode("utf-8")
    encoded = quote(secret, safe="")
    plus = quote_plus(secret, safe="")
    standard = base64.b64encode(raw).decode("ascii")
    urlsafe = base64.urlsafe_b64encode(raw).decode("ascii")
    return tuple(
        dict.fromkeys(
            (
                secret,
                encoded,
                _percent_lower(encoded),
                plus,
                _percent_lower(plus),
                json.dumps(secret, ensure_ascii=True)[1:-1],
                standard,
                standard.rstrip("="),
                urlsafe,
                urlsafe.rstrip("="),
                raw.hex(),
                raw.hex().upper(),
            )
        )
    )


class _Circuit:
    async def can_execute(self) -> bool:
        return True

    async def record_success(self) -> None:
        return None

    async def record_failure(self) -> None:
        return None

    async def execute(self, coro: Any) -> Any:
        return await coro


def _leaky_stream_provider(secret: str = _SECRET) -> OpenAICompatibleProvider:
    provider = object.__new__(OpenAICompatibleProvider)
    provider.config = ModelProviderConfig(
        name="gemini-like",
        base_url="https://generativelanguage.googleapis.com/v1beta",
        api_key=secret,
        auth_adapter="query_param",
        query_param_name="key",
        default_model="leak-model",
        models=[_MODEL],
    )
    provider._is_local = False
    provider._last_stream_usage = None
    provider._stream_options_supported = True
    provider.circuit = _Circuit()

    async def leaky_stream_events(**_kwargs: Any) -> AsyncIterator[StreamEvent]:
        yield StreamEvent(
            kind="error",
            error=_leaky_message(secret),
            model="leak-model",
            meta={
                "retryable": False,
                "completion_tokens": 7,
                "api_key": secret,
                "raw_url": f"https://example.test?key={quote(secret, safe='')}",
                "diagnostic": _leaky_message(secret),
            },
        )

    provider.chat_stream_events = leaky_stream_events  # type: ignore[method-assign]
    provider.chat = AsyncMock(side_effect=RuntimeError(_leaky_message(secret)))
    provider.health_check = AsyncMock(return_value=True)
    provider.close = AsyncMock(return_value=None)
    return provider


def _successful_stream_provider(secret: str = _SECRET) -> OpenAICompatibleProvider:
    provider = _leaky_stream_provider(secret)

    async def successful_stream_events(**_kwargs: Any) -> AsyncIterator[StreamEvent]:
        content = "success:" + "|".join(_secret_forms(secret))
        reasoning = "reasoning:" + quote(secret, safe="")
        for char in content:
            yield StreamEvent(kind="text_delta", text=char, model="leak-model")
        for char in reasoning:
            yield StreamEvent(kind="thinking_delta", text=char, model="leak-model")
        yield StreamEvent(
            kind="usage",
            usage={"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3},
        )
        yield StreamEvent(kind="done", finish_reason="stop", model="leak-model")

    provider.chat_stream_events = successful_stream_events  # type: ignore[method-assign]
    return provider


def _build_app(monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.setenv("JS_ALLOWED_ORIGINS", "http://localhost")
    import js.web.auth as auth_mod

    monkeypatch.setattr(auth_mod, "_ALLOWED_ORIGINS", None)

    @asynccontextmanager
    async def _noop_lifespan(_app: Any) -> AsyncIterator[None]:
        yield

    with patch("js.web.server.lifespan", _noop_lifespan):
        from js.web.server import create_app

        return create_app()


@pytest.mark.asyncio
async def test_ws_type_stream_scrubs_secrets_in_all_sinks(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        security=SecurityConfig(api_key_required=False),
        echo_engine="on",
        max_turns=1,
    )
    (tmp_path / "workspace").mkdir(parents=True, exist_ok=True)
    (tmp_path / "state").mkdir(parents=True, exist_ok=True)

    agent = JSAgent(settings)
    provider = _leaky_stream_provider()
    agent.router._providers = {"gemini-like": provider}
    agent.router._model_map = {
        "leak-model": ("gemini-like", _MODEL),
        "gemini-like/leak-model": ("gemini-like", _MODEL),
    }
    agent.router._routing_cache.clear()

    app = _build_app(monkeypatch)
    bind_web_runtime(
        app,
        WebRuntime(agent=agent, settings=settings, stats_store=None),
    )
    with (
        patch("js.web.server._settings", settings),
        patch("js.web.server._agent", agent),
        patch("js.web.server.get_agent", lambda: agent),
        patch("js.web.deps._agent", agent),
        patch("js.web.deps._settings", settings),
    ):
        user_key = AuthManager(settings.state_dir).create_key("ws-scrub", role="user")
        client = TestClient(
            app,
            base_url="http://localhost",
            headers={"Origin": "http://localhost", "X-API-Key": user_key},
        )
        ws_frames: list[str] = []
        with (
            caplog.at_level(logging.DEBUG),
            client.websocket_connect("/ws") as ws,
        ):
            ws.send_json(
                {
                    "type": "stream",
                    "content": "hello",
                    "session_id": "sess-f13-stream-e2e",
                    "model": "leak-model",
                }
            )
            deadline = time.time() + 8.0
            while time.time() < deadline:
                try:
                    msg = ws.receive_json()
                except WebSocketDisconnect:
                    break
                ws_frames.append(repr(msg))
                if msg.get("type") in {"error", "done", "result", "stream_diagnostic"}:
                    if msg.get("type") == "result":
                        break
                    if msg.get("type") in {"error", "done"} and msg.get("terminal"):
                        break
                    if msg.get("type") == "stream_diagnostic":
                        # Keep reading until terminal frame.
                        continue

    await agent.close()

    raw_log_records = [
        (record.msg, record.args, record.exc_info, record.__dict__)
        for record in caplog.records
    ]

    sinks = [
        caplog.text,
        *ws_frames,
        raw_log_records,
    ]
    for sink in sinks:
        _assert_secret_absent(_SECRET, sink)

    diagnostic_frames = [f for f in ws_frames if "stream_diagnostic" in f]
    assert diagnostic_frames, "expected stream_diagnostic frame from provider error"
    for frame in diagnostic_frames:
        _assert_secret_absent(_SECRET, frame)

    assert any("error" in f or "stream_diagnostic" in f for f in ws_frames)


@pytest.mark.asyncio
async def test_ws_success_stream_scrubs_before_state_audit_events_and_raw_logs(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        security=SecurityConfig(api_key_required=False),
        echo_engine="on",
        max_turns=1,
    )
    settings.workspace.mkdir(parents=True, exist_ok=True)
    settings.state_dir.mkdir(parents=True, exist_ok=True)
    agent = JSAgent(settings)
    provider = _successful_stream_provider()
    agent.router._providers = {"gemini-like": provider}
    agent.router._model_map = {
        "leak-model": ("gemini-like", _MODEL),
        "gemini-like/leak-model": ("gemini-like", _MODEL),
    }
    agent.router._routing_cache.clear()

    audits: list[Any] = []
    events: list[Any] = []
    final_states: list[Any] = []
    reviews: list[Any] = []
    memory_writes: list[Any] = []
    dream_inputs: list[Any] = []

    original_finalize = agent._finalize_run

    async def finalize_run(
        state: Any,
        session_id: str,
        run_id: str,
        user_input: str,
        history_ua_count: int,
    ) -> None:
        final_states.append(state.to_dict())
        await original_finalize(
            state,
            session_id,
            run_id,
            user_input,
            history_ua_count,
        )

    agent.audit.log = lambda *args, **kwargs: audits.append((args, kwargs))  # type: ignore[method-assign]
    agent.event_store.emit = events.append  # type: ignore[method-assign]
    agent._finalize_run = finalize_run  # type: ignore[method-assign]
    agent._check_degraded = AsyncMock()  # type: ignore[method-assign]
    agent.review_store.store = reviews.append  # type: ignore[method-assign]
    agent.memory.store_messages = (  # type: ignore[method-assign]
        lambda *args, **kwargs: memory_writes.append(("messages", args, kwargs))
    )
    agent.memory.store_episode = (  # type: ignore[method-assign]
        lambda *args, **kwargs: memory_writes.append(("episode", args, kwargs))
    )
    agent.memory.store_working = (  # type: ignore[method-assign]
        lambda *args, **kwargs: memory_writes.append(("working", args, kwargs))
    )
    agent._dream_scheduler.notify_activity = (  # type: ignore[method-assign]
        lambda *args, **kwargs: dream_inputs.append((args, kwargs))
    )

    app = _build_app(monkeypatch)
    bind_web_runtime(app, WebRuntime(agent=agent, settings=settings, stats_store=None))
    ws_frames: list[Any] = []
    server_sent_frames: list[Any] = []
    original_websocket_send = WebSocket.send

    async def recording_websocket_send(
        websocket: WebSocket,
        message: dict[str, Any],
    ) -> None:
        if message.get("type") == "websocket.send":
            raw_text = message.get("text")
            if isinstance(raw_text, str):
                try:
                    frame = json.loads(raw_text)
                except json.JSONDecodeError:
                    frame = None
                if isinstance(frame, dict):
                    server_sent_frames.append(frame)
        await original_websocket_send(websocket, message)  # type: ignore[arg-type]

    with (
        patch("js.web.server._settings", settings),
        patch("js.web.server._agent", agent),
        patch("js.web.server.get_agent", lambda: agent),
        patch("js.web.deps._agent", agent),
        patch("js.web.deps._settings", settings),
        patch.object(WebSocket, "send", recording_websocket_send),
    ):
        user_key = AuthManager(settings.state_dir).create_key("ws-success", role="user")
        client = TestClient(
            app,
            base_url="http://localhost",
            headers={"Origin": "http://localhost", "X-API-Key": user_key},
        )
        with caplog.at_level(logging.DEBUG), client.websocket_connect("/ws") as ws:
            ws.send_json(
                {
                    "type": "stream",
                    "content": "hello",
                    "session_id": "sess-b1c-success",
                    "model": "leak-model",
                }
            )
            while True:
                frame = ws.receive_json()
                ws_frames.append(frame)
                if frame.get("terminal") and frame.get("type") in {
                    "done",
                    "error",
                    "cancelled",
                }:
                    break

    await agent.close()
    assert ws_frames
    assert final_states
    assert audits
    assert events
    assert reviews
    assert memory_writes
    assert dream_inputs
    raw_log_records = [
        (record.msg, record.args, record.exc_info, record.__dict__)
        for record in caplog.records
    ]
    for sink in (
        ws_frames,
        server_sent_frames,
        final_states,
        audits,
        events,
        reviews,
        memory_writes,
        dream_inputs,
        raw_log_records,
    ):
        _assert_secret_absent(_SECRET, sink)
    assert "[S]" in repr(ws_frames)
    terminal_frames = [frame for frame in ws_frames if frame.get("terminal")]
    assert len(terminal_frames) == 1
    assert terminal_frames[0].get("type") == "done"
    server_terminal_frames = [
        frame for frame in server_sent_frames if frame.get("terminal")
    ]
    assert len(server_terminal_frames) == 1
    assert server_terminal_frames[0].get("type") == "done"
    assert server_sent_frames == ws_frames
    assert final_states[-1].get("status") == "completed"
    streamed_text = "".join(
        str(frame.get("content", ""))
        for frame in ws_frames
        if frame.get("type") == "token"
    )
    streamed_thinking = "".join(
        str(frame.get("content", ""))
        for frame in ws_frames
        if frame.get("type") == "thinking"
    )
    assert streamed_text == "success:" + "|".join("[S]" for _ in _secret_forms(_SECRET))
    assert streamed_thinking == "reasoning:[S]"
