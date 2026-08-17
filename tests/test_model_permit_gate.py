"""P0-1: model authorization must be an unforgeable per-attempt runtime permit.

Attack reproduced on 2026-07-20 against digest
914b48fc61f20655db486f02234af23c7355c5dcc55a02c01e5116a0a0959d17:

1. ``ModelRouter.bind_echo_callbacks`` was public and repeatable.
2. Attacker rebound forged callbacks after the genuine Echo pair.
3. ``chat_stream_events`` accepted them (identity compare against the
   overwritten attributes) -> forged before/after executed, Echo bypassed.

These tests encode the required end state:

- no public rebind API exists at all;
- every provider attempt (retry/fallback/stream reconnect) requires a fresh
  single-use permit signed by the runtime-owned issuer;
- permits bind provider, model, messages hash, tools schema hash, owner,
  session and run;
- direct router calls without a valid permit fail closed;
- caller-supplied ``permit_grant`` is not an authority input: the router
  ignores it and issues an attempt-bound permit from the runtime issuer.
"""

from __future__ import annotations

import asyncio
import pathlib
import time
from collections.abc import AsyncGenerator
from dataclasses import replace
from types import SimpleNamespace
from typing import Any

import pytest

from js.config import JSSettings, ModelConfig
from js.models.permit import ModelPermitError, ModelPermitIssuer
from js.models.providers import ChatMessage, ChatResponse, ModelProvider
from js.models.router import ModelRouter
from js.models.stream_events import StreamEvent

_TOOLS_A = [{"type": "function", "function": {"name": "alpha"}}]
_TOOLS_B = [{"type": "function", "function": {"name": "beta"}}]


@pytest.fixture(autouse=True)
def _b2b_stub_identity(tmp_path: pathlib.Path) -> Any:
    from js.echo.turn_context import RuntimeContext, reset_runtime_context, set_runtime_context

    token = set_runtime_context(
        RuntimeContext(
            product_id="js-agent",
            channel="chat",
            owner_key_hash="owner",
            session_id="sess",
            run_id="run",
            role="user",
            profile="default",
            capabilities=(),
            workspace=tmp_path,
            state_dir=tmp_path,
        )
    )
    yield
    reset_runtime_context(token)


class _StubProvider(ModelProvider):
    def __init__(self, name: str = "stub", *, fail: bool = False) -> None:
        self.name = name
        self.fail = fail
        self.chat_calls = 0
        self.stream_calls = 0
        self.config = SimpleNamespace(
            name=name,
            base_url="http://127.0.0.1:9/v1",
            max_retries=1,
        )

    async def chat(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> ChatResponse:
        self.chat_calls += 1
        if self.fail:
            raise ConnectionError("provider exploded")
        return ChatResponse(
            content="stub",
            tool_calls=[],
            model=model,
            usage={"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            finish_reason="stop",
        )

    def chat_stream(self, messages, model, tools=None, temperature=0.7, max_tokens=None) -> Any:
        raise NotImplementedError

    async def chat_stream_events(
        self,
        *,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> AsyncGenerator[StreamEvent, None]:
        self.stream_calls += 1
        yield StreamEvent(kind="text_delta", text="hello")
        yield StreamEvent(kind="done", finish_reason="stop")

    async def health_check(self) -> bool:
        return True

    async def close(self) -> None:
        return None


class _FlakyProvider(_StubProvider):
    """Fails the first call with a retryable transport error, then succeeds."""

    async def chat(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> ChatResponse:
        self.chat_calls += 1
        if self.chat_calls == 1:
            import httpx

            raise httpx.ConnectError("transient transport failure")
        return ChatResponse(
            content="stub",
            tool_calls=[],
            model=model,
            usage={"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            finish_reason="stop",
        )


class _RetryableStreamProvider(_StubProvider):
    """First stream is a retryable error with no output; later streams succeed."""

    async def chat_stream_events(
        self,
        *,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> AsyncGenerator[StreamEvent, None]:
        self.stream_calls += 1
        if self.stream_calls == 1:
            yield StreamEvent(kind="error", error="transient", meta={"retryable": True})
            return
        yield StreamEvent(kind="text_delta", text="hello")
        yield StreamEvent(kind="done", finish_reason="stop")


class _RecordingGrant:
    def __init__(self, delegate: Any) -> None:
        self.calls = 0
        self._delegate = delegate

    def __call__(self, decision: Any, messages: list[ChatMessage], tools: Any) -> Any:
        self.calls += 1
        return self._delegate(decision, messages, tools)


def _router_with_stub(
    issuer: ModelPermitIssuer | None = None,
    *,
    providers: dict[str, _StubProvider] | None = None,
) -> ModelRouter:
    settings = JSSettings(workspace=pathlib.Path("/tmp/x"), providers=[])
    router = ModelRouter(settings, permit_verifier=issuer)
    for name, provider in (providers or {"stub": _StubProvider()}).items():
        router.add_provider(name, provider, [ModelConfig(id="m1", name="m1", provider=name)])
    return router


def _grant(issuer: ModelPermitIssuer, *, owner: str = "owner", session: str = "sess", run: str = "run"):
    def grant(decision: Any, messages: list[ChatMessage], tools: Any) -> Any:
        return issuer.issue(
            provider_name=decision.provider_name,
            model=decision.model,
            messages=messages,
            tools=tools,
            owner_key_hash=owner,
            session_id=session,
            run_id=run,
        )

    return grant


def _issuer_kwargs(**overrides: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "provider_name": "stub",
        "model": "m1",
        "messages": [ChatMessage(role="user", content="hi")],
        "tools": _TOOLS_A,
        "owner_key_hash": "owner",
        "session_id": "sess",
        "run_id": "run",
        "attempt_hash": "attempt-1",
        "consent_receipt_hash": "receipt-1",
        "channel": "chat",
        "provider_generation": "gen-1",
        "endpoint_digest": "endpoint-1",
        "attachments_digest": "att-1",
        "provenance_digest": "prov-1",
        "temperature": 0.7,
        "effective_max_tokens": 128,
        "appshell_epoch": "1",
    }
    values.update(overrides)
    return values


def _spy_issue(issuer: ModelPermitIssuer, monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    issued: list[Any] = []
    real = issuer.issue

    def _issue(**kwargs: Any) -> Any:
        permit = real(**kwargs)
        issued.append(permit)
        return permit

    monkeypatch.setattr(issuer, "issue", _issue)
    return issued


async def _noop_before(*_a: Any, **_kw: Any) -> Any:
    return {"claim": "ok"}


async def _noop_after(*_a: Any, **_kw: Any) -> None:
    return None


async def _instant_sleep(_delay: float) -> None:
    return None


# ---------------------------------------------------------------------------
# Gate shape
# ---------------------------------------------------------------------------


def test_router_has_no_public_callback_rebind_api() -> None:
    """The rebind attack surface must not exist at all."""
    assert not hasattr(ModelRouter, "bind_echo_callbacks")
    router = _router_with_stub(ModelPermitIssuer())
    assert not hasattr(router, "bind_echo_callbacks")


@pytest.mark.asyncio
async def test_rebind_attack_cannot_bypass_echo() -> None:
    """The exact P0-1 attack: rebind forged callbacks, then stream.

    Against the unfixed source this succeeds and the forged callbacks run.
    """
    issuer = ModelPermitIssuer()
    router = _router_with_stub(issuer)
    calls = {"genuine_before": 0, "genuine_after": 0, "forged_before": 0, "forged_after": 0}

    async def genuine_before(*_a: Any, **_kw: Any) -> Any:
        calls["genuine_before"] += 1
        return None

    async def genuine_after(*_a: Any, **_kw: Any) -> None:
        calls["genuine_after"] += 1

    async def forged_before(*_a: Any, **_kw: Any) -> Any:
        calls["forged_before"] += 1
        return None

    async def forged_after(*_a: Any, **_kw: Any) -> None:
        calls["forged_after"] += 1

    # Step 1+2 of the original attack: bind genuine, then publicly rebind forged.
    bind = getattr(router, "bind_echo_callbacks", None)
    assert bind is None, "public callback rebind API still exists"

    # Step 3: drive the router with forged callbacks and no valid permit.
    with pytest.raises((RuntimeError, ModelPermitError)):
        async for _ in router.chat_stream_events(
            messages=[ChatMessage(role="user", content="hi")],
            model="stub/m1",
            before_model_call=forged_before,
            after_model_call=forged_after,
        ):
            pass
    assert calls["forged_before"] == 0
    assert calls["forged_after"] == 0
    assert calls["genuine_before"] == 0
    assert calls["genuine_after"] == 0


# ---------------------------------------------------------------------------
# Permit enforcement
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_chat_without_permit_grant_fails_closed() -> None:
    router = _router_with_stub(ModelPermitIssuer())
    with pytest.raises(RuntimeError):
        await router.chat(
            messages=[ChatMessage(role="user", content="hi")],
            model="stub/m1",
            before_model_call=_noop_before,
            after_model_call=_noop_after,
        )


@pytest.mark.asyncio
async def test_chat_with_valid_permit_grant_succeeds() -> None:
    issuer = ModelPermitIssuer()
    provider = _StubProvider()
    router = _router_with_stub(issuer, providers={"stub": provider})
    response = await router.chat(
        messages=[ChatMessage(role="user", content="hi")],
        model="stub/m1",
        before_model_call=_noop_before,
        after_model_call=_noop_after,
        permit_grant=_grant(issuer),
    )
    assert response.content == "stub"
    assert provider.chat_calls == 1


@pytest.mark.asyncio
async def test_untrusted_external_permit_grant_is_ignored_and_runtime_issues_bound_permit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Caller ``permit_grant`` is not consumed; the runtime issuer binds the attempt."""
    issuer = ModelPermitIssuer()
    attacker = ModelPermitIssuer()
    provider = _StubProvider()
    router = _router_with_stub(issuer, providers={"stub": provider})
    issued = _spy_issue(issuer, monkeypatch)
    external = _RecordingGrant(_grant(attacker))
    spent_before = issuer.spent_nonce_count()
    response = await router.chat(
        messages=[ChatMessage(role="user", content="hi")],
        model="stub/m1",
        before_model_call=_noop_before,
        after_model_call=_noop_after,
        permit_grant=external,
    )
    assert response.content == "stub"
    assert external.calls == 0
    assert attacker.spent_nonce_count() == 0
    assert len(issued) == 1
    assert issued[0].attempt_hash
    assert issuer.spent_nonce_count() == spent_before + 1
    assert provider.chat_calls == 1


@pytest.mark.asyncio
async def test_fallback_issues_fresh_permit_per_attempt(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every provider attempt (retry/fallback) must re-issue and re-verify."""
    # Keep the retry backoff fast without weakening the assertions.
    monkeypatch.setattr(asyncio, "sleep", _instant_sleep)
    issuer = ModelPermitIssuer()
    flaky = _FlakyProvider("flaky")
    flaky.config = SimpleNamespace(
        name="flaky",
        base_url="http://127.0.0.1:9/v1",
        max_retries=3,
    )
    router = _router_with_stub(issuer, providers={"flaky": flaky})
    spent_before = issuer.spent_nonce_count()
    response = await router.chat(
        messages=[ChatMessage(role="user", content="hi")],
        model="flaky/m1",
        before_model_call=_noop_before,
        after_model_call=_noop_after,
        permit_grant=_grant(issuer),
    )
    assert response.content == "stub"
    assert flaky.chat_calls == 2
    assert issuer.spent_nonce_count() == spent_before + 2


@pytest.mark.asyncio
async def test_stream_events_requires_valid_permit() -> None:
    issuer = ModelPermitIssuer()
    provider = _StubProvider()
    router = _router_with_stub(issuer, providers={"stub": provider})

    with pytest.raises(RuntimeError):
        async for _ in router.chat_stream_events(
            messages=[ChatMessage(role="user", content="hi")],
            model="stub/m1",
            before_model_call=_noop_before,
            after_model_call=_noop_after,
        ):
            pass
    assert provider.stream_calls == 0

    kinds = []
    async for ev in router.chat_stream_events(
        messages=[ChatMessage(role="user", content="hi")],
        model="stub/m1",
        before_model_call=_noop_before,
        after_model_call=_noop_after,
        permit_grant=_grant(issuer),
    ):
        kinds.append(ev.kind)
    assert "text_delta" in kinds
    assert "done" in kinds
    assert provider.stream_calls == 1


@pytest.mark.asyncio
async def test_stream_ignores_external_permit_grant_and_uses_runtime_issuer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Stream ignores caller grant and consumes only the runtime-issued permit."""
    issuer = ModelPermitIssuer()
    attacker = ModelPermitIssuer()
    provider = _StubProvider()
    router = _router_with_stub(issuer, providers={"stub": provider})
    issued = _spy_issue(issuer, monkeypatch)
    external = _RecordingGrant(_grant(attacker))
    spent_before = issuer.spent_nonce_count()
    kinds = []
    async for ev in router.chat_stream_events(
        messages=[ChatMessage(role="user", content="hi")],
        model="stub/m1",
        before_model_call=_noop_before,
        after_model_call=_noop_after,
        permit_grant=external,
    ):
        kinds.append(ev.kind)
    assert "done" in kinds
    assert external.calls == 0
    assert attacker.spent_nonce_count() == 0
    assert len(issued) == 1
    assert issued[0].attempt_hash
    assert issuer.spent_nonce_count() == spent_before + 1
    assert provider.stream_calls == 1


# ---------------------------------------------------------------------------
# A–E: issuer is the authority boundary
# ---------------------------------------------------------------------------


def test_issuer_rejects_replay_of_same_permit() -> None:
    """The same issued permit cannot be consumed twice; spent nonce stays at one."""
    issuer = ModelPermitIssuer()
    kwargs = _issuer_kwargs()
    permit = issuer.issue(**kwargs)
    issuer.verify_and_consume(permit, **kwargs)
    spent_after_first = issuer.spent_nonce_count()
    assert spent_after_first == 1
    with pytest.raises(ModelPermitError, match="replayed"):
        issuer.verify_and_consume(permit, **kwargs)
    assert issuer.spent_nonce_count() == spent_after_first


def test_issuer_rejects_tampered_mac() -> None:
    issuer = ModelPermitIssuer()
    kwargs = _issuer_kwargs()
    permit = issuer.issue(**kwargs)
    tampered = replace(permit, mac="deadbeef" * 8)
    spent_before = issuer.spent_nonce_count()
    with pytest.raises(ModelPermitError, match="MAC mismatch"):
        issuer.verify_and_consume(tampered, **kwargs)
    assert issuer.spent_nonce_count() == spent_before


def test_issuer_rejects_expired_permit(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = {"now": 1_700_000_000.0}
    monkeypatch.setattr(time, "time", lambda: clock["now"])
    issuer = ModelPermitIssuer(ttl_seconds=10.0)
    kwargs = _issuer_kwargs()
    permit = issuer.issue(**kwargs)
    clock["now"] = permit.expires_at + 0.1
    spent_before = issuer.spent_nonce_count()
    with pytest.raises(ModelPermitError, match="expired"):
        issuer.verify_and_consume(permit, **kwargs)
    assert issuer.spent_nonce_count() == spent_before


def test_issuer_rejects_messages_digest_mismatch() -> None:
    issuer = ModelPermitIssuer()
    messages_a = [ChatMessage(role="user", content="alpha")]
    messages_b = [ChatMessage(role="user", content="beta")]
    kwargs = _issuer_kwargs(messages=messages_a)
    permit = issuer.issue(**kwargs)
    spent_before = issuer.spent_nonce_count()
    with pytest.raises(ModelPermitError, match="messages"):
        issuer.verify_and_consume(permit, **{**kwargs, "messages": messages_b})
    assert issuer.spent_nonce_count() == spent_before


@pytest.mark.parametrize(
    "override",
    [
        {"tools": _TOOLS_B},
        {"attachments_digest": "att-other"},
        {"provenance_digest": "prov-other"},
        {"endpoint_digest": "endpoint-other"},
        {"provider_generation": "gen-other"},
        {"temperature": 0.1},
        {"effective_max_tokens": 64},
        {"owner_key_hash": "owner-b"},
        {"session_id": "sess-b"},
        {"run_id": "run-b"},
        {"channel": "other"},
        {"consent_receipt_hash": "receipt-other"},
    ],
    ids=[
        "tools_digest",
        "attachment_digest",
        "provenance_digest",
        "endpoint_digest",
        "provider_generation",
        "temperature",
        "effective_max_tokens",
        "owner",
        "session",
        "run",
        "channel",
        "consent_receipt_hash",
    ],
)
def test_issuer_rejects_exact_attempt_binding_mismatch(override: dict[str, Any]) -> None:
    issuer = ModelPermitIssuer()
    kwargs = _issuer_kwargs()
    permit = issuer.issue(**kwargs)
    spent_before = issuer.spent_nonce_count()
    with pytest.raises(ModelPermitError):
        issuer.verify_and_consume(permit, **{**kwargs, **override})
    assert issuer.spent_nonce_count() == spent_before


# ---------------------------------------------------------------------------
# F–H: router internal permit lifecycle (issuer wrapped, router not replaced)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_router_retry_reuse_of_same_permit_fails_before_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A retry that reuses the first attempt's permit must die before transport."""
    monkeypatch.setattr(asyncio, "sleep", _instant_sleep)
    issuer = ModelPermitIssuer()
    flaky = _FlakyProvider("flaky")
    flaky.config = SimpleNamespace(
        name="flaky",
        base_url="http://127.0.0.1:9/v1",
        max_retries=3,
    )
    router = _router_with_stub(issuer, providers={"flaky": flaky})
    held: list[Any] = []
    real = issuer.issue

    def _reuse(**kwargs: Any) -> Any:
        if not held:
            held.append(real(**kwargs))
        return held[0]

    monkeypatch.setattr(issuer, "issue", _reuse)
    spent_before = issuer.spent_nonce_count()
    with pytest.raises(ModelPermitError):
        await router.chat(
            messages=[ChatMessage(role="user", content="hi")],
            model="flaky/m1",
            before_model_call=_noop_before,
            after_model_call=_noop_after,
            permit_grant=_grant(issuer),
        )
    assert flaky.chat_calls == 1
    assert issuer.spent_nonce_count() == spent_before + 1
    assert len(held) == 1


@pytest.mark.asyncio
async def test_stream_reconnect_reuse_of_same_permit_fails_before_second_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Stream reconnect must not reuse the first permit or continue fallback."""
    monkeypatch.setattr(asyncio, "sleep", _instant_sleep)
    issuer = ModelPermitIssuer()
    provider = _RetryableStreamProvider()
    provider.config = SimpleNamespace(
        name="stub",
        base_url="http://127.0.0.1:9/v1",
        max_retries=3,
    )
    router = _router_with_stub(issuer, providers={"stub": provider})
    held: list[Any] = []
    real = issuer.issue

    def _reuse(**kwargs: Any) -> Any:
        if not held:
            held.append(real(**kwargs))
        return held[0]

    monkeypatch.setattr(issuer, "issue", _reuse)
    kinds: list[str] = []
    with pytest.raises(ModelPermitError):
        async for ev in router.chat_stream_events(
            messages=[ChatMessage(role="user", content="hi")],
            model="stub/m1",
            before_model_call=_noop_before,
            after_model_call=_noop_after,
            permit_grant=_grant(issuer),
        ):
            kinds.append(ev.kind)
    assert provider.stream_calls == 1
    assert "done" not in kinds
    assert "text_delta" not in kinds


def _wrap_internal_issue(
    issuer: ModelPermitIssuer,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    real = issuer.issue

    def _issue(**kwargs: Any) -> Any:
        permit = real(**kwargs)
        if mode == "tampered":
            return replace(permit, mac="deadbeef" * 8)
        if mode == "expired":
            shifted = replace(permit, expires_at=time.time() - 1.0)
            return replace(shifted, mac=issuer._mac(shifted))
        if mode == "already_consumed":
            issuer.verify_and_consume(permit, **kwargs)
            return permit
        if mode == "wrong_attempt":
            return real(**{**kwargs, "attempt_hash": f"wrong-{kwargs['attempt_hash']}"})
        raise AssertionError(f"unknown internal permit mode {mode}")

    monkeypatch.setattr(issuer, "issue", _issue)


@pytest.mark.parametrize(
    "mode",
    ["tampered", "expired", "already_consumed", "wrong_attempt"],
)
@pytest.mark.asyncio
async def test_router_internal_issuer_invalid_permit_is_rejected_before_chat(
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    issuer = ModelPermitIssuer()
    provider = _StubProvider()
    router = _router_with_stub(issuer, providers={"stub": provider})
    _wrap_internal_issue(issuer, monkeypatch, mode)
    with pytest.raises(ModelPermitError):
        await router.chat(
            messages=[ChatMessage(role="user", content="hi")],
            model="stub/m1",
            before_model_call=_noop_before,
            after_model_call=_noop_after,
            permit_grant=_grant(issuer),
        )
    assert provider.chat_calls == 0
    assert provider.stream_calls == 0


@pytest.mark.parametrize(
    "mode",
    ["tampered", "expired", "already_consumed", "wrong_attempt"],
)
@pytest.mark.asyncio
async def test_router_internal_issuer_invalid_permit_is_rejected_before_stream(
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    issuer = ModelPermitIssuer()
    provider = _StubProvider()
    router = _router_with_stub(issuer, providers={"stub": provider})
    _wrap_internal_issue(issuer, monkeypatch, mode)
    with pytest.raises(ModelPermitError):
        async for _ in router.chat_stream_events(
            messages=[ChatMessage(role="user", content="hi")],
            model="stub/m1",
            before_model_call=_noop_before,
            after_model_call=_noop_after,
            permit_grant=_grant(issuer),
        ):
            pass
    assert provider.stream_calls == 0
    assert provider.chat_calls == 0


@pytest.mark.asyncio
async def test_router_internal_issuer_wrong_messages_permit_is_rejected_before_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    issuer = ModelPermitIssuer()
    provider = _StubProvider()
    router = _router_with_stub(issuer, providers={"stub": provider})
    real = issuer.issue

    def _wrong_messages(**kwargs: Any) -> Any:
        return real(
            **{
                **kwargs,
                "messages": [ChatMessage(role="user", content="different")],
            }
        )

    monkeypatch.setattr(issuer, "issue", _wrong_messages)
    spent_before = issuer.spent_nonce_count()
    with pytest.raises(ModelPermitError, match="messages"):
        await router.chat(
            messages=[ChatMessage(role="user", content="hi")],
            model="stub/m1",
            before_model_call=_noop_before,
            after_model_call=_noop_after,
            permit_grant=_grant(issuer),
        )
    assert provider.chat_calls == 0
    assert issuer.spent_nonce_count() == spent_before
