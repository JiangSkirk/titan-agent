"""B2B-A: one-use manual consent for every real model Provider payload egress.

These tests are the required RED/GREEN contract. They use only fake brokers,
fake providers, TemporaryDirectory/tmp_path, and synthetic text. They must
not touch a real Provider, Keychain, ~/.js, ~/.js-work, user chat/memory,
or the network.
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlparse

import pytest

from js.agent import JSAgent
from js.config import JSSettings, ModelConfig, ModelProviderConfig
from js.echo.turn_context import (
    RuntimeContext,
    reset_runtime_context,
    set_runtime_context,
)
from js.memory.embeddings import HybridEmbedder, KeywordEmbedder, LLMEmbedder
from js.models.permit import ModelPermitError, ModelPermitIssuer
from js.models.providers import ChatMessage, ChatResponse, ModelProvider
from js.models.router import ModelRouter
from js.models.stream_events import StreamEvent
from js.security.approvals import (
    ApprovalDecision,
    ApprovalDecisionType,
    ApprovalMode,
    ApprovalQueue,
)
from js.security.net_guard import PinnedTransport, is_canonical_loopback_literal

SYNTH_PROMPT = "SYNTH_PROMPT_NEVER_PERSIST_q9z"
SYNTH_PATH = "/tmp/synth_attach_secret_file.txt"
SYNTH_ATTACH = "synth_secret_attachment.pdf"
SYNTH_API_KEY = "sk-synth-b2b-never-log"
SYNTH_RAW_ARGS = "raw_tool_arg_secret_xyz"
REMOTE_URL = "https://api.example.test/v1"
LOOPBACK_URL = "http://127.0.0.1:1234/v1"
PRIVACY_NEEDLES = (SYNTH_PROMPT, SYNTH_PATH, SYNTH_ATTACH, SYNTH_API_KEY, SYNTH_RAW_ARGS)


def _egress_mod() -> Any:
    try:
        from js.security import egress as module
    except ImportError:
        pytest.fail("js.security.egress is required for B2B-A")
    return module


def _identity(**overrides: Any) -> Any:
    module = _egress_mod()
    cls = getattr(module, "EgressIdentityV1", None)
    if cls is None:
        pytest.fail("EgressIdentityV1 is required")
    values = {
        "product_id": "js-agent",
        "channel": "chat",
        "owner_key_hash": "owner-a",
        "session_id": "session-a",
        "run_id": "run-a",
        "appshell_epoch": "1",
    }
    values.update(overrides)
    return cls(**values)


def _bind_broker(router: ModelRouter, broker: Any) -> None:
    bind = getattr(router, "bind_egress_consent_broker", None)
    if not callable(bind):
        pytest.fail("ModelRouter.bind_egress_consent_broker is required")
    bind(broker)


def _runtime_context(tmp_path: Path, **overrides: Any) -> RuntimeContext:
    values: dict[str, Any] = {
        "product_id": "js-agent",
        "channel": "chat",
        "owner_key_hash": "owner-a",
        "session_id": "session-a",
        "run_id": "run-a",
        "role": "user",
        "profile": "default",
        "capabilities": (),
        "workspace": tmp_path,
        "state_dir": tmp_path,
    }
    values.update(overrides)
    return RuntimeContext(**values)


class _SpyConfig:
    def __init__(
        self,
        *,
        name: str,
        base_url: Any,
        max_retries: int = 1,
        api_key: str | None = None,
        generation: str = "gen-1",
    ) -> None:
        self.name = name
        self.base_url = base_url
        self.max_retries = max_retries
        self.api_key = api_key
        self.query_param_name = None
        self.generation = generation


class _SpyProvider(ModelProvider):
    def __init__(
        self,
        *,
        name: str = "remote",
        base_url: Any = REMOTE_URL,
        max_retries: int = 1,
        fail_times: int = 0,
        stream_fail_times: int = 0,
        api_key: str | None = None,
        generation: str = "gen-1",
    ) -> None:
        self.name = name
        self.config = _SpyConfig(
            name=name,
            base_url=base_url,
            max_retries=max_retries,
            api_key=api_key,
            generation=generation,
        )
        self._provider_generation = generation
        self.calls = 0
        self.stream_calls = 0
        self.embed_calls = 0
        self.seen: list[dict[str, Any]] = []
        self._fail_remaining = fail_times
        self._stream_fail_remaining = stream_fail_times

    def response_secret_snapshot(self) -> str | None:
        return self.config.api_key

    async def chat(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> ChatResponse:
        self.calls += 1
        self.seen.append(
            {
                "messages": [
                    {
                        "role": message.role,
                        "content": message.content,
                        "tool_calls": message.tool_calls,
                    }
                    for message in messages
                ],
                "tools": tools,
                "temperature": temperature,
                "max_tokens": max_tokens,
                "model": model,
                "base_url": self.config.base_url,
                "generation": self._provider_generation,
            }
        )
        if self._fail_remaining > 0:
            self._fail_remaining -= 1
            from js.models.capability import SafeProviderError

            raise SafeProviderError("synthetic-retryable", retryable=True)
        return ChatResponse(
            content="ok",
            tool_calls=[],
            model=model,
            usage={"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            finish_reason="stop",
        )

    def chat_stream(self, *args: Any, **kwargs: Any) -> Any:
        raise NotImplementedError

    async def chat_stream_events(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> Any:
        self.stream_calls += 1
        self.seen.append(
            {
                "stream": True,
                "messages": [{"role": m.role, "content": m.content} for m in messages],
                "temperature": temperature,
                "max_tokens": max_tokens,
                "base_url": self.config.base_url,
            }
        )
        if self._stream_fail_remaining > 0:
            self._stream_fail_remaining -= 1
            yield StreamEvent(kind="error", error="synthetic-retryable", meta={"retryable": True})
            return
        yield StreamEvent(kind="text_delta", text="ok")
        yield StreamEvent(kind="done")

    async def embed(self, texts: list[str], model: str | None = None) -> list[list[float]]:
        self.embed_calls += 1
        return [[0.1, 0.2] for _ in texts]

    async def health_check(self) -> bool:
        return True

    async def close(self) -> None:
        return None


class _FakeBroker:
    def __init__(
        self,
        *,
        action: str = "approve",
        actions: list[str] | None = None,
        hang: bool = False,
    ) -> None:
        self.action = action
        self.actions = list(actions or [])
        self.hang = hang
        self.attempts: list[Any] = []
        self.receipts: list[Any] = []
        self.summaries: list[Any] = []
        self.claim_count = 0

    async def request_and_claim(self, attempt: Any, safe_summary: Any) -> Any:
        self.attempts.append(attempt)
        self.summaries.append(safe_summary)
        if self.hang:
            await asyncio.Event().wait()
        planned = self.actions.pop(0) if self.actions else self.action
        if planned == "reject":
            raise PermissionError("egress consent rejected")
        if planned == "timeout":
            raise TimeoutError("egress consent timeout")
        if planned == "cancel":
            raise asyncio.CancelledError()
        module = _egress_mod()
        receipt_cls = getattr(module, "EgressConsentReceiptV1", None)
        if receipt_cls is None:
            pytest.fail("EgressConsentReceiptV1 is required")
        attempt_hash = getattr(attempt, "attempt_hash", None)
        if not isinstance(attempt_hash, str) or not attempt_hash:
            hasher = getattr(module, "hash_egress_attempt", None)
            if not callable(hasher):
                pytest.fail("hash_egress_attempt is required")
            attempt_hash = hasher(attempt)
        receipt = receipt_cls(
            attempt_hash=attempt_hash,
            claim_receipt_hash=f"claim-{len(self.receipts) + 1}",
            expires_at=8_000_000_000.0,
            nonce=f"nonce-{len(self.receipts) + 1}",
        )
        self.receipts.append(receipt)
        self.claim_count += 1
        return receipt


def _router(
    tmp_path: Path,
    provider: _SpyProvider,
    issuer: ModelPermitIssuer | None = None,
    *,
    extra_providers: list[_SpyProvider] | None = None,
) -> tuple[ModelRouter, ModelPermitIssuer]:
    issuer = issuer or ModelPermitIssuer()
    settings = JSSettings(workspace=tmp_path, state_dir=tmp_path / "state", providers=[])
    router = ModelRouter(settings, permit_verifier=issuer)
    router.add_provider(
        provider.name,
        provider,
        [ModelConfig(id="m1", name="m1", provider=provider.name, max_tokens=50)],
    )
    for extra in extra_providers or []:
        router.add_provider(
            extra.name,
            extra,
            [ModelConfig(id="m1", name="m1", provider=extra.name, max_tokens=50)],
        )
    return router, issuer


def _grant(issuer: ModelPermitIssuer, *, owner: str = "owner-a") -> Any:
    def grant(decision: Any, messages: list[ChatMessage], tools: Any) -> Any:
        return issuer.issue(
            provider_name=decision.provider_name,
            model=decision.model,
            messages=messages,
            tools=tools,
            owner_key_hash=owner,
            session_id="session-a",
            run_id="run-a",
        )

    return grant


async def _noop_before(*_args: Any, **_kwargs: Any) -> Any:
    return None


async def _noop_after(*_args: Any, **_kwargs: Any) -> None:
    return None


def _chat_kwargs(issuer: ModelPermitIssuer, **extra: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "model": extra.pop("model", "remote/m1"),
        "before_model_call": extra.pop("before_model_call", _noop_before),
        "after_model_call": extra.pop("after_model_call", _noop_after),
        "permit_grant": extra.pop("permit_grant", _grant(issuer)),
    }
    values.update(extra)
    return values


# ---------------------------------------------------------------------------
# 1. Remote endpoint without a broker
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_remote_chat_without_broker_is_zero_calls(tmp_path: Path) -> None:
    provider = _SpyProvider()
    router, issuer = _router(tmp_path, provider)
    token = set_runtime_context(_runtime_context(tmp_path))
    try:
        with pytest.raises((PermissionError, RuntimeError, ModelPermitError)):
            await router.chat(
                [ChatMessage(role="user", content=SYNTH_PROMPT)],
                **_chat_kwargs(issuer),
            )
    finally:
        reset_runtime_context(token)
    assert provider.calls == 0


@pytest.mark.asyncio
async def test_remote_stream_without_broker_is_zero_calls(tmp_path: Path) -> None:
    provider = _SpyProvider()
    router, issuer = _router(tmp_path, provider)
    token = set_runtime_context(_runtime_context(tmp_path))
    try:
        with pytest.raises((PermissionError, RuntimeError, ModelPermitError)):
            async for _event in router.chat_stream_events(
                [ChatMessage(role="user", content=SYNTH_PROMPT)],
                **_chat_kwargs(issuer),
            ):
                pass
    finally:
        reset_runtime_context(token)
    assert provider.stream_calls == 0
    assert provider.calls == 0


@pytest.mark.asyncio
async def test_background_and_setup_without_broker_are_zero_calls(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    state = tmp_path / "state"
    workspace.mkdir()
    settings = JSSettings(workspace=workspace, state_dir=state, providers=[])
    agent = JSAgent(settings)
    provider = _SpyProvider(name="remote")
    agent.router.add_provider(
        "remote",
        provider,
        [ModelConfig(id="m1", name="m1", provider="remote")],
    )
    with pytest.raises((PermissionError, RuntimeError, ModelPermitError)):
        await agent.authorized_model_chat(
            [ChatMessage(role="user", content=SYNTH_PROMPT)],
            tenant_id="owner-a",
            run_id="background-run",
            session_id="background-session",
            model="remote/m1",
        )
    assert provider.calls == 0

    setup_token = set_runtime_context(
        _runtime_context(tmp_path, channel="setup_model_test", run_id="setup-run")
    )
    try:
        with pytest.raises((PermissionError, RuntimeError, ModelPermitError)):
            await agent.router.chat(
                [ChatMessage(role="user", content=SYNTH_PROMPT)],
                **_chat_kwargs(agent._model_permit_issuer, model="remote/m1"),
            )
    finally:
        reset_runtime_context(setup_token)
    assert provider.calls == 0


# ---------------------------------------------------------------------------
# 2. Pending / approve / reject / timeout / cancel
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_consent_pending_keeps_provider_at_zero(tmp_path: Path) -> None:
    provider = _SpyProvider()
    router, issuer = _router(tmp_path, provider)
    broker = _FakeBroker(hang=True)
    _bind_broker(router, broker)
    token = set_runtime_context(_runtime_context(tmp_path))
    try:
        task = asyncio.create_task(
            router.chat(
                [ChatMessage(role="user", content=SYNTH_PROMPT)],
                **_chat_kwargs(issuer),
            )
        )
        await asyncio.sleep(0.05)
        assert provider.calls == 0
        assert broker.claim_count == 0
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    finally:
        reset_runtime_context(token)
    assert provider.calls == 0


@pytest.mark.asyncio
async def test_approve_allows_exactly_one_provider_call(tmp_path: Path) -> None:
    provider = _SpyProvider()
    router, issuer = _router(tmp_path, provider)
    broker = _FakeBroker(action="approve")
    _bind_broker(router, broker)
    token = set_runtime_context(_runtime_context(tmp_path))
    try:
        response = await router.chat(
            [ChatMessage(role="user", content=SYNTH_PROMPT)],
            **_chat_kwargs(issuer),
        )
    finally:
        reset_runtime_context(token)
    assert response.content == "ok"
    assert provider.calls == 1
    assert broker.claim_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("action", ["reject", "timeout", "cancel"])
async def test_denied_consent_is_zero_calls(tmp_path: Path, action: str) -> None:
    provider = _SpyProvider()
    router, issuer = _router(tmp_path, provider)
    broker = _FakeBroker(action=action)
    _bind_broker(router, broker)
    token = set_runtime_context(_runtime_context(tmp_path))
    expected: tuple[type[BaseException], ...] = (PermissionError, TimeoutError, asyncio.CancelledError)
    try:
        with pytest.raises(expected):
            await router.chat(
                [ChatMessage(role="user", content=SYNTH_PROMPT)],
                **_chat_kwargs(issuer),
            )
    finally:
        reset_runtime_context(token)
    assert provider.calls == 0
    assert broker.claim_count == 0


# ---------------------------------------------------------------------------
# 3. Retry / fallback / replay
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_retry_fallback_receipts_are_distinct_and_reject_stops(tmp_path: Path) -> None:
    primary = _SpyProvider(name="remote", max_retries=2, fail_times=1)
    fallback = _SpyProvider(name="fallback", base_url="https://fallback.example.test/v1")
    issuer = ModelPermitIssuer()
    settings = JSSettings(workspace=tmp_path, state_dir=tmp_path / "state", providers=[])
    router = ModelRouter(settings, permit_verifier=issuer)
    router.add_provider(
        "remote",
        primary,
        [ModelConfig(id="m1", name="m1", provider="remote", max_tokens=50)],
    )
    router.add_provider(
        "fallback",
        fallback,
        [ModelConfig(id="m2", name="m2", provider="fallback", max_tokens=50)],
    )
    broker = _FakeBroker(actions=["approve", "reject"])
    _bind_broker(router, broker)
    token = set_runtime_context(_runtime_context(tmp_path))
    try:
        with pytest.raises(PermissionError):
            await router.chat(
                [ChatMessage(role="user", content=SYNTH_PROMPT)],
                model=None,
                before_model_call=_noop_before,
                after_model_call=_noop_after,
                permit_grant=_grant(issuer),
            )
    finally:
        reset_runtime_context(token)
    assert primary.calls == 1
    assert fallback.calls == 0
    assert broker.claim_count == 1
    assert len(broker.attempts) == 2
    ids = [getattr(item, "attempt_id", None) for item in broker.attempts]
    assert ids[0] and ids[1] and ids[0] != ids[1]


@pytest.mark.asyncio
async def test_stream_reconnect_uses_fresh_receipt(tmp_path: Path) -> None:
    provider = _SpyProvider(max_retries=2, stream_fail_times=1)
    router, issuer = _router(tmp_path, provider)
    broker = _FakeBroker(action="approve")
    _bind_broker(router, broker)
    token = set_runtime_context(_runtime_context(tmp_path))
    try:
        events = [
            event
            async for event in router.chat_stream_events(
                [ChatMessage(role="user", content=SYNTH_PROMPT)],
                **_chat_kwargs(issuer),
            )
        ]
    finally:
        reset_runtime_context(token)
    assert any(event.kind == "done" for event in events)
    assert provider.stream_calls == 2
    assert broker.claim_count == 2
    assert broker.receipts[0].nonce != broker.receipts[1].nonce
    assert broker.receipts[0].claim_receipt_hash != broker.receipts[1].claim_receipt_hash


@pytest.mark.asyncio
async def test_first_receipt_replay_fails(tmp_path: Path) -> None:
    module = _egress_mod()
    consume = getattr(module, "consume_egress_receipt", None)
    if not callable(consume):
        pytest.fail("consume_egress_receipt is required")
    provider = _SpyProvider()
    router, issuer = _router(tmp_path, provider)
    broker = _FakeBroker(action="approve")
    _bind_broker(router, broker)
    token = set_runtime_context(_runtime_context(tmp_path))
    try:
        await router.chat(
            [ChatMessage(role="user", content=SYNTH_PROMPT)],
            **_chat_kwargs(issuer),
        )
        first = broker.receipts[0]
        with pytest.raises((PermissionError, ModelPermitError)):
            consume(first)
    finally:
        reset_runtime_context(token)
    assert provider.calls == 1


# ---------------------------------------------------------------------------
# 4. Mutation after consent
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_nested_message_and_hook_mutation_sends_approved_snapshot(tmp_path: Path) -> None:
    provider = _SpyProvider()
    router, issuer = _router(tmp_path, provider)
    broker = _FakeBroker(action="approve")
    _bind_broker(router, broker)
    nested = {"note": SYNTH_PROMPT}
    messages = [ChatMessage(role="user", content=[{"type": "text", "text": SYNTH_PROMPT, "extra": nested}])]
    tools = [{"type": "function", "function": {"name": "x", "parameters": {"p": SYNTH_RAW_ARGS}}}]

    async def _mutating_before(
        _decision: Any, hook_messages: list[ChatMessage], hook_tools: Any
    ) -> Any:
        nested["note"] = "MUTATED_AFTER_CONSENT"
        hook_messages.append(ChatMessage(role="user", content="hook-injected"))
        if hook_messages:
            first = hook_messages[0]
            if isinstance(first.content, list):
                first.content.append({"type": "text", "text": "hook-mutated"})
        if isinstance(hook_tools, list):
            hook_tools.append({"type": "function", "function": {"name": "evil"}})
        return None

    token = set_runtime_context(_runtime_context(tmp_path))
    try:
        await router.chat(
            messages,
            **_chat_kwargs(issuer, tools=tools, before_model_call=_mutating_before),
        )
    finally:
        reset_runtime_context(token)
    assert provider.calls == 1
    sent = provider.seen[0]
    assert sent["messages"][0]["content"][0]["extra"]["note"] == SYNTH_PROMPT
    assert len(sent["messages"]) == 1
    assert sent["tools"] is not None
    assert len(sent["tools"]) == 1


@pytest.mark.asyncio
async def test_temperature_and_clamped_max_tokens_are_bound(tmp_path: Path) -> None:
    provider = _SpyProvider()
    router, issuer = _router(tmp_path, provider)
    broker = _FakeBroker(action="approve")
    _bind_broker(router, broker)
    model_cfg = router.get_model_config("m1")
    assert model_cfg is not None

    async def _shrink_cap(*_args: Any, **_kwargs: Any) -> Any:
        model_cfg.max_tokens = 10
        return None

    token = set_runtime_context(_runtime_context(tmp_path))
    try:
        await router.chat(
            [ChatMessage(role="user", content=SYNTH_PROMPT)],
            **_chat_kwargs(
                issuer,
                temperature=0.2,
                max_tokens=999,
                before_model_call=_shrink_cap,
            ),
        )
    finally:
        reset_runtime_context(token)
    assert provider.calls == 1
    assert provider.seen[0]["temperature"] == 0.2
    assert provider.seen[0]["max_tokens"] == 50


@pytest.mark.asyncio
async def test_endpoint_generation_or_identity_change_is_zero_calls(tmp_path: Path) -> None:
    provider = _SpyProvider(generation="gen-1")
    router, issuer = _router(tmp_path, provider)
    broker = _FakeBroker(action="approve")
    _bind_broker(router, broker)

    async def _mutate_endpoint(*_args: Any, **_kwargs: Any) -> Any:
        provider.config.base_url = "https://evil.example.test/v1"
        provider._provider_generation = "gen-2"
        return None

    token = set_runtime_context(_runtime_context(tmp_path))
    try:
        with pytest.raises((PermissionError, ModelPermitError, RuntimeError)):
            await router.chat(
                [ChatMessage(role="user", content=SYNTH_PROMPT)],
                **_chat_kwargs(issuer, before_model_call=_mutate_endpoint),
            )
    finally:
        reset_runtime_context(token)
    assert provider.calls == 0


@pytest.mark.asyncio
async def test_owner_session_run_channel_epoch_change_is_zero_calls(tmp_path: Path) -> None:
    provider = _SpyProvider()
    router, issuer = _router(tmp_path, provider)
    broker = _FakeBroker(action="approve")
    _bind_broker(router, broker)
    token = set_runtime_context(_runtime_context(tmp_path))

    async def _swap_identity(*_args: Any, **_kwargs: Any) -> Any:
        set_runtime_context(
            _runtime_context(
                tmp_path,
                owner_key_hash="owner-b",
                session_id="session-b",
                run_id="run-b",
                channel="other",
            )
        )
        return None

    try:
        with pytest.raises((PermissionError, ModelPermitError, RuntimeError)):
            await router.chat(
                [ChatMessage(role="user", content=SYNTH_PROMPT)],
                **_chat_kwargs(issuer, before_model_call=_swap_identity),
            )
    finally:
        reset_runtime_context(token)
    assert provider.calls == 0


# ---------------------------------------------------------------------------
# 5. Permit bindings
# ---------------------------------------------------------------------------


def test_permit_rejects_cross_owner_and_missing_identity() -> None:
    issuer = ModelPermitIssuer()
    messages = [ChatMessage(role="user", content=SYNTH_PROMPT)]
    permit = issuer.issue(
        provider_name="remote",
        model="m1",
        messages=messages,
        tools=None,
        owner_key_hash="owner-a",
        session_id="session-a",
        run_id="run-a",
        attempt_hash="attempt-a",
        consent_receipt_hash="receipt-a",
        channel="chat",
        provider_generation="gen-1",
        endpoint_digest="endpoint-a",
        attachments_digest="att-a",
        provenance_digest="prov-a",
        temperature=0.2,
        effective_max_tokens=50,
        appshell_epoch="1",
    )
    with pytest.raises(ModelPermitError):
        issuer.verify_and_consume(
            permit,
            provider_name="remote",
            model="m1",
            messages=messages,
            tools=None,
            owner_key_hash="owner-b",
            session_id="session-a",
            run_id="run-a",
            attempt_hash="attempt-a",
            consent_receipt_hash="receipt-a",
            channel="chat",
            provider_generation="gen-1",
            endpoint_digest="endpoint-a",
            attachments_digest="att-a",
            provenance_digest="prov-a",
            temperature=0.2,
            effective_max_tokens=50,
            appshell_epoch="1",
        )
    with pytest.raises(ModelPermitError):
        issuer.verify_and_consume(
            permit,
            provider_name="remote",
            model="m1",
            messages=messages,
            tools=None,
        )


def test_permit_rejects_hash_mismatch_double_consume_and_binds_clamp() -> None:
    issuer = ModelPermitIssuer()
    messages = [ChatMessage(role="user", content=SYNTH_PROMPT)]
    kwargs = {
        "provider_name": "remote",
        "model": "m1",
        "messages": messages,
        "tools": None,
        "owner_key_hash": "owner-a",
        "session_id": "session-a",
        "run_id": "run-a",
        "attempt_hash": "attempt-a",
        "consent_receipt_hash": "receipt-a",
        "channel": "chat",
        "provider_generation": "gen-1",
        "endpoint_digest": "endpoint-a",
        "attachments_digest": "att-a",
        "provenance_digest": "prov-a",
        "temperature": 0.2,
        "effective_max_tokens": 50,
        "appshell_epoch": "1",
    }
    permit = issuer.issue(**kwargs)
    with pytest.raises(ModelPermitError):
        issuer.verify_and_consume(permit, **{**kwargs, "attempt_hash": "other"})
    issuer.verify_and_consume(permit, **kwargs)
    with pytest.raises(ModelPermitError):
        issuer.verify_and_consume(permit, **kwargs)
    mismatch = issuer.issue(**{**kwargs, "effective_max_tokens": 50})
    with pytest.raises(ModelPermitError):
        issuer.verify_and_consume(mismatch, **{**kwargs, "effective_max_tokens": 10})


# ---------------------------------------------------------------------------
# 6. Loopback table
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "needs_consent"),
    [
        ("http://127.0.0.1:1234/v1", False),
        ("http://127.0.0.2:1234/v1", False),
        ("http://[::1]:1234/v1", False),
        ("https://localhost/v1", True),
        ("https://127.1/v1", True),
        ("https://2130706433/v1", True),
        ("https://0x7f000001/v1", True),
        ("https://10.0.0.1/v1", True),
        ("https://192.168.1.8/v1", True),
        ("https://[fd00::1]/v1", True),
    ],
)
@pytest.mark.asyncio
async def test_loopback_table_human_consent(
    tmp_path: Path, url: str, needs_consent: bool
) -> None:
    host = urlparse(url).hostname or ""
    if not needs_consent:
        assert is_canonical_loopback_literal(host)
    else:
        assert not is_canonical_loopback_literal(host)
    provider = _SpyProvider(base_url=url)
    router, issuer = _router(tmp_path, provider)
    broker = _FakeBroker(action="approve")
    _bind_broker(router, broker)
    spent_before = issuer.spent_nonce_count()
    token = set_runtime_context(_runtime_context(tmp_path))
    try:
        await router.chat(
            [ChatMessage(role="user", content=SYNTH_PROMPT)],
            **_chat_kwargs(issuer),
        )
    finally:
        reset_runtime_context(token)
    assert provider.calls == 1
    assert issuer.spent_nonce_count() == spent_before + 1
    if needs_consent:
        assert broker.claim_count == 1
    else:
        assert broker.claim_count == 0


# ---------------------------------------------------------------------------
# 7. Remote embedding
# ---------------------------------------------------------------------------


def test_jsagent_remote_embedding_uses_keyword_and_zero_http(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    http_calls: list[str] = []

    def _forbid_http(*_args: Any, **_kwargs: Any) -> Any:
        http_calls.append("http")
        raise AssertionError("remote embedding HTTP is forbidden")

    monkeypatch.setattr(
        "js.security.net_guard.resolve_and_validate_provider_endpoint",
        _forbid_http,
    )
    monkeypatch.setattr("httpx.Client.post", _forbid_http)
    monkeypatch.setattr("httpx.AsyncClient.post", _forbid_http)
    workspace = tmp_path / "ws"
    state = tmp_path / "state"
    workspace.mkdir()
    settings = JSSettings(
        workspace=workspace,
        state_dir=state,
        providers=[
            ModelProviderConfig(
                name="cloud",
                base_url=REMOTE_URL,
                embedding_model="text-embedding-3-small",
            )
        ],
    )
    agent = JSAgent(settings)
    assert isinstance(agent.memory.embedder, KeywordEmbedder)
    agent.memory.store("semantic-key", "semantic-value")
    agent.memory.search("semantic-value")
    enhanced = getattr(agent.memory, "enhanced", None)
    if enhanced is not None and hasattr(enhanced, "store_semantic"):
        enhanced.store_semantic("semantic-key", "semantic-value", owner_key_hash="owner-a")
        if hasattr(enhanced, "search_semantic"):
            enhanced.search_semantic("semantic-value", owner_key_hash="owner-a")
    recover = getattr(agent.memory.embedder, "force_recover", None)
    if callable(recover):
        recover()
    assert http_calls == []


@pytest.mark.asyncio
async def test_remote_llm_and_provider_embed_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    http_calls: list[str] = []

    def _forbid_http(*_args: Any, **_kwargs: Any) -> Any:
        http_calls.append("http")
        raise AssertionError("remote embedding HTTP is forbidden")

    monkeypatch.setattr(
        "js.security.net_guard.resolve_and_validate_provider_endpoint",
        _forbid_http,
    )
    monkeypatch.setattr("httpx.Client.post", _forbid_http)
    embedder = LLMEmbedder(base_url=REMOTE_URL, api_key=SYNTH_API_KEY)
    with pytest.raises((PermissionError, RuntimeError)):
        embedder.embed("hello")
    from js.models.providers import OpenAICompatibleProvider

    provider = OpenAICompatibleProvider(
        ModelProviderConfig(name="cloud", base_url=REMOTE_URL, embedding_model="emb")
    )
    with pytest.raises((PermissionError, RuntimeError)):
        await provider.embed(["hello"])
    assert http_calls == []


def test_hybrid_recovery_ping_does_not_hit_remote(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    http_calls: list[str] = []

    def _forbid_http(*_args: Any, **_kwargs: Any) -> Any:
        http_calls.append("http")
        raise AssertionError("hidden ping is forbidden")

    monkeypatch.setattr(
        "js.security.net_guard.resolve_and_validate_provider_endpoint",
        _forbid_http,
    )
    monkeypatch.setattr("httpx.Client.post", _forbid_http)
    primary = LLMEmbedder(base_url=REMOTE_URL, api_key=SYNTH_API_KEY)
    hybrid = HybridEmbedder(primary, KeywordEmbedder(), failure_threshold=1, recovery_timeout=0.0)
    hybrid._using_fallback = True
    hybrid._last_failure_time = 0.0
    hybrid._consecutive_failures = 1
    assert hybrid.force_recover() is False
    hybrid.embed("recovery-search")
    assert http_calls == []


def test_literal_loopback_embedding_still_works(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, Any]:
            return {"data": [{"embedding": [0.2, 0.3]}]}

    class _FakeClient:
        def post(self, *_args: Any, **_kwargs: Any) -> _FakeResponse:
            return _FakeResponse()

        def close(self) -> None:
            return None

    monkeypatch.setattr(
        "js.security.net_guard.resolve_and_validate_provider_endpoint",
        lambda *_args, **_kwargs: ("127.0.0.1",),
    )
    embedder = LLMEmbedder(base_url=LOOPBACK_URL, api_key="dummy")
    embedder.client = _FakeClient()  # type: ignore[assignment]
    assert embedder.embed("loopback") == [0.2, 0.3]


# ---------------------------------------------------------------------------
# 8. Privacy
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_approval_echo_logs_have_no_raw_payload(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    module = _egress_mod()
    broker_cls = getattr(module, "ApprovalQueueEgressBroker", None)
    if broker_cls is None:
        pytest.fail("ApprovalQueueEgressBroker is required")
    from js.echo.ledger.service import EchoSafetyService
    from js.security.approvals import wire_echo_approval_authority

    service = EchoSafetyService(state_dir=tmp_path / "echo")
    authority = wire_echo_approval_authority(service, product_id="js-agent")
    queue = ApprovalQueue(
        default_mode=ApprovalMode.AUTO_APPROVE,
        ledger_path=tmp_path / "approvals.jsonl",
    )
    queue.set_echo_authority(authority)

    async def _resolve(request_id: str, _summary: Any) -> ApprovalDecision:
        pending = queue.get_pending_request(request_id, owner_key_hash="owner-a")
        assert pending is not None
        assert pending.tool_name == "model_egress"
        blob = json.dumps(pending.arguments, default=str)
        for needle in PRIVACY_NEEDLES:
            assert needle not in blob
        return queue.decide(
            request_id,
            ApprovalDecisionType.APPROVE,
            owner_key_hash="owner-a",
        )

    provider = _SpyProvider(api_key=SYNTH_API_KEY)
    router, issuer = _router(tmp_path, provider)
    _bind_broker(router, broker_cls(queue, resolver=_resolve))
    caplog.set_level(logging.DEBUG)
    token = set_runtime_context(_runtime_context(tmp_path))
    try:
        await router.chat(
            [ChatMessage(role="user", content=SYNTH_PROMPT)],
            **_chat_kwargs(
                issuer,
                tools=[{"type": "function", "function": {"name": "x", "parameters": {"p": SYNTH_RAW_ARGS}}}],
                attachments=[{"name": SYNTH_ATTACH, "path": SYNTH_PATH}],
            ),
        )
    finally:
        reset_runtime_context(token)
    assert provider.calls == 1
    surfaces: list[str] = []
    if queue._ledger_path is not None and queue._ledger_path.exists():
        surfaces.append(queue._ledger_path.read_text(encoding="utf-8"))
    echo_dir = tmp_path / "echo"
    if echo_dir.exists():
        for path in echo_dir.rglob("*"):
            if path.is_file():
                try:
                    surfaces.append(path.read_text(encoding="utf-8", errors="replace"))
                except OSError:
                    continue
    surfaces.extend(record.getMessage() for record in caplog.records)
    surfaces.append(repr(provider))
    joined = "\n".join(surfaces)
    for needle in PRIVACY_NEEDLES:
        assert needle not in joined
    auto = queue.request_decision(
        "model_egress",
        {"provider": "remote", "model": "m1"},
        context="cron",
        mode=ApprovalMode.AUTO_APPROVE,
        session_id="session-a",
        run_id="run-a",
        owner_key_hash="owner-a",
    )
    assert auto.action is ApprovalDecisionType.REJECT


def test_model_egress_forbids_edit_respond_and_remember(tmp_path: Path) -> None:
    queue = ApprovalQueue(
        default_mode=ApprovalMode.MANUAL,
        ledger_path=tmp_path / "approvals.jsonl",
    )
    pending = queue.request_decision(
        "model_egress",
        {"provider": "remote", "model": "m1", "attempt_kind": "initial"},
        context="web",
        session_id="session-a",
        run_id="run-a",
        owner_key_hash="owner-a",
        queue_if_unhandled=True,
    )
    assert pending.action is ApprovalDecisionType.PENDING
    with pytest.raises((PermissionError, ValueError)):
        queue.decide(
            pending.request_id,
            ApprovalDecisionType.EDIT,
            edited_arguments={"provider": "remote"},
            owner_key_hash="owner-a",
        )
    with pytest.raises((PermissionError, ValueError)):
        queue.decide(
            pending.request_id,
            ApprovalDecisionType.RESPOND,
            response="no",
            owner_key_hash="owner-a",
        )
    remember = getattr(queue, "remember", None)
    if callable(remember):
        with pytest.raises((PermissionError, ValueError)):
            remember(pending.request_id)


# ---------------------------------------------------------------------------
# 9. B1 regression
# ---------------------------------------------------------------------------


def test_b1b_pinned_transport_still_used(monkeypatch: pytest.MonkeyPatch) -> None:
    from js.models.providers import OpenAICompatibleProvider

    captured: list[Any] = []

    class _FakePinned(PinnedTransport):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            captured.append((args, kwargs))
            super().__init__(*args, **kwargs)

    monkeypatch.setattr("js.security.net_guard.PinnedTransport", _FakePinned)
    monkeypatch.setattr("js.models.providers.PinnedTransport", _FakePinned)
    monkeypatch.setattr(
        "js.security.net_guard.resolve_and_validate_provider_endpoint",
        lambda *_args, **_kwargs: ("203.0.113.10",),
    )
    provider = OpenAICompatibleProvider(
        ModelProviderConfig(name="cloud", base_url=REMOTE_URL)
    )
    assert hasattr(provider, "_ensure_client")
    # Construction must remain lazy; the pinned transport type is still the
    # B1B class used when a client is created for a permitted loopback path.
    loopback = OpenAICompatibleProvider(
        ModelProviderConfig(name="local", base_url=LOOPBACK_URL)
    )
    assert loopback._is_local is True


@pytest.mark.asyncio
async def test_b1c_success_scrub_and_provider_retry_cannot_bypass(
    tmp_path: Path,
) -> None:
    provider = _SpyProvider(api_key=SYNTH_API_KEY, max_retries=3, fail_times=0)

    async def _leaky_chat(
        self: _SpyProvider,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> ChatResponse:
        self.calls += 1
        self.seen.append({"content_secret": True})
        return ChatResponse(
            content=f"hello {SYNTH_API_KEY}",
            tool_calls=[],
            model=model,
            usage={"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            finish_reason="stop",
        )

    provider.chat = _leaky_chat.__get__(provider, _SpyProvider)  # type: ignore[method-assign]
    router, issuer = _router(tmp_path, provider)
    broker = _FakeBroker(action="approve")
    _bind_broker(router, broker)
    token = set_runtime_context(_runtime_context(tmp_path))
    try:
        response = await router.chat(
            [ChatMessage(role="user", content=SYNTH_PROMPT)],
            **_chat_kwargs(issuer),
        )
    finally:
        reset_runtime_context(token)
    assert provider.calls == 1
    assert broker.claim_count == 1
    assert SYNTH_API_KEY not in response.content

    retry_provider = _SpyProvider(name="retry", max_retries=3, fail_times=2)
    retry_router, retry_issuer = _router(tmp_path, retry_provider)
    retry_broker = _FakeBroker(action="approve")
    _bind_broker(retry_router, retry_broker)
    token = set_runtime_context(_runtime_context(tmp_path))
    try:
        await retry_router.chat(
            [ChatMessage(role="user", content=SYNTH_PROMPT)],
            **_chat_kwargs(retry_issuer, model="retry/m1"),
        )
    finally:
        reset_runtime_context(token)
    assert retry_provider.calls == 3
    assert retry_broker.claim_count == 3
    assert len({item.nonce for item in retry_broker.receipts}) == 3


@pytest.mark.asyncio
async def test_no_trusted_owner_is_zero_calls(tmp_path: Path) -> None:
    provider = _SpyProvider()
    router, issuer = _router(tmp_path, provider)
    broker = _FakeBroker(action="approve")
    _bind_broker(router, broker)
    with pytest.raises(PermissionError, match="trusted owner required") as raised:
        await router.chat(
            [ChatMessage(role="user", content=SYNTH_PROMPT)],
            **_chat_kwargs(issuer),
        )
    assert "Requested model" not in str(raised.value)
    assert provider.calls == 0


# ---------------------------------------------------------------------------
# 10. Missing/empty endpoint is not a consent exemption
# ---------------------------------------------------------------------------

EVIL_URL = "https://evil.example.test/v1"
_EGRESS_CONSENT_ERROR_MARKERS = (
    "provider endpoint is invalid",
    "egress consent",
    "trusted owner required",
)


def _fake_chat_sdk() -> Any:
    async def _create(**kwargs: Any) -> Any:
        del kwargs
        return SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(
                        content="ok",
                        tool_calls=None,
                        reasoning_content=None,
                    ),
                    finish_reason="stop",
                )
            ],
            usage=None,
            model="m1",
        )

    return SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=_create)))


def _install_transport_spies(monkeypatch: pytest.MonkeyPatch) -> dict[str, list[Any]]:
    captured: dict[str, list[Any]] = {
        "resolver": [],
        "pinned": [],
        "async_client": [],
        "sdk": [],
    }

    def _resolve(url: Any, *args: Any, **kwargs: Any) -> tuple[str, ...]:
        del args, kwargs
        captured["resolver"].append(url)
        return ("203.0.113.10",)

    class _SpyPinned(PinnedTransport):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            captured["pinned"].append((args, kwargs))
            super().__init__(*args, **kwargs)

    class _SpyAsyncClient:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            captured["async_client"].append(kwargs)
            self._transport = kwargs.get("transport")

        async def aclose(self) -> None:
            return None

    def _sdk(**kwargs: Any) -> Any:
        captured["sdk"].append(kwargs.get("base_url"))
        client = _fake_chat_sdk()
        client.base_url = kwargs.get("base_url")
        return client

    monkeypatch.setattr(
        "js.security.net_guard.resolve_and_validate_provider_endpoint",
        _resolve,
    )
    monkeypatch.setattr("js.models.providers.PinnedTransport", _SpyPinned)
    monkeypatch.setattr("js.models.providers.httpx.AsyncClient", _SpyAsyncClient)
    monkeypatch.setattr("js.models.providers.AsyncOpenAI", _sdk)
    return captured


def _assert_no_transport(captured: dict[str, list[Any]]) -> None:
    assert captured["resolver"] == []
    assert captured["pinned"] == []
    assert captured["async_client"] == []
    assert captured["sdk"] == []


def test_classify_closed_set_has_no_none_exemption() -> None:
    module = _egress_mod()
    classify = getattr(module, "classify_provider_endpoint", None)
    if not callable(classify):
        pytest.fail("classify_provider_endpoint is required")
    missing = SimpleNamespace(config=SimpleNamespace())
    empty = _SpyProvider(base_url="")
    blank = _SpyProvider(base_url=" ")
    remote = _SpyProvider(base_url=REMOTE_URL)
    loopback = _SpyProvider(base_url=LOOPBACK_URL)
    assert classify(missing) == "invalid"
    assert classify(empty) == "invalid"
    assert classify(blank) == "invalid"
    assert classify(remote) == "remote"
    assert classify(loopback) == "literal_loopback"
    assert classify(missing) != "none"
    assert classify(empty) != "none"


@pytest.mark.asyncio
async def test_production_provider_hidden_endpoint_is_zero_calls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from js.models.providers import OpenAICompatibleProvider

    captured = _install_transport_spies(monkeypatch)
    sdk_creates = {"count": 0}
    original_create = _fake_chat_sdk().chat.completions.create

    async def _counting_create(**kwargs: Any) -> Any:
        sdk_creates["count"] += 1
        return await original_create(**kwargs)

    provider = OpenAICompatibleProvider(
        ModelProviderConfig(name="cloud", base_url=REMOTE_URL, max_retries=1)
    )
    provider.name = "cloud"
    fake_client = _fake_chat_sdk()
    fake_client.chat.completions.create = _counting_create
    provider.client = fake_client
    provider.config = SimpleNamespace(name="cloud")
    router, issuer = _router(tmp_path, provider)
    broker = _FakeBroker(action="approve")
    _bind_broker(router, broker)
    token = set_runtime_context(_runtime_context(tmp_path))
    try:
        with pytest.raises((PermissionError, RuntimeError, ModelPermitError)) as exc_info:
            await router.chat(
                [ChatMessage(role="user", content=SYNTH_PROMPT)],
                **_chat_kwargs(issuer, model="cloud/m1"),
            )
        with pytest.raises((PermissionError, RuntimeError, ModelPermitError)):
            async for _event in router.chat_stream_events(
                [ChatMessage(role="user", content=SYNTH_PROMPT)],
                **_chat_kwargs(issuer, model="cloud/m1"),
            ):
                pass
    finally:
        reset_runtime_context(token)
    assert any(marker in str(exc_info.value) for marker in _EGRESS_CONSENT_ERROR_MARKERS)
    assert broker.claim_count == 0
    assert sdk_creates["count"] == 0
    _assert_no_transport(captured)


@pytest.mark.parametrize(
    "base_url",
    [
        None,
        "",
        " ",
        "\t",
        123,
        pytest.param(object(), id="non-str-object"),
        "https://",
        "not a url",
        "http://[unclosed",
    ],
)
@pytest.mark.asyncio
async def test_empty_or_malformed_endpoint_is_zero_calls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    base_url: Any,
) -> None:
    captured = _install_transport_spies(monkeypatch)
    provider = _SpyProvider(base_url=base_url)
    router, issuer = _router(tmp_path, provider)
    broker = _FakeBroker(action="approve")
    _bind_broker(router, broker)
    token = set_runtime_context(_runtime_context(tmp_path))
    try:
        with pytest.raises((PermissionError, RuntimeError, ModelPermitError)):
            await router.chat(
                [ChatMessage(role="user", content=SYNTH_PROMPT)],
                **_chat_kwargs(issuer),
            )
    finally:
        reset_runtime_context(token)
    assert provider.calls == 0
    assert broker.claim_count == 0
    _assert_no_transport(captured)


@pytest.mark.asyncio
async def test_custom_provider_without_endpoint_cannot_self_report_local(
    tmp_path: Path,
) -> None:
    class _CustomHidden(ModelProvider):
        def __init__(self) -> None:
            self.name = "custom"
            self.is_local = True
            self.local = True
            self.capability = "memory-only"
            self.remote_sends = 0

        def claims_local(self) -> bool:
            return True

        async def chat(
            self,
            messages: list[ChatMessage],
            model: str,
            tools: list[dict[str, Any]] | None = None,
            temperature: float = 0.7,
            max_tokens: int | None = None,
        ) -> ChatResponse:
            del messages, model, tools, temperature, max_tokens
            self.remote_sends += 1
            return ChatResponse(
                content="sent",
                tool_calls=[],
                model="m1",
                usage={"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
                finish_reason="stop",
            )

        def chat_stream(self, *args: Any, **kwargs: Any) -> Any:
            raise NotImplementedError

        async def health_check(self) -> bool:
            return True

        async def close(self) -> None:
            return None

    provider = _CustomHidden()
    router, issuer = _router(tmp_path, provider)
    broker = _FakeBroker(action="approve")
    _bind_broker(router, broker)
    token = set_runtime_context(_runtime_context(tmp_path))
    try:
        with pytest.raises((PermissionError, RuntimeError, ModelPermitError)):
            await router.chat(
                [ChatMessage(role="user", content=SYNTH_PROMPT)],
                **_chat_kwargs(issuer, model="custom/m1"),
            )
    finally:
        reset_runtime_context(token)
    assert provider.remote_sends == 0
    assert broker.claim_count == 0


@pytest.mark.asyncio
async def test_memory_stub_explicit_loopback_still_binds_permit(tmp_path: Path) -> None:
    provider = _SpyProvider(base_url=LOOPBACK_URL)
    router, issuer = _router(tmp_path, provider)
    broker = _FakeBroker(action="approve")
    _bind_broker(router, broker)
    spent_before = issuer.spent_nonce_count()
    token = set_runtime_context(_runtime_context(tmp_path))
    try:
        await router.chat(
            [ChatMessage(role="user", content=SYNTH_PROMPT)],
            **_chat_kwargs(issuer),
        )
    finally:
        reset_runtime_context(token)
    assert provider.calls == 1
    assert broker.claim_count == 0
    assert issuer.spent_nonce_count() == spent_before + 1
    module = _egress_mod()
    assert getattr(module, "LOOPBACK_EXEMPTION_RECEIPT", None) == "loopback-exemption"


# ---------------------------------------------------------------------------
# 11. Permit-after endpoint TOCTOU
# ---------------------------------------------------------------------------


def _production_provider() -> Any:
    from js.models.providers import OpenAICompatibleProvider

    provider = OpenAICompatibleProvider(
        ModelProviderConfig(name="cloud", base_url=REMOTE_URL, max_retries=1)
    )
    provider.name = "cloud"
    return provider


async def _authorized_production_chat(
    tmp_path: Path,
    provider: Any,
    *,
    model: str = "cloud/m1",
) -> tuple[Any, ModelPermitIssuer, _FakeBroker]:
    router, issuer = _router(tmp_path, provider)
    broker = _FakeBroker(action="approve")
    _bind_broker(router, broker)
    token = set_runtime_context(_runtime_context(tmp_path))
    try:
        await router.chat(
            [ChatMessage(role="user", content=SYNTH_PROMPT)],
            **_chat_kwargs(issuer, model=model),
        )
    finally:
        reset_runtime_context(token)
    return router, issuer, broker


@pytest.mark.asyncio
async def test_post_permit_base_url_mutation_cannot_retarget_transport(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured = _install_transport_spies(monkeypatch)
    provider = _production_provider()
    original_init = provider._initialise_client

    async def _mutate_then_init() -> Any:
        provider.config.base_url = EVIL_URL
        return await original_init()

    provider._initialise_client = _mutate_then_init
    token = set_runtime_context(_runtime_context(tmp_path))
    router, issuer = _router(tmp_path, provider)
    broker = _FakeBroker(action="approve")
    _bind_broker(router, broker)
    try:
        await router.chat(
            [ChatMessage(role="user", content=SYNTH_PROMPT)],
            **_chat_kwargs(issuer, model="cloud/m1"),
        )
    finally:
        reset_runtime_context(token)
    assert EVIL_URL not in captured["resolver"]
    assert EVIL_URL not in captured["sdk"]
    assert all(url != EVIL_URL for url in captured["resolver"])
    assert all(url != EVIL_URL for url in captured["sdk"])
    if captured["resolver"] or captured["sdk"]:
        assert REMOTE_URL in captured["resolver"] or REMOTE_URL in captured["sdk"]


@pytest.mark.asyncio
async def test_post_permit_config_object_replace_cannot_retarget_transport(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured = _install_transport_spies(monkeypatch)
    provider = _production_provider()
    original_init = provider._initialise_client

    async def _replace_then_init() -> Any:
        provider.config = ModelProviderConfig(
            name="cloud",
            base_url=EVIL_URL,
            max_retries=9,
        )
        return await original_init()

    provider._initialise_client = _replace_then_init
    token = set_runtime_context(_runtime_context(tmp_path))
    router, issuer = _router(tmp_path, provider)
    broker = _FakeBroker(action="approve")
    _bind_broker(router, broker)
    try:
        await router.chat(
            [ChatMessage(role="user", content=SYNTH_PROMPT)],
            **_chat_kwargs(issuer, model="cloud/m1"),
        )
    finally:
        reset_runtime_context(token)
    assert EVIL_URL not in captured["resolver"]
    assert EVIL_URL not in captured["sdk"]
    assert getattr(provider, "_max_retries_snapshot", 1) == 1
    if captured["resolver"] or captured["sdk"]:
        assert REMOTE_URL in captured["resolver"] or REMOTE_URL in captured["sdk"]


@pytest.mark.asyncio
async def test_inflight_permit_survives_provider_swap_without_mixing_endpoints(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured = _install_transport_spies(monkeypatch)
    provider = _production_provider()
    evil = _production_provider()
    evil.config.base_url = EVIL_URL
    original_init = provider._initialise_client
    router, issuer = _router(tmp_path, provider)
    broker = _FakeBroker(action="approve")
    _bind_broker(router, broker)

    async def _swap_then_init() -> Any:
        router.add_provider(
            "cloud",
            evil,
            [ModelConfig(id="m1", name="m1", provider="cloud", max_tokens=50)],
        )
        provider.config.base_url = EVIL_URL
        return await original_init()

    provider._initialise_client = _swap_then_init
    token = set_runtime_context(_runtime_context(tmp_path))
    try:
        await router.chat(
            [ChatMessage(role="user", content=SYNTH_PROMPT)],
            **_chat_kwargs(issuer, model="cloud/m1"),
        )
    finally:
        reset_runtime_context(token)
    assert EVIL_URL not in captured["resolver"]
    assert EVIL_URL not in captured["sdk"]
    assert getattr(evil, "client", None) is None


@pytest.mark.asyncio
async def test_lazy_client_after_permit_uses_approved_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured = _install_transport_spies(monkeypatch)
    provider = _production_provider()
    assert provider.client is None
    original_init = provider._initialise_client

    async def _mutate_then_init() -> Any:
        provider.config.base_url = EVIL_URL
        return await original_init()

    provider._initialise_client = _mutate_then_init
    token = set_runtime_context(_runtime_context(tmp_path))
    router, issuer = _router(tmp_path, provider)
    broker = _FakeBroker(action="approve")
    _bind_broker(router, broker)
    try:
        await router.chat(
            [ChatMessage(role="user", content=SYNTH_PROMPT)],
            **_chat_kwargs(issuer, model="cloud/m1"),
        )
    finally:
        reset_runtime_context(token)
    assert provider.client is not None or captured["resolver"] == []
    assert EVIL_URL not in captured["resolver"]
    assert EVIL_URL not in captured["sdk"]


@pytest.mark.asyncio
async def test_existing_client_config_change_cannot_reuse_receipt_for_new_endpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _egress_mod()
    digest = module.endpoint_digest
    captured = _install_transport_spies(monkeypatch)
    provider = _production_provider()
    router, issuer, broker = await _authorized_production_chat(tmp_path, provider)
    assert provider.client is not None
    first_receipt = broker.receipts[0]
    provider.config.base_url = EVIL_URL
    second_failed = False
    token = set_runtime_context(_runtime_context(tmp_path))
    try:
        try:
            await router.chat(
                [ChatMessage(role="user", content=SYNTH_PROMPT)],
                **_chat_kwargs(issuer, model="cloud/m1"),
            )
        except (PermissionError, RuntimeError, ModelPermitError):
            second_failed = True
    finally:
        reset_runtime_context(token)
    original_digest = digest(REMOTE_URL)
    evil_digest = digest(EVIL_URL)
    assert all(attempt.endpoint_digest != evil_digest for attempt in broker.attempts)
    assert EVIL_URL not in captured["resolver"]
    assert EVIL_URL not in captured["sdk"]
    if second_failed:
        assert broker.claim_count == 1
        assert first_receipt.attempt_hash == broker.receipts[0].attempt_hash
    else:
        assert all(attempt.endpoint_digest == original_digest for attempt in broker.attempts)
        assert broker.claim_count == 2
        assert first_receipt.attempt_hash != broker.receipts[-1].attempt_hash


# ---------------------------------------------------------------------------
# 12. Permanent RED/oracle: identity, cancel, stream close, anti-false-green
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_background_missing_session_remote_is_zero_calls(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    state = tmp_path / "state"
    workspace.mkdir()
    agent = JSAgent(JSSettings(workspace=workspace, state_dir=state, providers=[]))
    provider = _SpyProvider(name="remote")
    agent.router.add_provider(
        "remote",
        provider,
        [ModelConfig(id="m1", name="m1", provider="remote")],
    )
    with pytest.raises((PermissionError, RuntimeError, ModelPermitError)):
        await agent.authorized_model_chat(
            [ChatMessage(role="user", content=SYNTH_PROMPT)],
            tenant_id="owner-a",
            run_id="background-run",
            model="remote/m1",
        )
    assert provider.calls == 0
    assert classify_provider_endpoint(provider) == "remote"


@pytest.mark.asyncio
async def test_background_missing_broker_remote_is_zero_calls(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    state = tmp_path / "state"
    workspace.mkdir()
    settings = JSSettings(workspace=workspace, state_dir=state, providers=[])
    agent = JSAgent(settings)
    provider = _SpyProvider(name="remote")
    router = ModelRouter(settings, permit_verifier=agent._model_permit_issuer)
    router.add_provider(
        "remote",
        provider,
        [ModelConfig(id="m1", name="m1", provider="remote")],
    )
    agent.router = router
    with pytest.raises((PermissionError, RuntimeError, ModelPermitError)):
        await agent.authorized_model_chat(
            [ChatMessage(role="user", content=SYNTH_PROMPT)],
            tenant_id="owner-a",
            session_id="background-session",
            run_id="background-run",
            model="remote/m1",
        )
    assert provider.calls == 0
    assert classify_provider_endpoint(provider) == "remote"


@pytest.mark.asyncio
async def test_background_trusted_context_and_manual_broker_is_one_call(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "ws"
    state = tmp_path / "state"
    workspace.mkdir()
    settings = JSSettings(workspace=workspace, state_dir=state, providers=[])
    agent = JSAgent(settings)
    provider = _SpyProvider(name="remote")
    router = ModelRouter(settings, permit_verifier=agent._model_permit_issuer)
    router.add_provider(
        "remote",
        provider,
        [ModelConfig(id="m1", name="m1", provider="remote")],
    )
    broker = _FakeBroker(action="approve")
    _bind_broker(router, broker)
    agent.router = router
    spent_before = agent._model_permit_issuer.spent_nonce_count()
    response = await agent.authorized_model_chat(
        [ChatMessage(role="user", content=SYNTH_PROMPT)],
        tenant_id="owner-a",
        session_id="background-session",
        run_id="background-run",
        model="remote/m1",
    )
    assert response.content == "ok"
    assert provider.calls == 1
    assert broker.claim_count == 1
    assert classify_provider_endpoint(provider) == "remote"
    assert agent._model_permit_issuer.spent_nonce_count() == spent_before + 1


@pytest.mark.asyncio
async def test_stream_missing_context_remote_is_zero_calls(tmp_path: Path) -> None:
    provider = _SpyProvider()
    router, issuer = _router(tmp_path, provider)
    broker = _FakeBroker(action="approve")
    _bind_broker(router, broker)
    with pytest.raises((PermissionError, RuntimeError, ModelPermitError)):
        async for _event in router.chat_stream_events(
            [ChatMessage(role="user", content=SYNTH_PROMPT)],
            **_chat_kwargs(issuer),
        ):
            pass
    assert provider.stream_calls == 0
    assert provider.calls == 0
    assert broker.claim_count == 0
    assert classify_provider_endpoint(provider) == "remote"


@pytest.mark.asyncio
async def test_stream_trusted_context_and_manual_broker_is_one_transport(
    tmp_path: Path,
) -> None:
    provider = _SpyProvider()
    router, issuer = _router(tmp_path, provider)
    broker = _FakeBroker(action="approve")
    _bind_broker(router, broker)
    spent_before = issuer.spent_nonce_count()
    token = set_runtime_context(_runtime_context(tmp_path))
    try:
        events = [
            event
            async for event in router.chat_stream_events(
                [ChatMessage(role="user", content=SYNTH_PROMPT)],
                **_chat_kwargs(issuer),
            )
        ]
    finally:
        reset_runtime_context(token)
    assert [event.kind for event in events if event.kind != "usage"]
    assert provider.stream_calls == 1
    assert broker.claim_count == 1
    assert classify_provider_endpoint(provider) == "remote"
    assert issuer.spent_nonce_count() == spent_before + 1


@pytest.mark.asyncio
@pytest.mark.parametrize("owner", ["local", "local-user", ""])
async def test_synthetic_owner_cannot_auto_approve_remote(
    tmp_path: Path, owner: str
) -> None:
    provider = _SpyProvider()
    router, issuer = _router(tmp_path, provider)
    token = set_runtime_context(_runtime_context(tmp_path, owner_key_hash=owner))
    try:
        with pytest.raises((PermissionError, RuntimeError, ModelPermitError)):
            await router.chat(
                [ChatMessage(role="user", content=SYNTH_PROMPT)],
                **_chat_kwargs(issuer, permit_grant=_grant(issuer, owner=owner or "owner-a")),
            )
    finally:
        reset_runtime_context(token)
    assert provider.calls == 0
    assert classify_provider_endpoint(provider) == "remote"


@pytest.mark.asyncio
async def test_cancel_before_permit_is_zero_calls(tmp_path: Path) -> None:
    provider = _SpyProvider(base_url=LOOPBACK_URL)
    router, issuer = _router(tmp_path, provider)
    cancel = asyncio.Event()
    cancel.set()
    spent_before = issuer.spent_nonce_count()
    token = set_runtime_context(_runtime_context(tmp_path, cancel_token=cancel))
    try:
        with pytest.raises(asyncio.CancelledError):
            await router.chat(
                [ChatMessage(role="user", content=SYNTH_PROMPT)],
                **_chat_kwargs(issuer, model="remote/m1"),
            )
    finally:
        reset_runtime_context(token)
    assert provider.calls == 0
    assert issuer.spent_nonce_count() == spent_before


@pytest.mark.asyncio
async def test_cancel_after_permit_before_transport_is_zero_calls(tmp_path: Path) -> None:
    provider = _SpyProvider(base_url=LOOPBACK_URL)
    router, issuer = _router(tmp_path, provider)
    cancel = asyncio.Event()
    original = issuer.verify_and_consume

    def _consume_then_cancel(*args: Any, **kwargs: Any) -> None:
        original(*args, **kwargs)
        cancel.set()

    issuer.verify_and_consume = _consume_then_cancel  # type: ignore[method-assign]
    spent_before = issuer.spent_nonce_count()
    token = set_runtime_context(_runtime_context(tmp_path, cancel_token=cancel))
    try:
        with pytest.raises(asyncio.CancelledError):
            await router.chat(
                [ChatMessage(role="user", content=SYNTH_PROMPT)],
                **_chat_kwargs(issuer, model="remote/m1"),
            )
    finally:
        reset_runtime_context(token)
    assert provider.calls == 0
    assert issuer.spent_nonce_count() == spent_before + 1


@pytest.mark.asyncio
async def test_stream_generator_close_does_not_start_next_attempt(tmp_path: Path) -> None:
    provider = _SpyProvider()
    fallback = _SpyProvider(name="fallback", base_url="https://fallback.example.test/v1")
    router, issuer = _router(tmp_path, provider, extra_providers=[fallback])
    broker = _FakeBroker(action="approve")
    _bind_broker(router, broker)
    token = set_runtime_context(_runtime_context(tmp_path))
    try:
        stream = router.chat_stream_events(
            [ChatMessage(role="user", content=SYNTH_PROMPT)],
            **_chat_kwargs(issuer),
        )
        first = await anext(stream)
        await stream.aclose()
    finally:
        reset_runtime_context(token)
    assert first.kind in {"text_delta", "done", "usage"}
    assert provider.stream_calls == 1
    assert fallback.stream_calls == 0
    assert broker.claim_count == 1
    assert classify_provider_endpoint(provider) == "remote"


@pytest.mark.asyncio
async def test_anti_false_green_runtime_context_removal_fails(tmp_path: Path) -> None:
    provider = _SpyProvider(base_url=LOOPBACK_URL)
    router, issuer = _router(tmp_path, provider)
    with pytest.raises(PermissionError, match="trusted owner required") as raised:
        await router.chat(
            [ChatMessage(role="user", content=SYNTH_PROMPT)],
            **_chat_kwargs(issuer, model="remote/m1"),
        )
    assert "Requested model" not in str(raised.value)
    assert provider.calls == 0


@pytest.mark.asyncio
async def test_anti_false_green_permit_skip_is_detected(tmp_path: Path) -> None:
    provider = _SpyProvider(base_url=LOOPBACK_URL)
    router, issuer = _router(tmp_path, provider)
    spent_before = issuer.spent_nonce_count()
    token = set_runtime_context(_runtime_context(tmp_path))
    try:
        await router.chat(
            [ChatMessage(role="user", content=SYNTH_PROMPT)],
            **_chat_kwargs(issuer, model="remote/m1"),
        )
    finally:
        reset_runtime_context(token)
    assert provider.calls == 1
    assert issuer.spent_nonce_count() == spent_before + 1


@pytest.mark.asyncio
async def test_anti_false_green_missing_identity_is_not_requested_model_wrap(
    tmp_path: Path,
) -> None:
    provider = _SpyProvider(base_url=REMOTE_URL)
    router, issuer = _router(tmp_path, provider)
    broker = _FakeBroker(action="approve")
    _bind_broker(router, broker)
    with pytest.raises(PermissionError, match="trusted owner required") as raised:
        await router.chat(
            [ChatMessage(role="user", content=SYNTH_PROMPT)],
            **_chat_kwargs(issuer, model="remote/m1"),
        )
    assert "Requested model" not in str(raised.value)
    assert not isinstance(raised.value, RuntimeError)
    assert provider.calls == 0
    assert broker.claim_count == 0


def test_anti_false_green_remote_consent_rejects_loopback_substitution() -> None:
    provider = _SpyProvider(base_url=REMOTE_URL)
    parsed = urlparse(REMOTE_URL)
    assert parsed.scheme == "https"
    assert not is_canonical_loopback_literal(parsed.hostname or "")
    assert classify_provider_endpoint(provider) == "remote"
    loopback = _SpyProvider(base_url=LOOPBACK_URL)
    assert classify_provider_endpoint(loopback) == "literal_loopback"
    assert classify_provider_endpoint(provider) != classify_provider_endpoint(loopback)


def classify_provider_endpoint(provider: Any) -> str:
    module = _egress_mod()
    classify = getattr(module, "classify_provider_endpoint", None)
    if not callable(classify):
        pytest.fail("classify_provider_endpoint is required")
    return str(classify(provider))
