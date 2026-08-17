"""Round 8.1 A: non-error stream events must use trusted routing identity."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from js.config import JSSettings, ModelConfig, ModelProviderConfig
from js.echo.turn_context import (
    RuntimeContext,
    current_runtime_context,
    reset_runtime_context,
    set_runtime_context,
)
from js.models.permit import ModelPermitIssuer
from js.models.providers import ChatMessage, ChatResponse
from js.models.router import ModelRouter
from js.models.stream_events import StreamEvent
from js.security.egress import (
    EgressConsentError,
    EgressConsentReceiptV1,
    classify_provider_endpoint,
    consume_egress_receipt,
)

_SECRET = "1234567890123456"
_MODEL = ModelConfig(id="trusted-model", name="Trusted", context_window=4096)


def _echo_hooks(router: ModelRouter) -> tuple[Any, Any, Any]:
    async def _before(decision: Any, _messages: Any, _tools: Any) -> str:
        return decision.provider_name

    async def _after(
        _context: Any,
        _response: ChatResponse | None,
        _error: BaseException | None,
    ) -> None:
        return None

    issuer = router._permit_verifier
    assert isinstance(issuer, ModelPermitIssuer)

    def _grant(decision: Any, messages: list[ChatMessage], tools: Any) -> Any:
        return issuer.issue(
            provider_name=decision.provider_name,
            model=decision.model,
            messages=messages,
            tools=tools,
            owner_key_hash="owner",
            session_id="session",
            run_id="run",
        )

    return _before, _after, _grant


@pytest.mark.asyncio
async def test_stream_events_force_trusted_provider_model_and_meta_allowlist(
    tmp_path: Path,
) -> None:
    settings = JSSettings(workspace=tmp_path / "ws", state_dir=tmp_path / "state")
    router = ModelRouter(settings, permit_verifier=ModelPermitIssuer())

    class _ForgedIdentityProvider:
        config = ModelProviderConfig(
            name="trusted-provider",
            base_url="https://example.test/v1",
            api_key=_SECRET,
            auth_adapter="query_param",
            query_param_name="api_key",
            default_model="trusted-model",
            models=[_MODEL],
        )

        async def chat_stream_events(self, **_kwargs: Any) -> Any:
            yield StreamEvent(
                kind="text_delta",
                text="hello",
                provider="forged-provider",
                model="forged-model",
                meta={"api_key": _SECRET, "raw": "drop-me"},
            )
            yield StreamEvent(
                kind="thinking_delta",
                text="think",
                provider="forged-provider",
                model="forged-model",
                meta={"secret": _SECRET},
            )
            yield StreamEvent(
                kind="tool_call_delta",
                tool_call={
                    "index": 0,
                    "id": "c1",
                    "name": "noop",
                    "arguments_delta": "{}",
                },
                provider="evil",
                model="evil-model",
                meta={"token": _SECRET},
            )
            yield StreamEvent(
                kind="done",
                finish_reason="stop",
                provider="forged-provider",
                model="forged-model",
                meta={"leak": _SECRET},
            )

        async def health_check(self) -> bool:
            return True

        async def close(self) -> None:
            return None

    provider = _ForgedIdentityProvider()
    router.add_provider("trusted-provider", provider, [_MODEL])  # type: ignore[arg-type]
    assert classify_provider_endpoint(provider) == "remote"

    class _ManualBroker:
        claim_count = 0

        async def request_and_claim(self, attempt: Any, _summary: Any) -> EgressConsentReceiptV1:
            self.claim_count += 1
            return EgressConsentReceiptV1(
                attempt_hash=attempt.attempt_hash,
                claim_receipt_hash=f"claim-{self.claim_count}",
                expires_at=8_000_000_000.0,
                nonce=f"nonce-{self.claim_count}",
            )

    broker = _ManualBroker()
    router.bind_egress_consent_broker(broker)
    issuer = router._permit_verifier
    assert isinstance(issuer, ModelPermitIssuer)
    spent_before = issuer.spent_nonce_count()
    before, after, grant = _echo_hooks(router)
    token = set_runtime_context(
        RuntimeContext(
            product_id="js-agent",
            channel="chat",
            owner_key_hash="owner",
            session_id="session",
            run_id="run",
            role="user",
            profile="default",
            capabilities=(),
            workspace=tmp_path,
            state_dir=tmp_path,
        )
    )
    try:
        events = [
            event
            async for event in router.chat_stream_events(
                [ChatMessage(role="user", content="hi")],
                model="trusted-model",
                before_model_call=before,
                after_model_call=after,
                permit_grant=grant,
            )
        ]
    finally:
        reset_runtime_context(token)
    assert broker.claim_count == 1
    assert issuer.spent_nonce_count() == spent_before + 1
    assert classify_provider_endpoint(provider) == "remote"
    kinds = [event.kind for event in events]
    assert kinds == ["text_delta", "thinking_delta", "tool_call_delta", "done"]
    for event in events:
        assert event.provider == "trusted-provider"
        assert event.model == "trusted-model"
        assert _SECRET not in repr(event)
        assert _SECRET not in str(event.meta)
        assert "api_key" not in event.meta
        assert "secret" not in event.meta
        assert "token" not in event.meta
        assert "leak" not in event.meta
        assert "raw" not in event.meta
    assert events[0].text == "hello"
    assert events[1].text == "think"
    assert events[2].tool_call is not None
    assert events[2].tool_call.get("name") == "noop"
    assert events[3].finish_reason == "stop"


class _ManualBroker:
    def __init__(self) -> None:
        self.claim_count = 0
        self.receipts: list[EgressConsentReceiptV1] = []
        self.replay: EgressConsentReceiptV1 | None = None

    async def request_and_claim(self, attempt: Any, _summary: Any) -> EgressConsentReceiptV1:
        self.claim_count += 1
        if self.replay is not None:
            return self.replay
        receipt = EgressConsentReceiptV1(
            attempt_hash=attempt.attempt_hash,
            claim_receipt_hash=f"claim-{self.claim_count}",
            expires_at=8_000_000_000.0,
            nonce=f"nonce-{self.claim_count}",
        )
        self.receipts.append(receipt)
        return receipt


class _ZeroCallRemoteProvider:
    """Remote HTTPS spy. Transport/DNS/SDK counters stay 0 unless entered."""

    def __init__(self) -> None:
        self.config = ModelProviderConfig(
            name="trusted-provider",
            base_url="https://example.test/v1",
            api_key=_SECRET,
            auth_adapter="query_param",
            query_param_name="api_key",
            default_model="trusted-model",
            models=[_MODEL],
        )
        self.stream_calls = 0
        self.chat_calls = 0
        self.dns_lookups = 0
        self.client_constructed = 0
        self.sdk_calls = 0

    async def chat(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> ChatResponse:
        self.chat_calls += 1
        self.sdk_calls += 1
        self.dns_lookups += 1
        self.client_constructed += 1
        return ChatResponse(
            content="hello",
            tool_calls=[],
            model=model,
            usage={"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            finish_reason="stop",
        )

    async def chat_stream_events(self, **_kwargs: Any) -> Any:
        self.stream_calls += 1
        self.sdk_calls += 1
        self.dns_lookups += 1
        self.client_constructed += 1
        yield StreamEvent(kind="text_delta", text="hello")
        yield StreamEvent(kind="done", finish_reason="stop")

    async def health_check(self) -> bool:
        return True

    async def close(self) -> None:
        return None


def _identity_context(tmp_path: Path) -> RuntimeContext:
    return RuntimeContext(
        product_id="js-agent",
        channel="chat",
        owner_key_hash="owner",
        session_id="session",
        run_id="run",
        role="user",
        profile="default",
        capabilities=(),
        workspace=tmp_path,
        state_dir=tmp_path,
    )


def _swap_only(field: str, value: str) -> Any:
    async def _before(_decision: Any, _messages: Any, _tools: Any) -> None:
        current = current_runtime_context()
        assert current is not None
        assert current.owner_key_hash == "owner"
        assert current.channel == "chat"
        if field == "session_id":
            assert current.run_id == "run"
            set_runtime_context(replace(current, session_id=value))
        else:
            assert current.session_id == "session"
            set_runtime_context(replace(current, run_id=value))
        swapped = current_runtime_context()
        assert swapped is not None
        assert swapped.owner_key_hash == "owner"
        assert swapped.channel == "chat"
        if field == "session_id":
            assert swapped.session_id == value
            assert swapped.run_id == "run"
        else:
            assert swapped.run_id == value
            assert swapped.session_id == "session"
        return None

    return _before


@pytest.mark.parametrize(
    ("field", "value"),
    [("session_id", "session-alt"), ("run_id", "run-alt")],
    ids=["session_id_only", "run_id_only"],
)
@pytest.mark.asyncio
async def test_stream_before_hook_identity_field_change_is_zero_calls(
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    settings = JSSettings(workspace=tmp_path / "ws", state_dir=tmp_path / "state")
    router = ModelRouter(settings, permit_verifier=ModelPermitIssuer())
    provider = _ZeroCallRemoteProvider()
    router.add_provider("trusted-provider", provider, [_MODEL])  # type: ignore[arg-type]
    assert classify_provider_endpoint(provider) == "remote"
    broker = _ManualBroker()
    router.bind_egress_consent_broker(broker)
    _ignored_before, after, grant = _echo_hooks(router)
    del _ignored_before
    token = set_runtime_context(_identity_context(tmp_path))
    events: list[StreamEvent] = []
    try:
        with pytest.raises(EgressConsentError, match="egress identity changed after consent"):
            async for event in router.chat_stream_events(
                [ChatMessage(role="user", content="hi")],
                model="trusted-model",
                before_model_call=_swap_only(field, value),
                after_model_call=after,
                permit_grant=grant,
            ):
                events.append(event)
        assert classify_provider_endpoint(provider) == "remote"
        assert broker.claim_count == 1
        assert provider.stream_calls == 0
        assert provider.chat_calls == 0
        assert provider.dns_lookups == 0
        assert provider.client_constructed == 0
        assert provider.sdk_calls == 0
        assert events == []
        assert broker.receipts
        with pytest.raises(EgressConsentError, match="replayed"):
            consume_egress_receipt(broker.receipts[0])
        set_runtime_context(_identity_context(tmp_path))
        broker.replay = broker.receipts[0]
        replay_before, replay_after, replay_grant = _echo_hooks(router)
        with pytest.raises(EgressConsentError):
            async for event in router.chat_stream_events(
                [ChatMessage(role="user", content="hi")],
                model="trusted-model",
                before_model_call=replay_before,
                after_model_call=replay_after,
                permit_grant=replay_grant,
            ):
                events.append(event)
        assert provider.stream_calls == 0
        assert provider.chat_calls == 0
        assert provider.sdk_calls == 0
        assert events == []
        assert classify_provider_endpoint(provider) == "remote"
    finally:
        reset_runtime_context(token)


@pytest.mark.parametrize(
    ("field", "value"),
    [("session_id", "session-alt"), ("run_id", "run-alt")],
    ids=["session_id_only", "run_id_only"],
)
@pytest.mark.asyncio
async def test_chat_before_hook_identity_field_change_is_zero_calls(
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    settings = JSSettings(workspace=tmp_path / "ws", state_dir=tmp_path / "state")
    router = ModelRouter(settings, permit_verifier=ModelPermitIssuer())
    provider = _ZeroCallRemoteProvider()
    router.add_provider("trusted-provider", provider, [_MODEL])  # type: ignore[arg-type]
    assert classify_provider_endpoint(provider) == "remote"
    broker = _ManualBroker()
    router.bind_egress_consent_broker(broker)
    _before, after, grant = _echo_hooks(router)
    token = set_runtime_context(_identity_context(tmp_path))
    try:
        with pytest.raises(EgressConsentError, match="egress identity changed after consent"):
            await router.chat(
                [ChatMessage(role="user", content="hi")],
                model="trusted-model",
                before_model_call=_swap_only(field, value),
                after_model_call=after,
                permit_grant=grant,
            )
        assert classify_provider_endpoint(provider) == "remote"
        assert broker.claim_count == 1
        assert provider.chat_calls == 0
        assert provider.stream_calls == 0
        assert provider.dns_lookups == 0
        assert provider.client_constructed == 0
        assert provider.sdk_calls == 0
        assert broker.receipts
        with pytest.raises(EgressConsentError, match="replayed"):
            consume_egress_receipt(broker.receipts[0])
        set_runtime_context(_identity_context(tmp_path))
        broker.replay = broker.receipts[0]
        with pytest.raises(EgressConsentError):
            await router.chat(
                [ChatMessage(role="user", content="hi")],
                model="trusted-model",
                before_model_call=_before,
                after_model_call=after,
                permit_grant=grant,
            )
        assert provider.chat_calls == 0
        assert provider.stream_calls == 0
        assert provider.sdk_calls == 0
        assert classify_provider_endpoint(provider) == "remote"
    finally:
        reset_runtime_context(token)
