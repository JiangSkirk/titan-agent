"""ModelRouter.chat must reject calls without a valid runtime-issued permit.

Historically the router accepted a callback pair "bound" via the public,
repeatable ``bind_echo_callbacks`` API, which allowed an attacker to rebind
forged callbacks and bypass Echo (P0-1).  The gate is now an unforgeable,
single-use :class:`~js.models.permit.ModelPermit` issued per provider
attempt by the runtime-owned issuer; callback identity plays no role.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from js.config import JSSettings
from js.models.permit import ModelPermitError, ModelPermitIssuer
from js.models.providers import ChatMessage, ChatResponse, ModelProvider
from js.models.router import ModelRouter


@pytest.fixture(autouse=True)
def _b2b_stub_identity(tmp_path: Path) -> Any:
    from js.echo.turn_context import RuntimeContext, reset_runtime_context, set_runtime_context

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
    yield
    reset_runtime_context(token)


class _StubProvider(ModelProvider):
    def __init__(self, name: str = "stub") -> None:
        self.name = name
        self.calls = 0
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
        self.calls += 1
        return ChatResponse(
            content="stub",
            tool_calls=[],
            model=model,
            usage={"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            finish_reason="stop",
        )

    def chat_stream(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> Any:  # pragma: no cover - not exercised
        raise NotImplementedError

    async def health_check(self) -> bool:
        return True

    async def close(self) -> None:
        return None


def _router_with_stub_provider(issuer: ModelPermitIssuer | None = None) -> ModelRouter:
    settings = JSSettings(workspace=__import__("pathlib").Path("/tmp/x"), providers=[])
    router = ModelRouter(settings, permit_verifier=issuer)
    from js.config import ModelConfig

    provider = _StubProvider()
    router.add_provider(
        "stub",
        provider,
        [ModelConfig(id="m1", name="m1", provider="stub")],
    )
    return router


def _grant(issuer: ModelPermitIssuer):
    def grant(decision: Any, messages: list[ChatMessage], tools: Any) -> Any:
        return issuer.issue(
            provider_name=decision.provider_name,
            model=decision.model,
            messages=messages,
            tools=tools,
            owner_key_hash="owner",
            session_id="session",
            run_id="run",
        )

    return grant


@pytest.mark.asyncio
async def test_router_chat_rejects_missing_permit_grant() -> None:
    """Callbacks alone are not authorization; the permit grant is mandatory."""
    issuer = ModelPermitIssuer()
    router = _router_with_stub_provider(issuer)

    async def _fake_before(*_args: Any, **_kw: Any) -> Any:
        return None

    async def _fake_after(*_args: Any, **_kw: Any) -> None:
        return None

    with pytest.raises(RuntimeError, match="permit_grant"):
        await router.chat(
            [ChatMessage(role="user", content="hi")],
            model="stub/m1",
            before_model_call=_fake_before,
            after_model_call=_fake_after,
        )


@pytest.mark.asyncio
async def test_router_chat_accepts_valid_permit() -> None:
    """A genuine runtime-issued permit authorizes exactly one attempt."""
    issuer = ModelPermitIssuer()
    router = _router_with_stub_provider(issuer)

    async def _real_before(*_args: Any, **_kw: Any) -> Any:
        return "ctx"

    async def _real_after(*_args: Any, **_kw: Any) -> None:
        return None

    resp = await router.chat(
        [ChatMessage(role="user", content="hi")],
        model="stub/m1",
        before_model_call=_real_before,
        after_model_call=_real_after,
        permit_grant=_grant(issuer),
    )
    assert resp.content == "stub"


class _RecordingGrant:
    def __init__(self, delegate: Any) -> None:
        self.calls = 0
        self._delegate = delegate

    def __call__(self, decision: Any, messages: list[ChatMessage], tools: Any) -> Any:
        self.calls += 1
        return self._delegate(decision, messages, tools)


@pytest.mark.asyncio
async def test_untrusted_external_permit_grant_is_ignored_and_runtime_issues_bound_permit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Caller grant is ignored; the live router issuer binds and spends a new permit."""
    issuer = ModelPermitIssuer()
    attacker = ModelPermitIssuer()
    router = _router_with_stub_provider(issuer)
    provider = router._providers["stub"]
    issued: list[Any] = []
    real = issuer.issue

    def _spy_issue(**kwargs: Any) -> Any:
        permit = real(**kwargs)
        issued.append(permit)
        return permit

    monkeypatch.setattr(issuer, "issue", _spy_issue)
    external = _RecordingGrant(_grant(attacker))

    async def _before(*_args: Any, **_kw: Any) -> Any:
        return None

    async def _after(*_args: Any, **_kw: Any) -> None:
        return None

    spent_before = issuer.spent_nonce_count()
    resp = await router.chat(
        [ChatMessage(role="user", content="hi")],
        model="stub/m1",
        before_model_call=_before,
        after_model_call=_after,
        permit_grant=external,
    )
    assert resp.content == "stub"
    assert external.calls == 0
    assert attacker.spent_nonce_count() == 0
    assert len(issued) == 1
    assert issued[0].attempt_hash
    assert issuer.spent_nonce_count() == spent_before + 1
    assert provider.calls == 1


@pytest.mark.asyncio
async def test_router_without_verifier_fails_closed() -> None:
    """A router never wired to the Echo runtime cannot call providers at all."""
    router = _router_with_stub_provider(None)

    async def _before(*_args: Any, **_kw: Any) -> Any:
        return None

    async def _after(*_args: Any, **_kw: Any) -> None:
        return None

    issuer = ModelPermitIssuer()
    with pytest.raises(ModelPermitError):
        await router.chat(
            [ChatMessage(role="user", content="hi")],
            model="stub/m1",
            before_model_call=_before,
            after_model_call=_after,
            permit_grant=_grant(issuer),
        )
