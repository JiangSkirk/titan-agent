from __future__ import annotations

import asyncio
import base64
import json
import logging
import re
from collections.abc import AsyncIterator
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import quote, quote_plus

import pytest

import js.models.router as router_module
from js.config import JSSettings, ModelConfig, ModelProviderConfig
from js.echo.durable_thread import EchoDurableExecutor, claim_to_thread, durable_to_thread
from js.echo.ledger.service import EchoUnavailableError
from js.models.permit import ModelPermitIssuer
from js.models.providers import (
    ChatMessage,
    ChatResponse,
    ModelProvider,
    OpenAICompatibleProvider,
)
from js.models.router import ModelRouter
from js.models.stream_events import StreamEvent
from js.security.secrets import (
    ProviderSecretScrubber,
    ProviderSecretScrubError,
    SecretManager,
)

_SECRET = 'B1C key +/="\\éî-safe-42'
_MODEL = ModelConfig(id="safe-model", name="Safe model")


def _percent_lower(value: str) -> str:
    return re.sub(r"%[0-9A-Fa-f]{2}", lambda match: match.group(0).lower(), value)


def _percent_mixed(value: str) -> str:
    counter = 0

    def rewrite(match: re.Match[str]) -> str:
        nonlocal counter
        rewritten = ["%"]
        for nibble in match.group(0)[1:]:
            if nibble.lower() in "abcdef":
                counter += 1
                rewritten.append(nibble.lower() if counter % 2 else nibble.upper())
            else:
                rewritten.append(nibble)
        return "".join(rewritten)

    return re.sub(r"%[0-9A-Fa-f]{2}", rewrite, value)


def _secret_forms(secret: str) -> tuple[str, ...]:
    raw = secret.encode("utf-8")
    quoted = quote(secret, safe="")
    plus = quote_plus(secret, safe="")
    json_inner = json.dumps(secret, ensure_ascii=True)[1:-1]
    json_solidus = json_inner.replace("/", r"\/")
    fully_percent = "".join(f"%{byte:02X}" for byte in raw)
    std = base64.b64encode(raw).decode("ascii")
    url = base64.urlsafe_b64encode(raw).decode("ascii")
    candidates = (
        secret,
        quoted,
        _percent_lower(quoted),
        plus,
        _percent_lower(plus),
        fully_percent,
        json_inner,
        json_solidus,
        std,
        std.rstrip("="),
        url,
        url.rstrip("="),
        raw.hex(),
        raw.hex().upper(),
    )
    return tuple(dict.fromkeys(candidate for candidate in candidates if candidate))


def _assert_forms_absent(secret: str, *values: object) -> None:
    seen: set[int] = set()

    def strings(value: object) -> list[str]:
        if isinstance(value, str):
            return [value]
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


class _SyntheticProvider(ModelProvider):
    def __init__(
        self,
        *,
        secret: str,
        response: ChatResponse | None = None,
        events: list[StreamEvent] | None = None,
    ) -> None:
        self.config = SimpleNamespace(api_key=secret, max_retries=1)
        self.response = response
        self.events = list(events or [])
        self.chat_calls = 0
        self.stream_calls = 0
        self.seen_messages: list[ChatMessage] | None = None
        self.seen_tools: list[dict[str, Any]] | None = None

    async def chat(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> ChatResponse:
        del model, temperature, max_tokens
        self.chat_calls += 1
        self.seen_messages = deepcopy(messages)
        self.seen_tools = deepcopy(tools)
        assert self.response is not None
        return self.response

    def chat_stream(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> AsyncIterator[str]:
        del messages, model, tools, temperature, max_tokens

        async def _empty() -> AsyncIterator[str]:
            if False:  # pragma: no cover
                yield ""

        return _empty()

    async def chat_stream_events(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> AsyncIterator[StreamEvent]:
        del model, temperature, max_tokens
        self.stream_calls += 1
        self.seen_messages = deepcopy(messages)
        self.seen_tools = deepcopy(tools)
        for event in self.events:
            yield event

    async def health_check(self) -> bool:
        return True

    async def close(self) -> None:
        return None


def _router(provider: _SyntheticProvider) -> ModelRouter:
    router = ModelRouter(JSSettings(providers=[]), permit_verifier=ModelPermitIssuer())
    router.add_provider("synthetic", provider, [_MODEL])
    return router


def _grant(router: ModelRouter) -> Any:
    issuer = router._permit_verifier
    assert isinstance(issuer, ModelPermitIssuer)

    def issue(decision: Any, messages: list[ChatMessage], tools: Any) -> Any:
        return issuer.issue(
            provider_name=decision.provider_name,
            model=decision.model,
            messages=messages,
            tools=tools,
            owner_key_hash="owner",
            session_id="session",
            run_id="run",
        )

    return issue


async def _before(decision: Any, *_args: Any) -> str:
    return str(decision.provider_name)


def test_exact_scrubber_derives_all_forms_without_repr_or_detection_side_effects() -> None:
    scrubber = ProviderSecretScrubber([_SECRET])
    forms = _secret_forms(_SECRET)
    source = " | ".join(forms)

    redacted = scrubber.redact_text(source)

    _assert_forms_absent(_SECRET, redacted, scrubber, repr(scrubber))
    assert redacted.count("[S]") == len(forms)
    assert scrubber.redact_text("one-character-near-miss:" + _SECRET[:-1] + "X").endswith(
        _SECRET[:-1] + "X"
    )


@pytest.mark.parametrize("secret", ["12345678", "éééé", "x" * 512])
def test_exact_scrubber_accepts_utf8_byte_boundaries(secret: str) -> None:
    assert ProviderSecretScrubber([secret]).redact_text(secret) == "[S]"


@pytest.mark.parametrize("secret", ["1234567", "x" * 513, "\ud80012345678"])
def test_exact_scrubber_rejects_invalid_secret_boundaries_without_echo(secret: str) -> None:
    with pytest.raises(ProviderSecretScrubError) as raised:
        ProviderSecretScrubber([secret])
    assert secret not in repr(raised.value)


def test_exact_scrubber_recurses_keys_values_and_rejects_collisions_cycles() -> None:
    forms = _secret_forms(_SECRET)
    value = {
        f"key-{forms[0]}": [forms[1], (forms[2], {"nested": forms[3]})],
        "safe": 7,
    }
    safe = ProviderSecretScrubber([_SECRET]).redact_value(value)
    _assert_forms_absent(_SECRET, safe)

    collision = {forms[0]: "first", forms[1]: "second"}
    with pytest.raises(ProviderSecretScrubError):
        ProviderSecretScrubber([_SECRET]).redact_value(collision)

    cycle: list[Any] = []
    cycle.append(cycle)
    with pytest.raises(ProviderSecretScrubError):
        ProviderSecretScrubber([_SECRET]).redact_value(cycle)


def test_exact_scrubber_enforces_secret_count_without_exposing_values() -> None:
    secrets = [f"key-{index:04d}" for index in range(64)]
    scrubber = ProviderSecretScrubber(secrets)
    _assert_forms_absent(secrets[0], scrubber.redact_text(secrets[0]))
    with pytest.raises(ProviderSecretScrubError) as raised:
        ProviderSecretScrubber([*secrets, "key-0064"])
    assert all(secret not in repr(raised.value) for secret in secrets)


def test_exact_scrubber_enforces_recursive_size_depth_and_node_limits() -> None:
    scrubber = ProviderSecretScrubber([_SECRET])
    assert scrubber.redact_value("x" * (1024 * 1024)) == "x" * (1024 * 1024)
    with pytest.raises(ProviderSecretScrubError):
        scrubber.redact_value("x" * (1024 * 1024 + 1))

    aggregate = ["x" * (1024 * 1024) for _ in range(16)]
    assert scrubber.redact_value(aggregate) == aggregate
    with pytest.raises(ProviderSecretScrubError):
        scrubber.redact_value([*aggregate, "x"])

    assert scrubber.redact_value([0] * 4095) == [0] * 4095
    with pytest.raises(ProviderSecretScrubError):
        scrubber.redact_value([0] * 4096)

    depth_16: object = "safe"
    for _ in range(16):
        depth_16 = [depth_16]
    scrubber.redact_value(depth_16)
    depth_17: object = [depth_16]
    with pytest.raises(ProviderSecretScrubError):
        scrubber.redact_value(depth_17)


def test_exact_scrubber_never_writes_secret_detection_state(tmp_path: Path) -> None:
    manager = SecretManager(tmp_path / "state")
    before = manager.get_stats()
    ProviderSecretScrubber([_SECRET]).redact_text(_SECRET)
    assert manager.get_stats() == before


def test_exact_stream_matches_every_form_one_character_at_a_time() -> None:
    scrubber = ProviderSecretScrubber([_SECRET])
    stream = scrubber.open_stream()
    source = "|".join(_secret_forms(_SECRET))
    output = "".join(stream.feed(char) for char in source) + stream.flush()
    _assert_forms_absent(_SECRET, output, stream, repr(stream))
    assert output.count("[S]") == len(_secret_forms(_SECRET))


def test_exact_scrubber_treats_each_percent_triplet_case_insensitively() -> None:
    mixed = _percent_mixed(quote(_SECRET, safe=""))
    assert mixed not in {quote(_SECRET, safe=""), _percent_lower(quote(_SECRET, safe=""))}
    scrubber = ProviderSecretScrubber([_SECRET])
    assert scrubber.redact_text(mixed) == "[S]"
    stream = scrubber.open_stream()
    assert "".join(stream.feed(char) for char in mixed) + stream.flush() == "[S]"


def test_exact_scrubber_covers_fully_percent_encoded_secret() -> None:
    secret = "aa/b+c=d"
    encoded = "".join(f"%{byte:02x}" for byte in secret.encode("utf-8"))
    scrubber = ProviderSecretScrubber([secret])

    assert scrubber.redact_text(encoded) == "[S]"
    stream = scrubber.open_stream()
    assert "".join(stream.feed(char) for char in encoded) + stream.flush() == "[S]"


@pytest.mark.parametrize(
    "chunks",
    [
        ["abcdefgh%41"],
        ["abcdefgh%", "41"],
        ["abcdefgh%", "4", "1"],
        ["abcdefgh%4", "1"],
    ],
)
def test_exact_stream_defers_incomplete_percent_escape_before_shorter_match(
    chunks: list[str],
) -> None:
    scrubber = ProviderSecretScrubber(["abcdefgh%", "abcdefghA"])
    stream = scrubber.open_stream()

    output = "".join(stream.feed(chunk) for chunk in chunks) + stream.flush()

    assert output == "[S]"


@pytest.mark.parametrize(
    "chunks",
    [
        [r"abcdefgh\u00e", "9-ROTATED-SECRET-TAIL"],
        ["abcdefgh\\", "u00e", "9-ROTATED", "-SECRET", "-TAIL"],
        ["abcdefgh\\u", "0", "0", "e", "9-ROTATED-SECRET-TAIL"],
        [r"abcdefgh\u00e", "9-ROTATED", "-SECRET", "-TAIL"],
    ],
)
def test_exact_stream_defers_incomplete_json_escape_before_shorter_match(
    chunks: list[str],
) -> None:
    old_secret = r"abcdefgh\u00e"
    new_secret = "abcdefghé-ROTATED-SECRET-TAIL"
    stream = ProviderSecretScrubber([old_secret, new_secret]).open_stream()

    output = "".join(stream.feed(chunk) for chunk in chunks) + stream.flush()

    assert output == "[S]"


def test_exact_stream_flushes_benign_prefix_and_discards_failed_prefix() -> None:
    prefix = _SECRET[:5]
    stream = ProviderSecretScrubber([_SECRET]).open_stream()
    assert stream.feed(prefix) == ""
    assert stream.flush() == prefix

    discarded = ProviderSecretScrubber([_SECRET]).open_stream()
    assert discarded.feed(prefix) == ""
    discarded.discard()
    assert discarded.flush() == ""


def test_exact_scrubber_fails_closed_when_replacement_boundary_rebuilds_secret() -> None:
    secret = "abc[S]de"
    with pytest.raises(ProviderSecretScrubError) as raised:
        ProviderSecretScrubber([secret])
    assert secret not in repr(raised.value)


def test_exact_stream_fails_before_cross_return_marker_rebuilds_secret() -> None:
    secret = "S]abcdef"
    encoded = base64.b64encode(secret.encode("utf-8")).decode("ascii")
    stream = ProviderSecretScrubber([secret]).open_stream()

    published = stream.feed(encoded)
    assert published == "[S]"
    assert stream.feed("abcdef") == ""
    with pytest.raises(ProviderSecretScrubError):
        stream.flush()

    assert secret not in published
    assert stream.flush() == ""


@pytest.mark.parametrize(
    ("secret", "encoded"),
    [
        ("abcd/efg", r"abcd\/efg"),
        ("abcdéefg", r"abcd\u00E9efg"),
    ],
)
def test_exact_scrubber_covers_valid_json_escape_variants(
    secret: str,
    encoded: str,
) -> None:
    scrubber = ProviderSecretScrubber([secret])
    assert scrubber.redact_text(encoded) == "[S]"
    stream = scrubber.open_stream()
    assert "".join(stream.feed(char) for char in encoded) + stream.flush() == "[S]"


def test_exact_scrubber_keeps_invalid_percent_near_miss() -> None:
    scrubber = ProviderSecretScrubber(["abcd%aZx"])
    assert scrubber.redact_text("abcd%AZx") == "abcd%AZx"


@pytest.mark.parametrize(
    ("secret", "near_miss"),
    [
        ("abcd%abx", "abcd%ABx"),
        (r"abc\u00e9", r"abc\U00E9"),
    ],
)
def test_exact_scrubber_does_not_canonicalize_raw_near_misses(
    secret: str,
    near_miss: str,
) -> None:
    scrubber = ProviderSecretScrubber([secret])
    assert scrubber.redact_text(secret) == "[S]"
    assert scrubber.redact_text(near_miss) == near_miss


def test_json_solidus_variants_are_bounded_and_match_mixed_escapes() -> None:
    secret = "abcd////efgh"
    scrubber = ProviderSecretScrubber([secret])
    assert scrubber.redact_text(r"abcd\/\/\/\/efgh") == "[S]"
    assert scrubber.redact_text(r"abcd\//\/\/efgh") == "[S]"


def test_json_solidus_source_span_preserves_surrounding_text_and_backslash_parity() -> None:
    scrubber = ProviderSecretScrubber(["abcd/efg"])
    assert scrubber.redact_text(r"pre:abcd\/efg:post") == "pre:[S]:post"

    with_real_backslash = ProviderSecretScrubber([r"abcd\/efg"])
    assert with_real_backslash.redact_text(r"abcd/efg") == "abcd/efg"
    assert with_real_backslash.redact_text(r"abcd\\/efg") == "[S]"
    assert with_real_backslash.redact_text(r"abcd\\\/efg") == "[S]"


def test_exact_scrubber_exercises_distinct_standard_and_urlsafe_base64() -> None:
    secret = "123456789🌾"
    raw = secret.encode("utf-8")
    standard = base64.b64encode(raw).decode("ascii")
    urlsafe = base64.urlsafe_b64encode(raw).decode("ascii")
    assert standard != urlsafe
    assert standard.endswith("=") and urlsafe.endswith("=")
    scrubber = ProviderSecretScrubber([secret])
    for form in (standard, standard.rstrip("="), urlsafe, urlsafe.rstrip("=")):
        assert scrubber.redact_text(form) == "[S]"


def test_exact_stream_discards_pending_when_oversize_feed_fails() -> None:
    stream = ProviderSecretScrubber([_SECRET]).open_stream()
    assert stream.feed(_SECRET[:7]) == ""
    with pytest.raises(ProviderSecretScrubError):
        stream.feed("x" * (1024 * 1024 + 1))
    assert stream.flush() == ""


@pytest.mark.asyncio
async def test_router_rebuilds_nonstream_success_before_after_hook() -> None:
    forms = _secret_forms(_SECRET)
    raw = ChatResponse(
        content=f"content:{forms[0]}",
        reasoning_content=f"reasoning:{forms[1]}",
        tool_calls=[
            {
                f"secret-key-{forms[2]}": forms[3],
                "id": forms[4],
                "type": forms[5],
                "function": {"name": forms[6], "arguments": forms[7]},
            }
        ],
        model=forms[8],
        usage={"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3},
        finish_reason=forms[9],
        usage_source="provider_actual",
    )
    provider = _SyntheticProvider(secret=_SECRET, response=raw)
    router = _router(provider)
    messages = [ChatMessage(role="user", content=f"outbound:{_SECRET}")]
    tools = [{"type": "function", "function": {"name": "f", "description": _SECRET}}]
    hook_responses: list[ChatResponse] = []

    async def after(
        _context: Any,
        response: ChatResponse | None,
        error: BaseException | None,
    ) -> None:
        assert error is None
        assert response is not None
        _assert_forms_absent(_SECRET, response)
        hook_responses.append(response)

    response = await router.chat(
        messages,
        model="safe-model",
        tools=tools,
        before_model_call=_before,
        after_model_call=after,
        permit_grant=_grant(router),
    )

    assert hook_responses == [response]
    assert response is not raw
    assert response.model == "safe-model"
    assert response.usage == {"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3}
    assert response.content == "content:[S]"
    assert response.reasoning_content == "reasoning:[S]"
    assert response.finish_reason == "[S]"
    assert response.usage_source == "provider_actual"
    assert response.tool_calls == [
        {
            "secret-key-[S]": "[S]",
            "id": "[S]",
            "type": "[S]",
            "function": {"name": "[S]", "arguments": "[S]"},
        }
    ]
    _assert_forms_absent(_SECRET, response)
    assert provider.seen_messages == messages
    assert provider.seen_tools == tools


@pytest.mark.asyncio
@pytest.mark.parametrize("streaming", [False, True])
async def test_router_rejects_invalid_secret_before_echo_before_hook(
    streaming: bool,
) -> None:
    provider = _SyntheticProvider(
        secret="short",
        response=ChatResponse("safe", [], "safe-model", {}, "stop"),
        events=[StreamEvent(kind="done", finish_reason="stop")],
    )
    router = _router(provider)
    calls: list[str] = []
    claims: list[Any] = []
    executor = EchoDurableExecutor(
        max_claim_pending=2,
        max_finish_pending=2,
        thread_name_prefix="b1c-invalid-secret",
    )

    async def before(*_args: Any) -> Any:
        calls.append("before")
        claim = await claim_to_thread(
            lambda: "context",
            on_cancel=lambda _value: None,
            executor=executor,
        )
        claims.append(claim)
        return claim

    async def after(context: Any, *_args: Any) -> None:
        calls.append("after")
        await durable_to_thread(lambda: None, claim=context)

    try:
        with pytest.raises(ProviderSecretScrubError):
            if streaming:
                async for _event in router.chat_stream_events(
                    [ChatMessage(role="user", content="hi")],
                    model="safe-model",
                    before_model_call=before,
                    after_model_call=after,
                    permit_grant=_grant(router),
                ):
                    pass
            else:
                await router.chat(
                    [ChatMessage(role="user", content="hi")],
                    model="safe-model",
                    before_model_call=before,
                    after_model_call=after,
                    permit_grant=_grant(router),
                )
        outstanding_claims = executor.outstanding_claims
    finally:
        for claim in claims:
            if claim._reservation.state == "reserved":
                await durable_to_thread(lambda: None, claim=claim)
        executor.shutdown(wait=True)

    assert calls == []
    assert outstanding_claims == 0
    assert provider.chat_calls == 0
    assert provider.stream_calls == 0


@pytest.mark.asyncio
async def test_openai_provider_freezes_transport_credential_generation() -> None:
    old_secret = "old-generation-secret-12345"
    new_secret = "new-generation-secret-67890"
    config = ModelProviderConfig(
        name="snapshot",
        base_url="https://api.example.test/v1",
        api_key=old_secret,
        models=[ModelConfig(id="safe-model", name="Safe")],
    )
    provider = OpenAICompatibleProvider(config)
    config.api_key = new_secret
    fake_http = MagicMock()
    fake_http.aclose = AsyncMock()
    fake_sdk = MagicMock()
    fake_sdk.close = AsyncMock()

    with (
        patch(
            "js.security.net_guard.resolve_and_validate_provider_endpoint",
            return_value=["93.184.216.34"],
        ),
        patch("js.models.providers.PinnedTransport", return_value=MagicMock()),
        patch("js.models.providers.httpx.AsyncClient", return_value=fake_http),
        patch("js.models.providers.AsyncOpenAI", return_value=fake_sdk) as sdk_factory,
    ):
        assert await provider._ensure_client() is fake_sdk

    assert provider.response_secret_snapshot() == old_secret
    assert sdk_factory.call_args.kwargs["api_key"] == old_secret
    assert new_secret not in repr(sdk_factory.call_args.kwargs)
    await provider.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "usage",
    [
        {"prompt_tokens": True},
        {"prompt_tokens": -1},
        {"unknown_tokens": 1},
        {"prompt_tokens": "1"},
    ],
)
async def test_router_rejects_untrusted_nonstream_usage_before_after_success(
    usage: dict[str, Any],
) -> None:
    provider = _SyntheticProvider(
        secret=_SECRET,
        response=ChatResponse(
            content="safe",
            tool_calls=[],
            model="attacker-model",
            usage=usage,
            finish_reason="stop",
        ),
    )
    router = _router(provider)
    after_seen: list[tuple[ChatResponse | None, BaseException | None]] = []

    async def after(_context: Any, response: Any, error: BaseException | None) -> None:
        after_seen.append((response, error))

    with pytest.raises(ProviderSecretScrubError):
        await router.chat(
            [ChatMessage(role="user", content="hi")],
            model="safe-model",
            before_model_call=_before,
            after_model_call=after,
            permit_grant=_grant(router),
        )
    assert len(after_seen) == 1
    assert after_seen[0][0] is None
    assert isinstance(after_seen[0][1], ProviderSecretScrubError)


@pytest.mark.asyncio
@pytest.mark.parametrize("secret", ["1234567", "x" * 513])
async def test_router_rejects_invalid_runtime_secret_before_provider_call(secret: str) -> None:
    provider = _SyntheticProvider(
        secret=secret,
        response=ChatResponse("safe", [], "safe-model", {}, "stop"),
    )
    router = _router(provider)

    with pytest.raises(ProviderSecretScrubError):
        await router.chat(
            [ChatMessage(role="user", content="hi")],
            model="safe-model",
            before_model_call=_before,
            after_model_call=lambda *_args: None,  # type: ignore[arg-type]
            permit_grant=_grant(router),
        )
    assert provider.chat_calls == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "secret",
    [
        "safe-model",
        "estimated",
        "text_delta",
        "function",
        "arguments_delta",
        "prompt_tokens",
        "finish_reason",
    ],
)
async def test_router_rejects_secret_collisions_with_trusted_protocol_identity(
    secret: str,
) -> None:
    provider = _SyntheticProvider(
        secret=secret,
        response=ChatResponse("safe", [], "safe-model", {}, "stop"),
    )
    router = _router(provider)

    with pytest.raises(ProviderSecretScrubError):
        await router.chat(
            [ChatMessage(role="user", content="hi")],
            model="safe-model",
            before_model_call=_before,
            after_model_call=lambda *_args: None,  # type: ignore[arg-type]
            permit_grant=_grant(router),
        )
    assert provider.chat_calls == 0


@pytest.mark.asyncio
async def test_router_scrub_failure_hook_never_observes_raw_traceback_locals() -> None:
    provider = _SyntheticProvider(
        secret=_SECRET,
        response=ChatResponse(
            content=_SECRET,
            tool_calls=[],
            model="attacker-model",
            usage={"unknown_tokens": 1},
            finish_reason="stop",
        ),
    )
    router = _router(provider)
    hook_errors: list[BaseException] = []

    async def after(
        _context: Any,
        response: ChatResponse | None,
        error: BaseException | None,
    ) -> None:
        assert response is None
        assert isinstance(error, ProviderSecretScrubError)
        traceback_locals: list[object] = []
        current = error.__traceback__
        while current is not None:
            traceback_locals.append(current.tb_frame.f_locals)
            current = current.tb_next
        _assert_forms_absent(_SECRET, error, traceback_locals)
        assert error.__traceback__ is None
        assert error.__cause__ is None
        assert error.__context__ is None
        hook_errors.append(error)

    with pytest.raises(ProviderSecretScrubError) as raised:
        await router.chat(
            [ChatMessage(role="user", content="hi")],
            model="safe-model",
            before_model_call=_before,
            after_model_call=after,
            permit_grant=_grant(router),
        )
    assert len(hook_errors) == 1
    _assert_forms_absent(_SECRET, raised.value)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("streaming", "failure_type"),
    [
        (False, asyncio.CancelledError),
        (True, asyncio.CancelledError),
        (True, PermissionError),
    ],
)
async def test_router_detaches_provider_control_error_before_hook_and_propagation(
    streaming: bool,
    failure_type: type[BaseException],
) -> None:
    provider = _SyntheticProvider(
        secret=_SECRET,
        response=ChatResponse("safe", [], "safe-model", {}, "stop"),
    )

    if streaming:

        async def fail_stream(*_args: Any, **_kwargs: Any) -> AsyncIterator[StreamEvent]:
            raise failure_type(_SECRET)
            if False:  # pragma: no cover - retain async-generator shape
                yield StreamEvent(kind="done")

        provider.chat_stream_events = fail_stream  # type: ignore[method-assign]
    else:

        async def fail_chat(*_args: Any, **_kwargs: Any) -> ChatResponse:
            raise failure_type(_SECRET)

        provider.chat = fail_chat  # type: ignore[method-assign]

    router = _router(provider)
    hook_errors: list[BaseException] = []

    async def after(
        _context: Any,
        response: ChatResponse | None,
        error: BaseException | None,
    ) -> None:
        assert response is None
        assert error is not None
        assert isinstance(error, failure_type)
        assert error.__traceback__ is None
        assert error.__cause__ is None
        assert error.__context__ is None
        _assert_forms_absent(_SECRET, error)
        hook_errors.append(error)

    with pytest.raises(failure_type) as raised:
        if streaming:
            async for _event in router.chat_stream_events(
                [ChatMessage(role="user", content="hi")],
                model="safe-model",
                before_model_call=_before,
                after_model_call=after,
                permit_grant=_grant(router),
            ):
                pass
        else:
            await router.chat(
                [ChatMessage(role="user", content="hi")],
                model="safe-model",
                before_model_call=_before,
                after_model_call=after,
                permit_grant=_grant(router),
            )

    assert len(hook_errors) == 1
    _assert_forms_absent(_SECRET, raised.value)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    traceback_frames: list[str] = []
    current = raised.value.__traceback__
    while current is not None:
        traceback_frames.append(current.tb_frame.f_code.co_name)
        current = current.tb_next
    assert "fail_chat" not in traceback_frames
    assert "fail_stream" not in traceback_frames


@pytest.mark.asyncio
async def test_router_scrubs_encoded_provider_error_before_hook_and_propagation() -> None:
    encoded = base64.b64encode(_SECRET.encode("utf-8")).decode("ascii")
    provider = _SyntheticProvider(
        secret=_SECRET,
        response=ChatResponse("safe", [], "safe-model", {}, "stop"),
    )

    async def fail_chat(*_args: Any, **_kwargs: Any) -> ChatResponse:
        raise RuntimeError(f"bad:{encoded}")

    provider.chat = fail_chat  # type: ignore[method-assign]
    router = _router(provider)
    hook_errors: list[BaseException] = []

    async def after(
        _context: Any,
        response: ChatResponse | None,
        error: BaseException | None,
    ) -> None:
        assert response is None
        assert error is not None
        _assert_forms_absent(_SECRET, error)
        hook_errors.append(error)

    with pytest.raises(Exception) as raised:
        await router.chat(
            [ChatMessage(role="user", content="hi")],
            model="safe-model",
            before_model_call=_before,
            after_model_call=after,
            permit_grant=_grant(router),
        )

    assert len(hook_errors) == 1
    _assert_forms_absent(_SECRET, raised.value)


@pytest.mark.asyncio
async def test_router_provider_error_never_exposes_legacy_key_prefix_or_suffix() -> None:
    secret = "SYNTHETIC-RAW-KEY-12345"
    provider = _SyntheticProvider(
        secret=secret,
        response=ChatResponse("safe", [], "safe-model", {}, "stop"),
    )

    async def fail_chat(*_args: Any, **_kwargs: Any) -> ChatResponse:
        raise RuntimeError(secret)

    provider.chat = fail_chat  # type: ignore[method-assign]
    router = _router(provider)
    hook_errors: list[BaseException] = []

    async def after(
        _context: Any,
        response: ChatResponse | None,
        error: BaseException | None,
    ) -> None:
        assert response is None
        assert error is not None
        hook_errors.append(error)

    with pytest.raises(Exception) as raised:
        await router.chat(
            [ChatMessage(role="user", content="hi")],
            model="safe-model",
            before_model_call=_before,
            after_model_call=after,
            permit_grant=_grant(router),
        )

    for error in [*hook_errors, raised.value]:
        rendered = f"{error!s}|{error!r}"
        assert secret not in rendered
        assert secret[:4] not in rendered
        assert secret[-4:] not in rendered
        assert "[S]" in rendered


@pytest.mark.asyncio
async def test_router_success_hook_cancel_is_detached_and_preserves_safe_reason() -> None:
    provider = _SyntheticProvider(
        secret=_SECRET,
        response=ChatResponse("safe", [], "safe-model", {}, "stop"),
    )
    router = _router(provider)

    async def after(
        _context: Any,
        response: ChatResponse | None,
        error: BaseException | None,
    ) -> None:
        assert response is not None
        assert error is None
        raise asyncio.CancelledError("benign cancellation")

    with pytest.raises(asyncio.CancelledError, match="benign cancellation") as raised:
        await router.chat(
            [ChatMessage(role="user", content="hi")],
            model="safe-model",
            before_model_call=_before,
            after_model_call=after,
            permit_grant=_grant(router),
        )

    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    frames: set[str] = set()
    current = raised.value.__traceback__
    while current is not None:
        frames.add(current.tb_frame.f_code.co_name)
        current = current.tb_next
    assert "after" not in frames


@pytest.mark.asyncio
async def test_router_preserves_detached_echo_unavailable_hook_failure() -> None:
    provider = _SyntheticProvider(
        secret=_SECRET,
        response=ChatResponse("safe", [], "safe-model", {}, "stop"),
    )
    router = _router(provider)

    async def after(
        _context: Any,
        response: ChatResponse | None,
        error: BaseException | None,
    ) -> None:
        assert response is not None
        assert error is None
        raise EchoUnavailableError("journal unavailable")

    with pytest.raises(EchoUnavailableError, match="journal unavailable") as raised:
        await router.chat(
            [ChatMessage(role="user", content="hi")],
            model="safe-model",
            before_model_call=_before,
            after_model_call=after,
            permit_grant=_grant(router),
        )

    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


@pytest.mark.asyncio
async def test_router_attempt_diagnostics_use_immutable_original_key_snapshot() -> None:
    old_secret = "Requested model"
    provider = _SyntheticProvider(
        secret=old_secret,
        response=ChatResponse("safe", [], "safe-model", {}, "stop"),
    )

    async def rotate_then_fail(*_args: Any, **_kwargs: Any) -> ChatResponse:
        provider.config.api_key = "replacement-key-12345"
        raise RuntimeError("boom")

    provider.chat = rotate_then_fail  # type: ignore[method-assign]
    router = _router(provider)

    async def after(
        _context: Any,
        _response: ChatResponse | None,
        _error: BaseException | None,
    ) -> None:
        return None

    with pytest.raises(Exception) as raised:
        await router.chat(
            [ChatMessage(role="user", content="hi")],
            model="safe-model",
            before_model_call=_before,
            after_model_call=after,
            permit_grant=_grant(router),
        )

    assert old_secret not in str(raised.value)


@pytest.mark.asyncio
async def test_router_registered_generation_scrubs_cached_transport_key_after_config_change() -> None:
    old_secret = "cached-transport-key-12345"
    provider = _SyntheticProvider(
        secret=old_secret,
        response=ChatResponse(old_secret, [], "safe-model", {}, "stop"),
    )
    router = _router(provider)
    # Simulate the static-key transition window: an existing SDK transport
    # still uses the registration-time key while its shared config now points
    # at the replacement generation.
    provider.config.api_key = "replacement-key-12345"

    observed: list[ChatResponse] = []

    async def after(
        _context: Any,
        response: ChatResponse | None,
        error: BaseException | None,
    ) -> None:
        assert error is None
        assert response is not None
        observed.append(response)

    response = await router.chat(
        [ChatMessage(role="user", content="hi")],
        model="safe-model",
        before_model_call=_before,
        after_model_call=after,
        permit_grant=_grant(router),
    )

    assert response.content == "[S]"
    assert observed[0].content == "[S]"


@pytest.mark.asyncio
async def test_router_decision_and_before_hook_never_expose_secret_snapshot() -> None:
    provider = _SyntheticProvider(
        secret=_SECRET,
        response=ChatResponse("safe", [], "safe-model", {}, "stop"),
    )
    router = _router(provider)

    async def before(decision: Any, *_args: Any) -> str:
        assert _SECRET not in repr(decision)
        assert not hasattr(decision, "secret_values")
        return "context"

    async def after(
        _context: Any,
        _response: ChatResponse | None,
        _error: BaseException | None,
    ) -> None:
        return None

    response = await router.chat(
        [ChatMessage(role="user", content="hi")],
        model="safe-model",
        before_model_call=before,
        after_model_call=after,
        permit_grant=_grant(router),
    )

    assert response.content == "safe"


@pytest.mark.asyncio
async def test_router_stream_hook_failure_traceback_never_retains_raw_done_event() -> None:
    provider = _SyntheticProvider(
        secret=_SECRET,
        events=[
            StreamEvent(
                kind="done",
                finish_reason=_SECRET,
                meta={"provider_private": _SECRET},
            )
        ],
    )
    router = _router(provider)

    async def after(
        _context: Any,
        response: ChatResponse | None,
        error: BaseException | None,
    ) -> None:
        assert response is not None
        assert response.finish_reason == "[S]"
        assert error is None
        raise OSError("after failed")

    with pytest.raises(OSError, match="after failed") as raised:
        async for _event in router.chat_stream_events(
            [ChatMessage(role="user", content="hi")],
            model="safe-model",
            before_model_call=_before,
            after_model_call=after,
            permit_grant=_grant(router),
        ):
            pass

    current = raised.value.__traceback__
    while current is not None:
        for name in ("raw_ev", "raw_finish"):
            if name in current.tb_frame.f_locals:
                _assert_forms_absent(_SECRET, current.tb_frame.f_locals[name])
        current = current.tb_next


@pytest.mark.asyncio
async def test_router_stream_hook_failure_traceback_never_retains_raw_error_event() -> None:
    provider = _SyntheticProvider(
        secret=_SECRET,
        events=[StreamEvent(kind="error", error=_SECRET, meta={"retryable": False})],
    )
    router = _router(provider)

    async def after(
        _context: Any,
        response: ChatResponse | None,
        error: BaseException | None,
    ) -> None:
        assert response is None
        assert error is not None
        _assert_forms_absent(_SECRET, error)
        raise OSError("after failed")

    with pytest.raises(OSError, match="after failed") as raised:
        async for _event in router.chat_stream_events(
            [ChatMessage(role="user", content="hi")],
            model="safe-model",
            before_model_call=_before,
            after_model_call=after,
            permit_grant=_grant(router),
        ):
            pass

    current = raised.value.__traceback__
    while current is not None:
        if "raw_ev" in current.tb_frame.f_locals:
            _assert_forms_absent(_SECRET, current.tb_frame.f_locals["raw_ev"])
        current = current.tb_next


@pytest.mark.asyncio
async def test_router_hook_exception_stringification_failure_is_opaque() -> None:
    encoded = base64.b64encode(_SECRET.encode("utf-8")).decode("ascii")
    provider = _SyntheticProvider(
        secret=_SECRET,
        events=[StreamEvent(kind="done")],
    )
    router = _router(provider)

    class EvilArgument:
        def __str__(self) -> str:
            raise RuntimeError(encoded)

    async def after(
        _context: Any,
        _response: ChatResponse | None,
        _error: BaseException | None,
    ) -> None:
        raise OSError(EvilArgument())

    with pytest.raises(Exception) as raised:
        async for _event in router.chat_stream_events(
            [ChatMessage(role="user", content="hi")],
            model="safe-model",
            before_model_call=_before,
            after_model_call=after,
            permit_grant=_grant(router),
        ):
            pass

    assert encoded not in str(raised.value)
    assert str(raised.value) == "[S]"


@pytest.mark.asyncio
async def test_router_success_hook_failure_cannot_retain_raw_response_traceback() -> None:
    provider = _SyntheticProvider(
        secret=_SECRET,
        response=ChatResponse(_SECRET, [], "attacker", {}, "stop"),
    )
    router = _router(provider)

    async def after(
        _context: Any,
        response: ChatResponse | None,
        error: BaseException | None,
    ) -> None:
        assert error is None
        assert response is not None
        _assert_forms_absent(_SECRET, response)
        raise OSError("after failed")

    with pytest.raises(OSError, match="after failed") as raised:
        await router.chat(
            [ChatMessage(role="user", content="hi")],
            model="safe-model",
            before_model_call=_before,
            after_model_call=after,
            permit_grant=_grant(router),
        )

    frames: list[str] = []
    current = raised.value.__traceback__
    while current is not None:
        frames.append(current.tb_frame.f_code.co_name)
        if "raw_response" in current.tb_frame.f_locals:
            _assert_forms_absent(_SECRET, current.tb_frame.f_locals["raw_response"])
        current = current.tb_next
    assert "after" not in frames
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


@pytest.mark.asyncio
async def test_router_success_logs_hold_only_rebuilt_safe_response(
    caplog: pytest.LogCaptureFixture,
) -> None:
    provider = _SyntheticProvider(
        secret=_SECRET,
        response=ChatResponse(
            content=_SECRET,
            tool_calls=[],
            model="forged",
            usage={},
            finish_reason="stop",
        ),
    )
    router = _router(provider)

    async def after(_context: Any, response: Any, error: BaseException | None) -> None:
        assert error is None
        logging.getLogger("b1c.success").warning("safe response: %r", response)

    with caplog.at_level(logging.WARNING):
        await router.chat(
            [ChatMessage(role="user", content="hi")],
            model="safe-model",
            before_model_call=_before,
            after_model_call=after,
            permit_grant=_grant(router),
        )

    assert caplog.records
    for record in caplog.records:
        _assert_forms_absent(
            _SECRET,
            record.msg,
            record.args,
            record.exc_info,
            record.__dict__,
        )


@pytest.mark.asyncio
async def test_router_stream_scrubs_text_thinking_and_tool_fields_before_hooks() -> None:
    forms = _secret_forms(_SECRET)
    events: list[StreamEvent] = []
    for char in forms[0]:
        events.append(StreamEvent(kind="text_delta", text=char))
    for char in forms[1]:
        events.append(StreamEvent(kind="thinking_delta", text=char))
    for field, value in (("id", forms[2]), ("type", forms[3]), ("name", forms[4])):
        for char in value:
            events.append(StreamEvent(kind="tool_call_delta", tool_call={"index": 0, field: char}))
    for char in forms[5]:
        events.append(
            StreamEvent(
                kind="tool_call_delta",
                tool_call={"index": 0, "arguments_delta": char},
            )
        )
    events.extend(
        [
            StreamEvent(
                kind="usage",
                usage={"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3},
            ),
            StreamEvent(kind="done", finish_reason=f"stop-{forms[6]}"),
        ]
    )
    provider = _SyntheticProvider(secret=_SECRET, events=events)
    router = _router(provider)
    hook_responses: list[ChatResponse] = []

    async def after(_context: Any, response: Any, error: BaseException | None) -> None:
        assert error is None
        assert isinstance(response, ChatResponse)
        _assert_forms_absent(_SECRET, response)
        hook_responses.append(response)

    output = [
        event
        async for event in router.chat_stream_events(
            [ChatMessage(role="user", content="hi")],
            model="safe-model",
            before_model_call=_before,
            after_model_call=after,
            permit_grant=_grant(router),
        )
    ]

    _assert_forms_absent(_SECRET, output, hook_responses)
    assert output[-1].kind == "done"
    usage_position = next(
        index for index, event in enumerate(output) if event.kind == "usage"
    )
    argument_positions = [
        index
        for index, event in enumerate(output)
        if event.kind == "tool_call_delta"
        and isinstance(event.tool_call, dict)
        and "arguments_delta" in event.tool_call
    ]
    assert argument_positions
    assert min(argument_positions) < usage_position
    assert all(
        not any(field in (event.tool_call or {}) for field in ("id", "type", "name"))
        for event in output[:usage_position]
        if event.kind == "tool_call_delta"
    )
    streamed_arguments = "".join(
        str(event.tool_call["arguments_delta"])
        for event in output
        if event.kind == "tool_call_delta"
        and isinstance(event.tool_call, dict)
        and "arguments_delta" in event.tool_call
    )
    streamed_text = "".join(
        event.text for event in output if event.kind == "text_delta"
    )
    streamed_thinking = "".join(
        event.text for event in output if event.kind == "thinking_delta"
    )
    stable_tool_fields = [
        event.tool_call
        for event in output
        if event.kind == "tool_call_delta"
        and type(event.tool_call) is dict
        and any(field in event.tool_call for field in ("id", "type", "name"))
    ]
    assert streamed_text == "[S]"
    assert streamed_thinking == "[S]"
    assert streamed_arguments == "[S]"
    assert stable_tool_fields == [
        {"index": 0, "id": "[S]", "type": "[S]", "name": "[S]"}
    ]
    assert len(hook_responses) == 1
    assert hook_responses[0].model == "safe-model"
    assert hook_responses[0].content == "[S]"
    assert hook_responses[0].reasoning_content == "[S]"
    assert hook_responses[0].finish_reason == "stop-[S]"
    assert hook_responses[0].tool_calls == [
        {
            "id": "[S]",
            "type": "[S]",
            "function": {"name": "[S]", "arguments": "[S]"},
        }
    ]
    assert output[-1].finish_reason == "stop-[S]"


@pytest.mark.asyncio
async def test_router_stream_keeps_interleaved_text_thinking_and_tools_independent() -> None:
    secret = "INTERLEAVED-secret-12345"
    provider = _SyntheticProvider(
        secret=secret,
        events=[
            StreamEvent(kind="text_delta", text=secret[:6]),
            StreamEvent(kind="thinking_delta", text=secret[:7]),
            StreamEvent(
                kind="tool_call_delta",
                tool_call={"index": 0, "arguments_delta": secret[:8]},
            ),
            StreamEvent(
                kind="tool_call_delta",
                tool_call={"index": 1, "arguments_delta": secret[:9]},
            ),
            StreamEvent(kind="text_delta", text=secret[6:]),
            StreamEvent(kind="thinking_delta", text=secret[7:]),
            StreamEvent(
                kind="tool_call_delta",
                tool_call={"index": 1, "arguments_delta": secret[9:]},
            ),
            StreamEvent(
                kind="tool_call_delta",
                tool_call={"index": 0, "arguments_delta": secret[8:]},
            ),
            StreamEvent(kind="done", finish_reason="stop"),
        ],
    )
    router = _router(provider)
    hook_responses: list[ChatResponse] = []

    async def after(
        _context: Any,
        response: ChatResponse | None,
        error: BaseException | None,
    ) -> None:
        assert error is None
        assert response is not None
        hook_responses.append(response)

    output = [
        event
        async for event in router.chat_stream_events(
            [ChatMessage(role="user", content="hi")],
            model="safe-model",
            before_model_call=_before,
            after_model_call=after,
            permit_grant=_grant(router),
        )
    ]

    text = "".join(event.text for event in output if event.kind == "text_delta")
    thinking = "".join(
        event.text for event in output if event.kind == "thinking_delta"
    )
    tool_arguments: dict[int, str] = {0: "", 1: ""}
    for event in output:
        call = event.tool_call
        if event.kind != "tool_call_delta" or type(call) is not dict:
            continue
        index = call.get("index")
        arguments = call.get("arguments_delta")
        if type(index) is int and type(arguments) is str:
            tool_arguments[index] += arguments
    assert text == "[S]"
    assert thinking == "[S]"
    assert tool_arguments == {0: "[S]", 1: "[S]"}
    assert len(hook_responses) == 1
    assert [call["function"]["arguments"] for call in hook_responses[0].tool_calls] == [
        "[S]",
        "[S]",
    ]


@pytest.mark.asyncio
async def test_router_stream_cancellation_discards_existing_pending_prefix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prefix = _SECRET[:7]
    provider = _SyntheticProvider(secret=_SECRET)
    scrubbers: list[Any] = []
    base_scrubber = router_module._ProviderResponseStreamScrubber

    class CapturingResponseStreamScrubber(base_scrubber):
        def __init__(self, scrubber: ProviderSecretScrubber) -> None:
            super().__init__(scrubber)
            scrubbers.append(self)

    monkeypatch.setattr(
        router_module,
        "_ProviderResponseStreamScrubber",
        CapturingResponseStreamScrubber,
    )

    async def cancel_after_prefix(*_args: Any, **_kwargs: Any) -> AsyncIterator[StreamEvent]:
        yield StreamEvent(kind="text_delta", text=prefix)
        raise asyncio.CancelledError(_SECRET)

    provider.chat_stream_events = cancel_after_prefix  # type: ignore[method-assign]
    router = _router(provider)
    hook_errors: list[BaseException] = []

    async def after(
        _context: Any,
        response: ChatResponse | None,
        error: BaseException | None,
    ) -> None:
        assert response is None
        assert isinstance(error, asyncio.CancelledError)
        _assert_forms_absent(_SECRET, error)
        hook_errors.append(error)

    observed: list[StreamEvent] = []
    with pytest.raises(asyncio.CancelledError) as raised:
        async for event in router.chat_stream_events(
            [ChatMessage(role="user", content="hi")],
            model="safe-model",
            before_model_call=_before,
            after_model_call=after,
            permit_grant=_grant(router),
        ):
            observed.append(event)

    assert observed == []
    assert len(hook_errors) == 1
    _assert_forms_absent(_SECRET, raised.value)
    assert len(scrubbers) == 1
    assert scrubbers[0]._closed is True
    assert scrubbers[0]._channels
    assert all(channel._closed is True for channel in scrubbers[0]._channels.values())
    assert all(channel._pending == b"" for channel in scrubbers[0]._channels.values())


def test_response_stream_accepts_exact_total_byte_budget_then_rejects_next(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(router_module._ProviderResponseStreamScrubber, "_MAX_TOTAL_BYTES", 16)
    response_stream = router_module._ProviderResponseStreamScrubber(
        ProviderSecretScrubber([_SECRET])
    )

    response_stream.feed_text("text_delta", "x" * 16)

    assert response_stream._total_bytes == 16
    assert response_stream._closed is False
    with pytest.raises(ProviderSecretScrubError):
        response_stream.feed_text("thinking_delta", "y")
    assert response_stream._closed is True


@pytest.mark.asyncio
async def test_router_stream_total_input_budget_rejects_offending_event_without_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(router_module._ProviderResponseStreamScrubber, "_MAX_TOTAL_BYTES", 16)
    provider = _SyntheticProvider(
        secret=_SECRET,
        events=[
            StreamEvent(kind="text_delta", text="x" * 16),
            StreamEvent(kind="thinking_delta", text="y"),
            StreamEvent(kind="done"),
        ],
    )
    router = _router(provider)
    finalized: list[tuple[ChatResponse | None, BaseException | None]] = []

    async def after(
        _context: Any,
        response: ChatResponse | None,
        error: BaseException | None,
    ) -> None:
        finalized.append((response, error))

    observed: list[StreamEvent] = []
    with pytest.raises(ProviderSecretScrubError):
        async for event in router.chat_stream_events(
            [ChatMessage(role="user", content="hi")],
            model="safe-model",
            before_model_call=_before,
            after_model_call=after,
            permit_grant=_grant(router),
        ):
            observed.append(event)

    assert observed == []
    assert len(finalized) == 1
    assert finalized[0][0] is None
    assert isinstance(finalized[0][1], ProviderSecretScrubError)


@pytest.mark.asyncio
async def test_router_stream_error_discards_pending_prefix_and_error_state_is_safe() -> None:
    prefix = _SECRET[:6]
    provider = _SyntheticProvider(
        secret=_SECRET,
        events=[
            *[StreamEvent(kind="text_delta", text=char) for char in prefix],
            StreamEvent(kind="error", error="synthetic failure"),
        ],
    )
    router = _router(provider)
    after_errors: list[BaseException] = []

    async def after(_context: Any, response: Any, error: BaseException | None) -> None:
        assert response is None
        assert error is not None
        after_errors.append(error)

    output = [
        event
        async for event in router.chat_stream_events(
            [ChatMessage(role="user", content="hi")],
            model="safe-model",
            before_model_call=_before,
            after_model_call=after,
            permit_grant=_grant(router),
        )
    ]

    assert [event.kind for event in output] == ["error"]
    assert prefix not in repr(output)
    assert len(after_errors) == 1
    assert prefix not in repr(vars(after_errors[0]))


@pytest.mark.asyncio
async def test_router_completion_budget_discards_pending_secret_prefix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    instances: list[Any] = []
    original = router_module._ProviderResponseStreamScrubber

    class _ObservedStreamScrubber(original):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            instances.append(self)

    monkeypatch.setattr(
        router_module,
        "_ProviderResponseStreamScrubber",
        _ObservedStreamScrubber,
    )
    provider = _SyntheticProvider(
        secret=_SECRET,
        events=[
            *[StreamEvent(kind="text_delta", text=char) for char in _SECRET[:5]],
            StreamEvent(kind="done", finish_reason="stop"),
        ],
    )
    router = _router(provider)

    async def after(
        _context: Any,
        _response: ChatResponse | None,
        _error: BaseException | None,
    ) -> None:
        return None

    output = [
        event
        async for event in router.chat_stream_events(
            [ChatMessage(role="user", content="hi")],
            model="safe-model",
            max_tokens=1,
            before_model_call=_before,
            after_model_call=after,
            permit_grant=_grant(router),
        )
    ]

    assert output[-1].kind == "error"
    assert len(instances) == 1
    assert instances[0]._closed is True
    assert all(channel._pending == b"" for channel in instances[0]._channels.values())


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "usage",
    [
        {"prompt_tokens": True},
        {"prompt_tokens": -1},
        {"unknown_tokens": 1},
        {"prompt_tokens": "1"},
    ],
)
async def test_router_stream_rejects_untrusted_usage_event(usage: dict[str, Any]) -> None:
    provider = _SyntheticProvider(
        secret=_SECRET,
        events=[StreamEvent(kind="usage", usage=usage), StreamEvent(kind="done")],
    )
    router = _router(provider)

    async def after(_context: Any, response: Any, error: BaseException | None) -> None:
        assert response is None
        assert isinstance(error, ProviderSecretScrubError)

    with pytest.raises(ProviderSecretScrubError):
        async for _event in router.chat_stream_events(
            [ChatMessage(role="user", content="hi")],
            model="safe-model",
            before_model_call=_before,
            after_model_call=after,
            permit_grant=_grant(router),
        ):
            pass


@pytest.mark.asyncio
@pytest.mark.parametrize("index", [True, -1, "0", 1.0, None])
async def test_router_stream_rejects_noncanonical_tool_index(index: object) -> None:
    provider = _SyntheticProvider(
        secret=_SECRET,
        events=[
            StreamEvent(
                kind="tool_call_delta",
                tool_call={"index": index, "arguments_delta": "safe"},
            ),
            StreamEvent(kind="done"),
        ],
    )
    router = _router(provider)
    finalized: list[tuple[ChatResponse | None, BaseException | None]] = []

    async def after(
        _context: Any,
        response: ChatResponse | None,
        error: BaseException | None,
    ) -> None:
        finalized.append((response, error))

    observed: list[StreamEvent] = []
    with pytest.raises(ProviderSecretScrubError):
        async for event in router.chat_stream_events(
            [ChatMessage(role="user", content="hi")],
            model="safe-model",
            before_model_call=_before,
            after_model_call=after,
            permit_grant=_grant(router),
        ):
            observed.append(event)

    assert observed == []
    assert len(finalized) == 1
    assert finalized[0][0] is None
    assert isinstance(finalized[0][1], ProviderSecretScrubError)


@pytest.mark.asyncio
@pytest.mark.parametrize("channel_count, succeeds", [(128, True), (129, False)])
async def test_router_stream_enforces_active_tool_channel_limit(
    channel_count: int,
    succeeds: bool,
) -> None:
    events = [
        StreamEvent(
            kind="tool_call_delta",
            tool_call={"index": index, "arguments_delta": "x"},
        )
        for index in range(channel_count)
    ]
    events.append(StreamEvent(kind="done", finish_reason="tool_calls"))
    provider = _SyntheticProvider(secret=_SECRET, events=events)
    router = _router(provider)
    finalized: list[tuple[Any, BaseException | None]] = []

    async def after(_context: Any, response: Any, error: BaseException | None) -> None:
        finalized.append((response, error))

    stream = router.chat_stream_events(
        [ChatMessage(role="user", content="hi")],
        model="safe-model",
        before_model_call=_before,
        after_model_call=after,
        permit_grant=_grant(router),
    )
    if succeeds:
        output = [event async for event in stream]
        assert output[-1].kind == "done"
        assert len([event for event in output if event.kind == "tool_call_delta"]) == 128
        assert len(finalized) == 1
        assert len(finalized[0][0].tool_calls) == 128
    else:
        observed: list[StreamEvent] = []
        with pytest.raises(ProviderSecretScrubError):
            async for event in stream:
                observed.append(event)
        assert all(
            not (
                event.kind == "tool_call_delta"
                and isinstance(event.tool_call, dict)
                and event.tool_call.get("index") == 128
            )
            for event in observed
        )
        assert len(finalized) == 1
        assert finalized[0][0] is None
        assert isinstance(finalized[0][1], ProviderSecretScrubError)


@pytest.mark.asyncio
async def test_stream_fallback_discards_primary_prefix_and_uses_only_current_key() -> None:
    primary_secret = "PRIMARY-secret-12345"
    backup_secret = "BACKUP-secret-67890"
    prefix = primary_secret[:8]
    primary = _SyntheticProvider(
        secret=primary_secret,
        events=[
            *[StreamEvent(kind="text_delta", text=char) for char in prefix],
            StreamEvent(kind="error", error="primary unavailable"),
        ],
    )
    fallback_text = primary_secret[len(prefix) :] + "|" + backup_secret
    backup = _SyntheticProvider(
        secret=backup_secret,
        events=[
            *[StreamEvent(kind="text_delta", text=char) for char in fallback_text],
            StreamEvent(kind="done", finish_reason="stop"),
        ],
    )
    router = ModelRouter(JSSettings(providers=[]), permit_verifier=ModelPermitIssuer())
    primary_model = ModelConfig(id="primary-model", name="Primary")
    backup_model = ModelConfig(id="backup-model", name="Backup")
    router.add_provider("primary", primary, [primary_model])
    router.add_provider("backup", backup, [backup_model])

    async def select_primary(*_args: Any, **_kwargs: Any) -> Any:
        from js.models.router import RoutingDecision

        return RoutingDecision(primary, "primary-model", "primary", "test")

    router.select_model = select_primary  # type: ignore[method-assign]
    finalized: list[tuple[str, ChatResponse | None, BaseException | None]] = []

    async def before(decision: Any, *_args: Any) -> str:
        return str(decision.provider_name)

    async def after(
        context: str,
        response: ChatResponse | None,
        error: BaseException | None,
    ) -> None:
        finalized.append((context, response, error))

    output = [
        event
        async for event in router.chat_stream_events(
            [ChatMessage(role="user", content="hi")],
            model=None,
            before_model_call=before,
            after_model_call=after,
            permit_grant=_grant(router),
        )
    ]
    text = "".join(event.text for event in output if event.kind == "text_delta")
    assert prefix not in text
    assert primary_secret not in text
    assert backup_secret not in text
    assert text == primary_secret[len(prefix) :] + "|[S]"
    assert [item[0] for item in finalized] == ["primary", "backup"]
    assert finalized[0][1] is None and finalized[0][2] is not None
    assert finalized[1][1] is not None and finalized[1][2] is None
