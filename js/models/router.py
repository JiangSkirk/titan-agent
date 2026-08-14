"""Intelligent model routing with fallback and cost optimization."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator, AsyncIterator, Awaitable, Callable
from contextlib import aclosing
from dataclasses import dataclass
from typing import Any, Literal, cast

from cachetools import TTLCache

from js.config import JSSettings, ModelConfig
from js.echo.ledger.service import EchoBlockedError, EchoUnavailableError
from js.echo.model_budget import EchoBudgetExceededError
from js.echo.turn_context import current_runtime_context
from js.models.capability import (
    SafeProviderError,
    reraise_safe_provider_error,
    safe_provider_error,
)
from js.models.permit import ModelPermitError
from js.models.providers import (
    ChatMessage,
    ChatResponse,
    ModelProvider,
    OpenAICompatibleProvider,
    is_retryable_provider_error,
)
from js.models.stream_events import StreamEvent
from js.security.egress import (
    LOOPBACK_EXEMPTION_RECEIPT,
    EgressAttemptV1,
    EgressConsentError,
    EgressConsentReceiptV1,
    EgressIdentityV1,
    build_egress_attempt,
    classify_provider_endpoint,
    consume_egress_receipt,
    digest_jsonable,
    endpoint_digest,
    freeze_messages,
    freeze_tools,
    provider_endpoint_digest,
    provider_endpoint_url,
    provider_generation_of,
    safe_egress_summary,
)
from js.security.secrets import (
    ProviderSecretScrubber,
    ProviderSecretScrubError,
    ProviderSecretStream,
)

_NO_ROUTER_FALLBACK_ATTR = "_js_router_no_fallback"
_MAX_ROUTER_PROVIDER_ATTEMPTS = 5
_MAX_PROVIDER_USAGE_VALUE = (1 << 63) - 1
_ALLOWED_USAGE_KEYS = frozenset(
    {
        "prompt_tokens",
        "completion_tokens",
        "total_tokens",
        "cached_tokens",
        "provider_reported_prompt_tokens",
        "provider_reported_completion_tokens",
        "provider_reported_total_tokens",
    }
)
_ALLOWED_USAGE_SOURCES = frozenset(
    {"provider_actual", "tokenizer", "estimated", "unavailable"}
)
_MAX_PROVIDER_SECRET_STREAM_CHANNELS = 128

_ALLOWED_ERROR_META: dict[str, type] = {
    "retryable": bool,
    "completion_tokens": int,
    "prompt_tokens": int,
    "token_source": str,
    "echo_error_code": str,
    "provider_reported_prompt_tokens": int,
    "provider_reported_completion_tokens": int,
    "provider_reported_total_tokens": int,
}

# Per-kind meta allowlists. Non-error stream frames intentionally keep meta empty
# so custom providers cannot smuggle credentials or forge diagnostic bags.
_ALLOWED_STREAM_META: dict[str, dict[str, type]] = {
    "text_delta": {},
    "thinking_delta": {},
    "tool_call_delta": {},
    "usage": {},
    "done": {},
    "error": _ALLOWED_ERROR_META,
}


def _filter_stream_meta(kind: str, meta: dict[str, Any] | None) -> dict[str, Any]:
    """Keep only allowlisted meta keys for the given stream event kind."""
    if not meta or type(meta) is not dict:
        return {}
    allowed = _ALLOWED_STREAM_META.get(kind, {})
    if not allowed:
        return {}
    filtered: dict[str, Any] = {}
    for key, expected_type in allowed.items():
        if key not in meta:
            continue
        value = meta[key]
        if type(value) is expected_type:
            filtered[key] = value
    return filtered


def _filter_error_meta(meta: dict[str, Any] | None) -> dict[str, Any]:
    """Keep only allowlisted error meta keys with strict runtime types."""
    return _filter_stream_meta("error", meta)


def _rebuild_error_event(
    ev: StreamEvent | None,
    decision: RoutingDecision,
    safe_error: BaseException | str,
    *,
    failure_meta: dict[str, Any] | None = None,
) -> StreamEvent:
    """Rebuild a terminal error event from trusted routing + scrubbed text only."""
    meta = _filter_error_meta(failure_meta)
    if isinstance(safe_error, SafeProviderError) and "retryable" not in meta:
        meta["retryable"] = safe_error.retryable
    return StreamEvent(
        kind="error",
        error=str(safe_error),
        provider=decision.provider_name,
        model=decision.model,
        meta=meta,
    )


def _sanitize_with_provider(exc: BaseException, provider: ModelProvider) -> str:
    return str(_as_safe_provider_error(exc, provider))


def _as_safe_provider_error(exc: BaseException, provider: ModelProvider) -> SafeProviderError:
    """Ensure provider failures observed by the router are :class:`SafeProviderError`.

    Real ``OpenAICompatibleProvider`` exits already raise SafeProviderError.
    This helper covers mock/legacy providers and aggregation so logs and
    fallback messages never embed raw credential-bearing exception text.

    Always re-scrubs provider-aware — do not trust custom/legacy SafeProviderError
    messages that may have skipped sanitization.
    """
    from js.models.capability import sanitize_provider_error

    api_key = getattr(getattr(provider, "config", None), "api_key", None)
    query_param = getattr(getattr(provider, "config", None), "query_param_name", None)
    if isinstance(exc, SafeProviderError):
        message = sanitize_provider_error(
            str(exc),
            api_key=api_key,
            query_param_name=query_param,
        )
        return SafeProviderError(message, retryable=exc.retryable)
    return safe_provider_error(
        exc,
        api_key=api_key,
        query_param_name=query_param,
        retryable=is_retryable_provider_error(exc),
    )


class _StreamCompletionBudgetExceededError(RuntimeError):
    is_stream_completion_budget_exceeded = True

    def __init__(self, completion_tokens: int) -> None:
        super().__init__("Echo budget exceeded: completion_tokens_exceeded")
        self.completion_tokens = completion_tokens


class _SafeCancelledError(asyncio.CancelledError):
    def __init__(self, message: str = "[S]") -> None:
        super().__init__(message)

    def __repr__(self) -> str:
        return "[S]"


@dataclass(frozen=True, slots=True)
class _FailureSnapshot:
    category: str
    message: str = "[S]"
    retryable: bool = False
    no_fallback: bool = False


@dataclass
class RoutingDecision:
    provider: ModelProvider
    model: str
    provider_name: str
    reason: str


def _mark_no_router_fallback(exc: BaseException) -> None:
    if isinstance(exc, (ProviderSecretScrubError, _SafeCancelledError)):
        return
    try:
        setattr(exc, _NO_ROUTER_FALLBACK_ATTR, True)
    except Exception:
        pass


def _is_no_router_fallback(exc: BaseException) -> bool:
    return isinstance(
        exc,
        (
            ProviderSecretScrubError,
            _SafeCancelledError,
            EgressConsentError,
            ModelPermitError,
        ),
    ) or bool(getattr(exc, _NO_ROUTER_FALLBACK_ATTR, False))


def _failure_snapshot(
    exc: BaseException,
    scrubber: ProviderSecretScrubber | None,
    provider: ModelProvider,
) -> _FailureSnapshot:
    """Detach a provider failure from tainted traceback frames and values."""
    if isinstance(exc, ProviderSecretScrubError):
        return _FailureSnapshot(category="scrub", no_fallback=True)
    if isinstance(exc, asyncio.CancelledError):
        if scrubber is None:
            return _FailureSnapshot(category="cancel", no_fallback=True)
        return _FailureSnapshot(
            category="cancel",
            message=_safe_exception_message(scrubber, exc),
            no_fallback=True,
        )
    if scrubber is None:
        return _FailureSnapshot(category="scrub", no_fallback=True)
    try:
        if isinstance(exc, PermissionError):
            message = _safe_exception_message(scrubber, exc)
            return _FailureSnapshot(
                category="permission",
                message=message,
                no_fallback=True,
            )
        retryable = (
            exc.retryable
            if isinstance(exc, SafeProviderError)
            else is_retryable_provider_error(exc)
        )
        # Exact-scrub the original message before the legacy sanitizer.  The
        # latter intentionally retains four-character key prefixes/suffixes
        # and therefore must never be the first B1C boundary.
        exact_message = _safe_exception_message(scrubber, exc)
        safe = _as_safe_provider_error(
            SafeProviderError(exact_message, retryable=retryable),
            provider,
        )
        message = _safe_exception_message(scrubber, safe)
        return _FailureSnapshot(
            category="safe",
            message=message,
            retryable=safe.retryable,
            no_fallback=_is_no_router_fallback(exc),
        )
    except BaseException:
        return _FailureSnapshot(category="scrub", no_fallback=True)


def _materialize_failure(snapshot: _FailureSnapshot) -> BaseException:
    """Create one fresh outward exception with no cause, context, or traceback."""
    if snapshot.category == "cancel":
        error: BaseException = _SafeCancelledError(snapshot.message)
    elif snapshot.category == "generator_exit":
        error = GeneratorExit()
    elif snapshot.category in {"closed", "runtime"}:
        error = RuntimeError(snapshot.message)
    elif snapshot.category == "os":
        error = OSError(snapshot.message)
    elif snapshot.category == "permission":
        error = PermissionError(snapshot.message)
    elif snapshot.category == "echo_blocked":
        error = EchoBlockedError(snapshot.message)
    elif snapshot.category == "echo_unavailable":
        error = EchoUnavailableError(snapshot.message)
    elif snapshot.category == "echo_budget":
        error = EchoBudgetExceededError(snapshot.message)
    elif snapshot.category == "safe":
        error = SafeProviderError(snapshot.message, retryable=snapshot.retryable)
    else:
        error = ProviderSecretScrubError()
    if snapshot.no_fallback:
        _mark_no_router_fallback(error)
    return error


def _safe_outward_message(scrubber: ProviderSecretScrubber, message: str) -> str:
    """Return one exact-scrubbed outward diagnostic or the opaque marker."""
    try:
        return scrubber.redact_text(message) or "[S]"
    except ProviderSecretScrubError:
        return "[S]"


def _safe_exception_message(
    scrubber: ProviderSecretScrubber,
    error: BaseException,
) -> str:
    """Stringify an exception without allowing hostile ``__str__`` to escape."""
    try:
        message = str(error)
    except BaseException:
        return "[S]"
    return _safe_outward_message(scrubber, message)


def _hook_failure_snapshot(
    exc: BaseException,
    scrubber: ProviderSecretScrubber | None,
    provider: ModelProvider,
) -> _FailureSnapshot:
    """Detach an after-hook failure while retaining supported control types."""
    try:
        if scrubber is None:
            return _FailureSnapshot(category="scrub", no_fallback=True)
        if isinstance(exc, EchoBlockedError):
            return _FailureSnapshot(
                category="echo_blocked",
                message=_safe_exception_message(scrubber, exc),
                no_fallback=True,
            )
        if isinstance(exc, EchoUnavailableError):
            return _FailureSnapshot(
                category="echo_unavailable",
                message=_safe_exception_message(scrubber, exc),
                no_fallback=True,
            )
        if isinstance(exc, EchoBudgetExceededError):
            return _FailureSnapshot(
                category="echo_budget",
                message=_safe_exception_message(scrubber, exc),
                no_fallback=True,
            )
        if isinstance(exc, GeneratorExit):
            return _FailureSnapshot(category="generator_exit", no_fallback=True)
        if type(exc) in {OSError, RuntimeError}:
            return _FailureSnapshot(
                category="os" if type(exc) is OSError else "runtime",
                message=_safe_exception_message(scrubber, exc),
                no_fallback=True,
            )
        return _failure_snapshot(exc, scrubber, provider)
    except BaseException:
        return _FailureSnapshot(category="scrub", no_fallback=True)


def _secret_scrub_failure() -> ProviderSecretScrubError:
    error = ProviderSecretScrubError()
    _mark_no_router_fallback(error)
    return error


def _scrubber_for_decision(decision: RoutingDecision) -> ProviderSecretScrubber:
    configured_values = (
        getattr(getattr(decision.provider, "config", None), "api_key", None),
    )
    return _scrubber_for_values(decision, configured_values)


def _scrubber_for_values(
    decision: RoutingDecision,
    configured_values: tuple[object, ...],
) -> ProviderSecretScrubber:
    secrets: list[str] = []
    for configured in configured_values:
        if configured is None or configured == "":
            continue
        if type(configured) is not str:
            raise _secret_scrub_failure()
        if configured not in secrets:
            secrets.append(configured)
    try:
        scrubber = ProviderSecretScrubber(secrets)
        # Routing identity cannot be rewritten without breaking attribution.
        # If it collides with the active secret, fail before provider I/O.
        for trusted_identity in (
            decision.provider_name,
            decision.model,
            *_ALLOWED_USAGE_SOURCES,
            *_ALLOWED_STREAM_META,
            *_ALLOWED_USAGE_KEYS,
            *_ALLOWED_ERROR_META,
            "kind",
            "text",
            "tool_call",
            "usage",
            "finish_reason",
            "error",
            "provider",
            "model",
            "meta",
            "content",
            "tool_calls",
            "reasoning_content",
            "usage_source",
            "index",
            "id",
            "type",
            "name",
            "arguments_delta",
            "function",
            "arguments",
            "assistant_text",
            "estimated_completion_tokens",
            _NO_ROUTER_FALLBACK_ATTR,
            "ChatResponse",
            "StreamEvent",
            "SafeProviderError",
            "PermissionError",
            "EchoBlockedError",
            "EchoUnavailableError",
            "ProviderSecretScrubError",
            "CancelledError",
            "_SafeCancelledError",
            "_StreamCompletionBudgetExceededError",
            "RuntimeError",
            "OSError",
            "is_stream_completion_budget_exceeded",
            "completion_tokens_exceeded",
            "Echo budget exceeded: completion_tokens_exceeded",
            __file__,
        ):
            if scrubber.redact_text(trusted_identity) != trusted_identity:
                raise ProviderSecretScrubError
        return scrubber
    except ProviderSecretScrubError:
        raise _secret_scrub_failure() from None


def _normalize_provider_usage(value: object) -> dict[str, int]:
    if type(value) is not dict:
        raise _secret_scrub_failure()
    normalized: dict[str, int] = {}
    for key, count in value.items():
        if (
            type(key) is not str
            or key not in _ALLOWED_USAGE_KEYS
            or type(count) is not int
            or count < 0
            or count > _MAX_PROVIDER_USAGE_VALUE
        ):
            raise _secret_scrub_failure()
        normalized[key] = count
    return normalized


def _sanitize_chat_response(
    raw: object,
    decision: RoutingDecision,
    scrubber: ProviderSecretScrubber,
) -> ChatResponse:
    try:
        if type(raw) is not ChatResponse:
            raise ProviderSecretScrubError
        if raw.usage_source not in _ALLOWED_USAGE_SOURCES:
            raise ProviderSecretScrubError
        safe_fields = scrubber.redact_value(
            {
                "content": raw.content,
                "tool_calls": raw.tool_calls,
                "finish_reason": raw.finish_reason,
                "reasoning_content": raw.reasoning_content,
                "usage_source": raw.usage_source,
            }
        )
        if type(safe_fields) is not dict:
            raise ProviderSecretScrubError
        safe_tools = safe_fields.get("tool_calls")
        if type(safe_tools) is not list or any(
            type(tool_call) is not dict for tool_call in safe_tools
        ):
            raise ProviderSecretScrubError
        content = safe_fields.get("content")
        finish_reason = safe_fields.get("finish_reason")
        reasoning_content = safe_fields.get("reasoning_content")
        usage_source = safe_fields.get("usage_source")
        if not all(
            type(value) is str
            for value in (content, finish_reason, reasoning_content, usage_source)
        ):
            raise ProviderSecretScrubError
        safe_content = cast("str", content)
        safe_finish_reason = cast("str", finish_reason)
        safe_reasoning_content = cast("str", reasoning_content)
        safe_usage_source = cast(
            "Literal['provider_actual', 'tokenizer', 'estimated', 'unavailable']",
            usage_source,
        )
        return ChatResponse(
            content=safe_content,
            tool_calls=safe_tools,
            model=decision.model,
            usage=_normalize_provider_usage(raw.usage),
            finish_reason=safe_finish_reason,
            reasoning_content=safe_reasoning_content,
            usage_source=safe_usage_source,
        )
    except ProviderSecretScrubError:
        raise _secret_scrub_failure() from None


class _ProviderResponseStreamScrubber:
    """Per-attempt exact-value channels for successful Provider stream data."""

    _TOOL_FIELDS = frozenset({"id", "type", "name", "arguments_delta"})
    _MAX_TOTAL_BYTES = 16 * 1024 * 1024

    def __init__(self, scrubber: ProviderSecretScrubber) -> None:
        self._scrubber = scrubber
        self._channels: dict[tuple[object, ...], ProviderSecretStream] = {}
        self._tool_values: dict[int, dict[str, list[str]]] = {}
        self._total_bytes = 0
        self._closed = False

    def _record_input(self, value: object) -> str:
        if type(value) is not str:
            raise _secret_scrub_failure()
        try:
            size = len(value.encode("utf-8"))
        except UnicodeEncodeError:
            raise _secret_scrub_failure() from None
        self._total_bytes += size
        if self._total_bytes > self._MAX_TOTAL_BYTES:
            self.discard()
            raise _secret_scrub_failure()
        return value

    def _channel(self, key: tuple[object, ...]) -> ProviderSecretStream:
        if self._closed:
            raise _secret_scrub_failure()
        channel = self._channels.get(key)
        if channel is not None:
            return channel
        if len(self._channels) >= _MAX_PROVIDER_SECRET_STREAM_CHANNELS:
            self.discard()
            raise _secret_scrub_failure()
        channel = self._scrubber.open_stream()
        self._channels[key] = channel
        return channel

    def _feed(self, key: tuple[object, ...], value: object) -> str:
        text = self._record_input(value)
        try:
            return self._channel(key).feed(text)
        except ProviderSecretScrubError:
            self.discard()
            raise _secret_scrub_failure() from None

    def feed_text(self, kind: str, value: object) -> str:
        if kind not in {"text_delta", "thinking_delta"}:
            raise _secret_scrub_failure()
        return self._feed((kind,), value)

    def feed_tool(self, raw: object) -> dict[str, object] | None:
        if type(raw) is not dict:
            raise _secret_scrub_failure()
        if any(type(key) is not str for key in raw) or not set(raw) <= {
            "index",
            *self._TOOL_FIELDS,
        }:
            raise _secret_scrub_failure()
        index = raw.get("index")
        if type(index) is not int or index < 0:
            raise _secret_scrub_failure()
        present_fields = self._TOOL_FIELDS.intersection(raw)
        if not present_fields:
            raise _secret_scrub_failure()
        if index not in self._tool_values and len(self._tool_values) >= (
            _MAX_PROVIDER_SECRET_STREAM_CHANNELS
        ):
            self.discard()
            raise _secret_scrub_failure()
        values = self._tool_values.setdefault(
            index,
            {"id": [], "type": [], "name": [], "arguments_delta": []},
        )
        emitted_arguments = ""
        for field_name in ("id", "type", "name", "arguments_delta"):
            if field_name not in raw:
                continue
            safe = self._feed(("tool", index, field_name), raw[field_name])
            if safe:
                values[field_name].append(safe)
                if field_name == "arguments_delta":
                    emitted_arguments += safe
        # Tool identifiers are overwrite fields in the existing consumer, not
        # append-only deltas. Hold the complete safe call until finish so a
        # provider cannot make character-split ids/names collapse to the final
        # character. Arguments retain their delta field shape at publication.
        if emitted_arguments:
            return {"index": index, "arguments_delta": emitted_arguments}
        return None

    def finish(
        self,
    ) -> tuple[str, str, list[dict[str, object]], list[dict[str, object]]]:
        if self._closed:
            raise _secret_scrub_failure()
        emitted_tool_events: list[dict[str, object]] = []
        response_tool_calls: list[dict[str, object]] = []
        try:
            text_tail = self._flush_channel(("text_delta",))
            thinking_tail = self._flush_channel(("thinking_delta",))
            for index in sorted(self._tool_values):
                values = self._tool_values[index]
                argument_tail = ""
                for field_name in ("id", "type", "name", "arguments_delta"):
                    tail = self._flush_channel(("tool", index, field_name))
                    if tail:
                        values[field_name].append(tail)
                        if field_name == "arguments_delta":
                            argument_tail += tail
                stable_delta: dict[str, object] = {"index": index}
                for field_name in ("id", "type", "name"):
                    combined = "".join(values[field_name])
                    if combined:
                        stable_delta[field_name] = combined
                arguments = "".join(values["arguments_delta"])
                if argument_tail:
                    stable_delta["arguments_delta"] = argument_tail
                if len(stable_delta) > 1:
                    emitted_tool_events.append(stable_delta)
                call: dict[str, object] = {
                    "type": "".join(values["type"]) or "function",
                    "function": {
                        "name": "".join(values["name"]),
                        "arguments": arguments,
                    },
                }
                call_id = "".join(values["id"])
                if call_id:
                    call["id"] = call_id
                response_tool_calls.append(call)
            self._closed = True
            return text_tail, thinking_tail, emitted_tool_events, response_tool_calls
        except ProviderSecretScrubError:
            self.discard()
            raise _secret_scrub_failure() from None

    def _flush_channel(self, key: tuple[object, ...]) -> str:
        channel = self._channels.get(key)
        if channel is None:
            return ""
        try:
            return channel.flush()
        except ProviderSecretScrubError:
            raise _secret_scrub_failure() from None

    def discard(self) -> None:
        for channel in self._channels.values():
            channel.discard()
        self._closed = True


def _provider_attempt_limit(provider: ModelProvider) -> int:
    configured = getattr(provider, "_max_retries_snapshot", None)
    if configured is None:
        configured = getattr(getattr(provider, "config", None), "max_retries", 1)
    try:
        attempts = int(configured if configured is not None else 1)
    except (TypeError, ValueError):
        attempts = 1
    return max(1, min(attempts, _MAX_ROUTER_PROVIDER_ATTEMPTS))


def _stream_chat_response(
    *,
    model: str,
    text: str,
    usage: dict[str, int],
    finish_reason: str,
    estimated_completion_tokens: int,
    reasoning_content: str,
    tool_calls: list[dict[str, object]],
) -> ChatResponse:
    response_usage = (
        dict(usage)
        if usage
        else {
            "prompt_tokens": 0,
            "completion_tokens": estimated_completion_tokens,
            "total_tokens": estimated_completion_tokens,
            "cached_tokens": 0,
        }
    )
    prompt_tokens = int(response_usage.get("prompt_tokens", 0) or 0)
    provider_completion_tokens = int(response_usage.get("completion_tokens", 0) or 0)
    completion_tokens = max(provider_completion_tokens, estimated_completion_tokens)
    provider_total_tokens = int(
        response_usage.get("total_tokens", prompt_tokens + provider_completion_tokens) or 0
    )
    total_tokens = max(provider_total_tokens, prompt_tokens + completion_tokens)
    cached_tokens = int(response_usage.get("cached_tokens", 0) or 0)
    conservative_override = bool(usage) and completion_tokens > provider_completion_tokens
    normalized_usage = {
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": total_tokens,
        "cached_tokens": cached_tokens,
    }
    if conservative_override:
        normalized_usage["provider_reported_completion_tokens"] = provider_completion_tokens
        normalized_usage["provider_reported_total_tokens"] = provider_total_tokens
    return ChatResponse(
        content=text,
        tool_calls=tool_calls,
        model=model,
        usage=normalized_usage,
        finish_reason=finish_reason,
        reasoning_content=reasoning_content,
        usage_source="provider_actual" if usage and not conservative_override else "estimated",
    )


def _annotate_stream_failure(
    error: BaseException,
    *,
    text: str,
    usage: dict[str, int],
    estimated_completion_tokens: int,
) -> dict[str, int | str]:
    provider_completion_tokens = int(usage.get("completion_tokens", 0) or 0)
    completion_tokens = max(provider_completion_tokens, estimated_completion_tokens)
    token_source = (
        "provider_actual"
        if usage and provider_completion_tokens >= estimated_completion_tokens
        else "estimated"
    )
    details: dict[str, int | str] = {
        "completion_tokens": completion_tokens,
        "token_source": token_source,
    }
    if getattr(error, "is_stream_completion_budget_exceeded", False):
        details["echo_error_code"] = "completion_tokens_exceeded"
    if usage:
        provider_prompt_tokens = int(usage.get("prompt_tokens", 0) or 0)
        provider_total_tokens = int(
            usage.get(
                "total_tokens",
                provider_prompt_tokens + provider_completion_tokens,
            )
            or 0
        )
        details.update(
            prompt_tokens=provider_prompt_tokens,
            provider_reported_prompt_tokens=provider_prompt_tokens,
            provider_reported_completion_tokens=provider_completion_tokens,
            provider_reported_total_tokens=provider_total_tokens,
        )
    try:
        error.__dict__.update(
            assistant_text=text,
            **details,
        )
    except Exception:
        pass
    return details


def _stream_failure_completion(event: StreamEvent | None, error: BaseException | None) -> int:
    value: Any = None
    if event is not None:
        value = event.meta.get("completion_tokens")
    if value is None and error is not None:
        value = getattr(error, "completion_tokens", None)
    return max(0, value) if type(value) is int else 0


class ModelSwitchValidationError(Exception):
    """Raised when a model switch is rejected with a status code and detail."""

    def __init__(self, status_code: int, detail: str, *, needs_config: bool = False) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail
        self.needs_config = needs_config


def validate_model_for_activation(
    model_id: str,
    configured_providers: set[str],
    *,
    get_model_binding: Callable[[str], tuple[str, ModelConfig] | None] | None = None,
    get_preset: Callable[[str], Any] | None = None,
    provider_models: dict[str, set[str]] | None = None,
) -> None:
    """Validate that a model_id may become the active model.

    This is a shared pure function used by both the HTTP endpoint
    (``server.py``) and the control-plane tool (``tool_executor.py``)
    so the two layers can never drift.

    Rules (fail-closed):
    1. Extract ``provider_name`` from ``model_id`` (``"provider/model"``).
    2. If ``provider_name`` is **not** in ``configured_providers``:
       - If ``get_preset`` says it is a known preset -> raise 409
         ``needs_config``.
       - Otherwise -> raise 400 invalid.
       Router mappings (stale or dynamic) are **irrelevant** here:
       a mapping alone does not prove the provider is configured.
    3. If ``provider_name`` **is** configured, the model must still be
       explicitly declared.  Accept if any of:
       - ``provider_models`` maps ``provider_name`` to a set containing
         ``model_suffix`` (declared in ``settings.models``); **or**
       - ``get_model_binding(model_id)`` returns a tuple whose
         ``[0]`` equals ``provider_name`` and whose ``[1].id`` equals
         ``model_suffix``; **or**
       - ``get_model_binding(model_suffix)`` returns a tuple whose
         ``[0]`` equals ``provider_name`` and whose ``[1].id`` equals
         ``model_suffix``.
    4. Otherwise -> raise 400 invalid.
    """
    provider_name = model_id.split("/", 1)[0] if "/" in model_id else ""

    if provider_name not in configured_providers:
        if get_preset is not None:
            try:
                if get_preset(provider_name) is not None:
                    raise ModelSwitchValidationError(
                        409,
                        (
                            f"Provider '{provider_name}' 尚未配置，"
                            "请先添加该云模型并填写 API Key。"
                        ),
                        needs_config=True,
                    )
            except ModelSwitchValidationError:
                raise
            except Exception:
                pass
        raise ModelSwitchValidationError(400, f"Invalid model '{model_id}'")

    model_suffix = model_id.split("/", 1)[1] if "/" in model_id else model_id

    if provider_models is not None:
        declared = provider_models.get(provider_name)
        if declared and model_suffix in declared:
            return

    if get_model_binding is not None:
        try:
            binding = get_model_binding(model_id)
        except Exception:
            binding = None
        if binding is not None and isinstance(binding, tuple) and len(binding) == 2:
            bp_name, bp_config = binding
            if (
                isinstance(bp_name, str)
                and isinstance(bp_config, ModelConfig)
                and bp_name == provider_name
                and bp_config.id == model_suffix
            ):
                return
        try:
            binding_short = get_model_binding(model_suffix)
        except Exception:
            binding_short = None
        if binding_short is not None and isinstance(binding_short, tuple) and len(binding_short) == 2:
            bp_name, bp_config = binding_short
            if (
                isinstance(bp_name, str)
                and isinstance(bp_config, ModelConfig)
                and bp_name == provider_name
                and bp_config.id == model_suffix
            ):
                return

    raise ModelSwitchValidationError(400, f"Invalid model '{model_id}'")


class ModelRouter:
    """Routes requests to appropriate models with health checks and fallback."""

    # Class-level default so subclasses that bypass ``__init__`` still fail
    # closed at the permit gate instead of raising AttributeError.
    _permit_verifier: Any | None = None

    def __init__(
        self,
        settings: JSSettings,
        *,
        permit_verifier: Any | None = None,
        egress_consent_broker: Any | None = None,
    ) -> None:
        self.settings = settings
        self._providers: dict[str, ModelProvider] = {}
        self._registered_provider_secrets: dict[int, tuple[object, ...]] = {}
        self._model_map: dict[
            str, tuple[str, ModelConfig]
        ] = {}  # model_id -> (provider_name, config)
        self._routing_cache: TTLCache[str, RoutingDecision] = TTLCache(maxsize=50, ttl=10)
        self.preferred_model: str | None = None
        # Unforgeable single-use permit verifier owned by the Echo turn runtime.
        # There is deliberately no public setter: authorization identity comes
        # from this cryptographic capability, not from rebindable callbacks.
        self._permit_verifier = permit_verifier
        self._egress_consent_broker = egress_consent_broker
        self._init_providers()

    def bind_egress_consent_broker(self, broker: Any) -> None:
        if self._egress_consent_broker is not None:
            raise RuntimeError("egress consent broker already bound")
        self._egress_consent_broker = broker

    @staticmethod
    def _current_provider_secret(provider: ModelProvider) -> object:
        try:
            snapshot = getattr(provider, "response_secret_snapshot", None)
            if callable(snapshot):
                return snapshot()
            return getattr(getattr(provider, "config", None), "api_key", None)
        except BaseException:
            raise _secret_scrub_failure() from None

    def _remember_provider_secret(self, provider: ModelProvider) -> None:
        """Bind a credential snapshot to one registered Provider generation."""
        registry = getattr(self, "_registered_provider_secrets", None)
        if type(registry) is not dict:
            registry = {}
            self._registered_provider_secrets = registry
        registry[id(provider)] = (
            self._current_provider_secret(provider),
        )

    def _provider_secret_values(self, provider: ModelProvider) -> tuple[object, ...]:
        """Return the immutable credential bound to a Provider generation."""
        registry = getattr(self, "_registered_provider_secrets", {})
        values = list(registry.get(id(provider), ())) if type(registry) is dict else []
        if not values:
            # A decision may outlive removal from the routing table.  The
            # Provider itself remains the authority for its frozen generation.
            values.append(self._current_provider_secret(provider))
        unique: list[object] = []
        for value in values:
            if value not in unique:
                unique.append(value)
        return tuple(unique)

    def _decision(
        self,
        *,
        provider: ModelProvider,
        model: str,
        provider_name: str,
        reason: str,
    ) -> RoutingDecision:
        return RoutingDecision(
            provider=provider,
            model=model,
            provider_name=provider_name,
            reason=reason,
        )

    def _scrubber_for_registered_decision(
        self,
        decision: RoutingDecision,
    ) -> ProviderSecretScrubber:
        return _scrubber_for_values(
            decision,
            self._provider_secret_values(decision.provider),
        )

    def _consume_model_permit(
        self,
        permit_grant: Callable[
            [RoutingDecision, list[ChatMessage], list[dict[str, Any]] | None], Any
        ],
        decision: RoutingDecision,
        messages: list[ChatMessage],
        tools: list[dict[str, Any]] | None,
        *,
        attempt: EgressAttemptV1 | None = None,
        receipt: EgressConsentReceiptV1 | None = None,
        classification: str = "invalid",
    ) -> None:
        """Issue-and-verify a fresh single-use permit for one provider attempt.

        Called after egress consent (when required) and the before-hook
        re-check, immediately before transport.  Fails closed: a
        missing/invalid verifier or a forged, expired, mismatched, or
        replayed permit aborts the call before any provider code runs.
        Unbound ``permit_grant`` results never reach a provider method.
        """
        del permit_grant, classification
        if self._permit_verifier is None:
            raise ModelPermitError(
                "ModelRouter has no Echo permit verifier; direct provider calls "
                "are only available through the Echo turn runtime."
            )
        if attempt is None:
            raise ModelPermitError("model permit requires a bound egress attempt")
        try:
            issuer = self._permit_verifier
            if not callable(getattr(issuer, "issue", None)):
                raise ModelPermitError("model permit issuer is unavailable")
            consent_hash = (
                receipt.claim_receipt_hash
                if receipt is not None
                else LOOPBACK_EXEMPTION_RECEIPT
            )
            if not attempt.attempt_hash:
                raise ModelPermitError("model permit requires a bound egress attempt")
            permit = issuer.issue(
                provider_name=decision.provider_name,
                model=decision.model,
                messages=messages,
                tools=tools,
                owner_key_hash=attempt.owner_key_hash,
                session_id=attempt.session_id,
                run_id=attempt.run_id,
                attempt_hash=attempt.attempt_hash,
                consent_receipt_hash=consent_hash,
                channel=attempt.channel,
                provider_generation=attempt.provider_generation,
                endpoint_digest=attempt.endpoint_digest,
                attachments_digest=attempt.attachments_digest,
                provenance_digest=attempt.provenance_digest,
                temperature=attempt.temperature,
                effective_max_tokens=attempt.effective_max_tokens,
                appshell_epoch=attempt.appshell_epoch,
            )
            if (
                getattr(permit, "attempt_hash", "") != attempt.attempt_hash
                or getattr(permit, "endpoint_digest", "") != attempt.endpoint_digest
                or getattr(permit, "provider_generation", "") != attempt.provider_generation
            ):
                raise ModelPermitError("model permit is not bound to the egress attempt")
            self._permit_verifier.verify_and_consume(
                permit,
                provider_name=decision.provider_name,
                model=decision.model,
                messages=messages,
                tools=tools,
                owner_key_hash=attempt.owner_key_hash,
                session_id=attempt.session_id,
                run_id=attempt.run_id,
                attempt_hash=attempt.attempt_hash,
                consent_receipt_hash=consent_hash,
                channel=attempt.channel,
                provider_generation=attempt.provider_generation,
                endpoint_digest=attempt.endpoint_digest,
                attachments_digest=attempt.attachments_digest,
                provenance_digest=attempt.provenance_digest,
                temperature=attempt.temperature,
                effective_max_tokens=attempt.effective_max_tokens,
                appshell_epoch=attempt.appshell_epoch,
            )
        except ModelPermitError as exc:
            _mark_no_router_fallback(exc)
            raise
        except Exception as exc:  # defensive: a broken grant must fail closed
            _mark_no_router_fallback(exc)
            raise ModelPermitError(f"model permit grant failed: {exc}") from exc

    def _current_egress_identity(self) -> EgressIdentityV1 | None:
        context = current_runtime_context()
        if context is None or not context.owner_key_hash.strip():
            return None
        epoch = None
        binding = context.appshell_epoch_binding
        if binding is not None:
            epoch = str(getattr(binding, "epoch", "") or "")
        return EgressIdentityV1(
            product_id=context.product_id,
            channel=context.channel,
            owner_key_hash=context.owner_key_hash,
            session_id=context.session_id,
            run_id=context.run_id,
            appshell_epoch=epoch,
        )

    def _reverify_egress_attempt(
        self,
        *,
        decision: RoutingDecision,
        attempt: EgressAttemptV1,
        identity: EgressIdentityV1,
        messages: list[ChatMessage],
        tools: list[dict[str, Any]] | None,
        attachments: Any,
        provenance: Any,
        temperature: float,
        effective_max_tokens: int | None,
    ) -> None:
        context = current_runtime_context()
        cancel = getattr(context, "cancel_token", None) if context is not None else None
        if cancel is not None and bool(getattr(cancel, "is_set", lambda: False)()):
            raise asyncio.CancelledError()
        current = self._current_egress_identity()
        if current is None:
            raise EgressConsentError("trusted owner required for model egress")
        if (
            current.owner_key_hash != identity.owner_key_hash
            or current.session_id != identity.session_id
            or current.run_id != identity.run_id
            or current.channel != identity.channel
            or (current.appshell_epoch or "") != (identity.appshell_epoch or "")
            or current.product_id != identity.product_id
        ):
            raise EgressConsentError("egress identity changed after consent")
        if provider_generation_of(decision.provider) != attempt.provider_generation:
            raise EgressConsentError("provider generation changed after consent")
        if provider_endpoint_digest(decision.provider) != attempt.endpoint_digest:
            raise EgressConsentError("provider endpoint changed after consent")
        if endpoint_digest(provider_endpoint_url(decision.provider)) != attempt.endpoint_digest:
            raise EgressConsentError("provider endpoint changed after consent")
        replay = build_egress_attempt(
            identity=identity,
            attempt_kind=attempt.attempt_kind,
            provider_name=decision.provider_name,
            provider_generation=attempt.provider_generation,
            model=decision.model,
            endpoint_url=provider_endpoint_url(decision.provider),
            messages=messages,
            tools=tools,
            attachments=attachments,
            provenance=provenance,
            temperature=temperature,
            effective_max_tokens=effective_max_tokens,
        )
        # attempt_id is unique per attempt; compare the bound digests only.
        if (
            replay.messages_digest != attempt.messages_digest
            or replay.tools_digest != attempt.tools_digest
            or replay.attachments_digest != attempt.attachments_digest
            or replay.provenance_digest != attempt.provenance_digest
            or replay.temperature != attempt.temperature
            or replay.effective_max_tokens != attempt.effective_max_tokens
            or replay.endpoint_digest != attempt.endpoint_digest
            or replay.provider_generation != attempt.provider_generation
        ):
            raise EgressConsentError("egress attempt digest changed after consent")

    async def _authorize_egress_then_permit(
        self,
        decision: RoutingDecision,
        *,
        messages: list[ChatMessage],
        tools: list[dict[str, Any]] | None,
        attachments: Any,
        provenance: Any,
        temperature: float,
        max_tokens: int | None,
        attempt_kind: str,
        before_model_call: Callable[
            [RoutingDecision, list[ChatMessage], list[dict[str, Any]] | None], Awaitable[Any]
        ]
        | None,
        permit_grant: Callable[
            [RoutingDecision, list[ChatMessage], list[dict[str, Any]] | None], Any
        ],
    ) -> tuple[list[ChatMessage], list[dict[str, Any]] | None, int | None, Any]:
        classification = classify_provider_endpoint(decision.provider)
        if classification == "invalid" or classification not in {
            "literal_loopback",
            "remote",
        }:
            raise EgressConsentError("provider endpoint is invalid")
        frozen_messages = freeze_messages(messages)
        frozen_tools = freeze_tools(tools)
        frozen_attachments = digest_jsonable(attachments or [])
        frozen_provenance = digest_jsonable(provenance or {})
        effective_max_tokens = self._clamp_stream_max_tokens(decision, max_tokens)
        identity = self._current_egress_identity()
        if identity is None:
            raise EgressConsentError("trusted owner required for model egress")
        attempt = build_egress_attempt(
            identity=identity,
            attempt_kind=attempt_kind,
            provider_name=decision.provider_name,
            provider_generation=provider_generation_of(decision.provider),
            model=decision.model,
            endpoint_url=provider_endpoint_url(decision.provider),
            messages=frozen_messages,
            tools=frozen_tools,
            attachments=attachments or [],
            provenance=provenance or {},
            temperature=temperature,
            effective_max_tokens=effective_max_tokens,
        )
        receipt: EgressConsentReceiptV1 | None = None
        if classification == "remote":
            broker = self._egress_consent_broker
            if broker is None:
                raise EgressConsentError("egress consent broker required")
            try:
                receipt = await broker.request_and_claim(
                    attempt,
                    safe_egress_summary(
                        attempt,
                        endpoint_url=provider_endpoint_url(decision.provider),
                        message_count=len(frozen_messages),
                        tool_count=len(frozen_tools or []),
                    ),
                )
            except BaseException as exc:
                _mark_no_router_fallback(exc)
                raise
            if (
                receipt.attempt_hash != attempt.attempt_hash
                or not receipt.claim_receipt_hash
                or not receipt.nonce
            ):
                raise EgressConsentError("egress consent receipt does not match the attempt")
            consume_egress_receipt(receipt)
        hook_messages = freeze_messages(frozen_messages)
        hook_tools = freeze_tools(frozen_tools)
        context: Any = None
        if before_model_call is not None:
            try:
                context = await before_model_call(decision, hook_messages, hook_tools)
            except Exception as exc:
                _mark_no_router_fallback(exc)
                raise
        if (
            digest_jsonable(attachments or []) != frozen_attachments
            or digest_jsonable(provenance or {}) != frozen_provenance
        ):
            raise EgressConsentError("egress attachments or provenance changed after consent")
        self._reverify_egress_attempt(
            decision=decision,
            attempt=attempt,
            identity=identity,
            messages=frozen_messages,
            tools=frozen_tools,
            attachments=attachments,
            provenance=provenance,
            temperature=temperature,
            effective_max_tokens=effective_max_tokens,
        )
        current_identity = self._current_egress_identity()
        if current_identity is None:
            raise EgressConsentError("trusted owner required for model egress")
        identity = current_identity
        self._consume_model_permit(
            permit_grant,
            decision,
            frozen_messages,
            frozen_tools,
            attempt=attempt,
            receipt=receipt,
            classification=classification,
        )
        if (
            provider_endpoint_digest(decision.provider) != attempt.endpoint_digest
            or provider_generation_of(decision.provider) != attempt.provider_generation
            or endpoint_digest(provider_endpoint_url(decision.provider))
            != attempt.endpoint_digest
        ):
            raise EgressConsentError("provider endpoint generation mismatch")
        if (
            receipt is not None
            and receipt.attempt_hash != attempt.attempt_hash
        ):
            raise EgressConsentError("egress consent receipt does not match the attempt")
        self._raise_if_runtime_cancelled()
        return freeze_messages(frozen_messages), freeze_tools(frozen_tools), effective_max_tokens, context

    def _raise_if_runtime_cancelled(self) -> None:
        context = current_runtime_context()
        cancel = getattr(context, "cancel_token", None) if context is not None else None
        if cancel is not None and bool(getattr(cancel, "is_set", lambda: False)()):
            raise asyncio.CancelledError()

    def _init_providers(self) -> None:
        allow_private = (
            getattr(
                getattr(self.settings, "security", None),
                "allow_private_model_providers",
                False,
            )
            is True
        )
        for p_config in self.settings.providers:
            provider = OpenAICompatibleProvider(
                p_config,
                allow_private=allow_private,
            )
            self._providers[p_config.name] = provider
            self._remember_provider_secret(provider)
            # Register explicitly-configured models
            for m in p_config.models:
                full_id = f"{p_config.name}/{m.id}"
                self._model_map[full_id] = (p_config.name, m)
                self._model_map[m.id] = (p_config.name, m)
            # Ensure default_model is always reachable even if not in models list
            if p_config.default_model and p_config.default_model not in self._model_map:
                default_cfg = ModelConfig(
                    id=p_config.default_model,
                    name=p_config.default_model,
                    provider=p_config.name,
                )
                self._model_map[p_config.default_model] = (p_config.name, default_cfg)

    def add_provider(self, name: str, provider: ModelProvider, models: list[ModelConfig]) -> None:
        # Clear stale mappings for this provider first so that old model ids
        # (e.g. from a previous discover_models refresh) don't linger.
        old_provider = self._providers.pop(name, None)
        if old_provider is not None:
            registry = getattr(self, "_registered_provider_secrets", {})
            if type(registry) is dict:
                registry.pop(id(old_provider), None)
        self._model_map = {k: v for k, v in self._model_map.items() if v[0] != name}
        self._providers[name] = provider
        self._remember_provider_secret(provider)
        for m in models:
            self._model_map[m.id] = (name, m)
            self._model_map[f"{name}/{m.id}"] = (name, m)
        self._routing_cache.clear()
        # Close the old provider asynchronously without blocking the caller.
        if old_provider is not None:
            try:
                import asyncio

                asyncio.get_running_loop()
                asyncio.create_task(old_provider.close())
            except RuntimeError:
                pass

    def remove_provider(self, name: str) -> bool:
        """Remove a provider and all its model mappings."""
        if name not in self._providers:
            return False
        old_provider = self._providers.pop(name)
        registry = getattr(self, "_registered_provider_secrets", {})
        if type(registry) is dict:
            registry.pop(id(old_provider), None)
        self._model_map = {k: v for k, v in self._model_map.items() if v[0] != name}
        self._routing_cache.clear()
        # Close the old provider asynchronously without blocking the caller.
        try:
            import asyncio

            asyncio.get_running_loop()
            asyncio.create_task(old_provider.close())
        except RuntimeError:
            pass
        return True

    def get_model_config(self, model_id: str) -> ModelConfig | None:
        """Get model config by ID."""
        entry = self._model_map.get(model_id)
        if entry:
            return entry[1]
        return None

    def _clamp_stream_max_tokens(
        self,
        decision: RoutingDecision,
        requested_max_tokens: int | None,
    ) -> int | None:
        model_cfg = self.get_model_config(decision.model)
        model_cap = getattr(model_cfg, "max_tokens", None) if model_cfg is not None else None
        if isinstance(model_cap, bool) or not isinstance(model_cap, int) or model_cap <= 0:
            return requested_max_tokens
        if requested_max_tokens is None:
            return model_cap
        return min(max(0, requested_max_tokens), model_cap)

    def get_model_binding(self, model_id: str) -> tuple[str, ModelConfig] | None:
        """Return the configured provider/model pair without probing provider health."""
        entry = self._model_map.get(model_id)
        if entry and isinstance(entry, tuple) and len(entry) == 2:
            provider_name, config = entry
            if isinstance(provider_name, str) and isinstance(config, ModelConfig):
                return provider_name, config
        return None

    def get_model_bindings(self) -> tuple[tuple[str, ModelConfig], ...]:
        """Return deduplicated bindings backed by exact full model IDs."""
        bindings: list[tuple[str, ModelConfig]] = []
        seen: set[str] = set()
        for model_id, entry in self._model_map.items():
            if not isinstance(entry, tuple) or len(entry) != 2:
                continue
            provider_name, config = entry
            if not isinstance(provider_name, str) or not isinstance(config, ModelConfig):
                continue
            full_id = f"{provider_name}/{config.id}"
            if model_id != full_id or full_id in seen:
                continue
            seen.add(full_id)
            bindings.append((provider_name, config))
        return tuple(bindings)

    def is_local_model(self, model_id: str) -> bool:
        """Return True if the model is served by a local provider (e.g. LMStudio, Ollama)."""
        entry = self._model_map.get(model_id)
        if not entry:
            return False
        provider_name = entry[0]
        provider = self._providers.get(provider_name)
        if isinstance(provider, OpenAICompatibleProvider):
            return getattr(provider, "_is_local", False)
        return False

    async def _provider_healthy(self, provider: ModelProvider) -> bool:
        """Read local health state without starting an unpermitted network probe.

        Routing is allowed to consult circuit-breaker and previously recorded
        provider state only.  An unknown provider remains eligible so its real
        model request can run through the Echo permit boundary and report the
        authoritative outcome there.
        """
        try:
            if hasattr(provider, "circuit"):
                circuit_state = await provider.circuit.state()
                if circuit_state.value == "open":
                    return False

            last_check = getattr(provider, "_last_health_check", 0.0)
            if isinstance(last_check, (int, float)) and last_check > 0:
                return bool(getattr(provider, "_health_status", False))

            # Lightweight/mock providers may expose explicit in-memory state.
            healthy = getattr(provider, "healthy", None)
            if isinstance(healthy, bool):
                return healthy

            return True
        except Exception:
            return False

    async def select_model(
        self,
        _task_complexity: str = "medium",  # Reserved for future complexity-based routing
        preferred: str | None = None,
    ) -> RoutingDecision:
        """Select best model for task, skipping unhealthy providers."""
        if preferred is None and self.preferred_model:
            preferred = self.preferred_model
        cache_key = preferred or "__default__"
        cached: RoutingDecision | None = self._routing_cache.get(cache_key)
        if cached is not None:
            return cached

        if preferred and preferred in self._model_map:
            provider_name, config = self._model_map[preferred]
            provider = self._providers[provider_name]
            if await self._provider_healthy(provider):
                decision = self._decision(
                    provider=provider,
                    model=config.id,
                    provider_name=provider_name,
                    reason=f"User preferred: {preferred}",
                )
            else:
                # Respect user's explicit choice even if the provider appears
                # unhealthy.  Let the actual API call fail and surface the
                # error rather than silently falling back to a different model.
                decision = self._decision(
                    provider=provider,
                    model=config.id,
                    provider_name=provider_name,
                    reason=f"User preferred (unhealthy): {preferred}",
                )
            self._routing_cache[cache_key] = decision
            return decision

        # Build a unified view of provider → default_model from both
        # settings.providers (static config) and _model_map (runtime adds).
        provider_defaults: dict[str, str] = {}
        for p_config in self.settings.providers:
            if p_config.default_model:
                provider_defaults[p_config.name] = p_config.default_model
            elif p_config.models:
                chat_models = [m for m in p_config.models if "embed" not in m.id.lower()]
                model_candidates = chat_models if chat_models else p_config.models
                if model_candidates:
                    provider_defaults[p_config.name] = model_candidates[0].id

        # Fallback: infer from _model_map for providers added at runtime
        for full_id, (provider_name, config) in self._model_map.items():
            if provider_name not in provider_defaults and "/" not in full_id:
                provider_defaults[provider_name] = config.id

        # Select first healthy provider (parallel health checks for speed)
        candidates = [
            (name, model, self._providers[name])
            for name, model in provider_defaults.items()
            if name in self._providers
        ]
        if candidates:
            health_results = await asyncio.gather(
                *[self._provider_healthy(p) for _, _, p in candidates],
                return_exceptions=True,
            )
            for (name, model, _provider), healthy in zip(candidates, health_results, strict=False):
                if isinstance(healthy, bool) and healthy:
                    decision = self._decision(
                        provider=self._providers[name],
                        model=model,
                        provider_name=name,
                        reason=f"Default model: {model}",
                    )
                    self._routing_cache[cache_key] = decision
                    return decision

        # Last resort: first configured provider even if unhealthy
        for provider_name, default_model in provider_defaults.items():
            maybe_provider = self._providers.get(provider_name)
            if maybe_provider is not None:
                decision = self._decision(
                    provider=maybe_provider,
                    model=default_model,
                    provider_name=provider_name,
                    reason=f"Fallback (unhealthy): {default_model}",
                )
                self._routing_cache[cache_key] = decision
                return decision

        raise RuntimeError("No models configured")

    async def chat(
        self,
        messages: list[ChatMessage],
        model: str | None = None,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
        before_model_call: Callable[
            [RoutingDecision, list[ChatMessage], list[dict[str, Any]] | None], Awaitable[Any]
        ]
        | None = None,
        after_model_call: Callable[
            [Any, ChatResponse | None, BaseException | None], Awaitable[None]
        ]
        | None = None,
        permit_grant: Callable[
            [RoutingDecision, list[ChatMessage], list[dict[str, Any]] | None], Any
        ]
        | None = None,
        attachments: Any = None,
        provenance: Any = None,
    ) -> ChatResponse:
        """Send chat request with automatic fallback.

        When ``model`` is explicitly specified by the user we respect that
        choice and do **not** silently fall back to another provider – the
        user should see an error if their chosen model fails.  Fallback is
        only allowed when ``model`` is ``None`` (auto-select).

        Every provider attempt (initial try, transport retry, cross-provider
        fallback) consumes a fresh single-use permit obtained from
        ``permit_grant`` and verified against the runtime-owned verifier;
        without it the call fails closed before any provider code runs.
        """
        if before_model_call is None or after_model_call is None or permit_grant is None:
            raise RuntimeError(
                "Echo requires before_model_call/after_model_call callbacks and "
                "a runtime-issued permit_grant for ModelRouter.chat(); direct "
                "provider chat is only available through the Echo turn runtime."
            )
        if self._permit_verifier is None:
            raise ModelPermitError(
                "ModelRouter has no Echo permit verifier; direct provider calls "
                "are only available through the Echo turn runtime."
            )
        decision = await self.select_model(preferred=model)
        errors: list[str] = []
        attempt_scrubbers: list[ProviderSecretScrubber] = []

        def _scrub_attempt_diagnostics(message: str) -> str:
            safe = message
            for scrubber in attempt_scrubbers:
                safe = _safe_outward_message(scrubber, safe)
            return safe

        async def _after(
            context: Any,
            response: ChatResponse | None,
            error: BaseException | None,
            scrubber: ProviderSecretScrubber,
            provider: ModelProvider,
        ) -> _FailureSnapshot | None:
            if after_model_call is not None:
                try:
                    await after_model_call(context, response, error)
                except BaseException as exc:
                    return _hook_failure_snapshot(exc, scrubber, provider)
            return None

        async def _tainted_provider_call(
            call_decision: RoutingDecision,
            scrubber: ProviderSecretScrubber,
            send_messages: list[ChatMessage],
            send_tools: list[dict[str, Any]] | None,
            send_temperature: float,
            send_max_tokens: int | None,
        ) -> tuple[ChatResponse | None, _FailureSnapshot | None]:
            try:
                raw = await call_decision.provider.chat(
                    messages=send_messages,
                    model=call_decision.model,
                    tools=send_tools,
                    temperature=send_temperature,
                    max_tokens=send_max_tokens,
                )
                return _sanitize_chat_response(raw, call_decision, scrubber), None
            except BaseException as exc:
                return None, _failure_snapshot(exc, scrubber, call_decision.provider)

        async def _call_provider_once(
            call_decision: RoutingDecision,
            *,
            attempt_kind: str,
        ) -> ChatResponse:
            context: Any = None
            response: ChatResponse | None = None
            failure: _FailureSnapshot | None = None
            # Validate the attempt's immutable credential generation before a
            # permit is consumed or Echo reserves a durable finish slot.
            scrubber = self._scrubber_for_registered_decision(call_decision)
            attempt_scrubbers.append(scrubber)
            if permit_grant is None:
                raise ModelPermitError("Echo model attempt is missing its runtime permit grant")
            send_messages, send_tools, send_max_tokens, context = (
                await self._authorize_egress_then_permit(
                    call_decision,
                    messages=messages,
                    tools=tools,
                    attachments=attachments,
                    provenance=provenance,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    attempt_kind=attempt_kind,
                    before_model_call=before_model_call,
                    permit_grant=permit_grant,
                )
            )
            response, failure = await _tainted_provider_call(
                call_decision,
                scrubber,
                send_messages,
                send_tools,
                temperature,
                send_max_tokens,
            )
            if failure is not None:
                hook_failure = await _after(
                    context,
                    None,
                    _materialize_failure(failure),
                    scrubber,
                    call_decision.provider,
                )
                if hook_failure is not None:
                    raise _materialize_failure(hook_failure) from None
                propagated = _materialize_failure(failure)
                if isinstance(propagated, SafeProviderError):
                    reraise_safe_provider_error(propagated)
                raise propagated from None
            if response is None:
                raise _secret_scrub_failure()
            hook_failure = await _after(
                context,
                response,
                None,
                scrubber,
                call_decision.provider,
            )
            if hook_failure is not None:
                raise _materialize_failure(hook_failure) from None
            return response

        async def _call_provider(
            call_decision: RoutingDecision,
            *,
            attempt_kind_base: str = "initial",
        ) -> ChatResponse:
            attempt_limit = _provider_attempt_limit(call_decision.provider)
            for attempt in range(attempt_limit):
                try:
                    kind = attempt_kind_base if attempt == 0 else "retry"
                    return await _call_provider_once(call_decision, attempt_kind=kind)
                except Exception as exc:
                    if (
                        _is_no_router_fallback(exc)
                        or not is_retryable_provider_error(exc)
                        or attempt + 1 >= attempt_limit
                    ):
                        raise
                    delay = min(2**attempt, 30)
                    await asyncio.sleep(delay)
            reraise_safe_provider_error(
                SafeProviderError(
                    _scrub_attempt_diagnostics("provider retry loop ended without a result")
                )
            )

        try:
            return await _call_provider(decision)
        except Exception as e:
            if _is_no_router_fallback(e):
                raise
            safe = _as_safe_provider_error(e, decision.provider)
            errors.append(f"{decision.provider_name}/{decision.model}: {safe}")
            if model is not None:
                # User explicitly requested this model – do not silently fallback.
                reraise_safe_provider_error(
                    SafeProviderError(
                        _scrub_attempt_diagnostics(
                            f"Requested model '{model}' failed: {safe}"
                        )
                    )
                )

        # Fallback is only reached when ``model`` is None (auto-select).
        # Try fallback providers (skip unhealthy ones)
        for name, provider in self._providers.items():
            if name == decision.provider_name:
                continue
            try:
                if not await self._provider_healthy(provider):
                    continue
                # Use provider's default model
                fallback_model = next(
                    (
                        m.id
                        for mid, (p, m) in self._model_map.items()
                        if p == name and "/" not in mid
                    ),
                    "",
                )
                if not fallback_model:
                    continue
                fallback_decision = self._decision(
                    provider=provider,
                    model=fallback_model,
                    provider_name=name,
                    reason=f"Fallback: {fallback_model}",
                )
                return await _call_provider(fallback_decision, attempt_kind_base="fallback")
            except Exception as e:
                if _is_no_router_fallback(e):
                    raise
                safe = _as_safe_provider_error(e, provider)
                errors.append(f"{name}: {safe}")

        # Last resort: try the original selected provider even if unhealthy
        try:
            return await _call_provider(decision, attempt_kind_base="last_resort")
        except Exception as e:
            if _is_no_router_fallback(e):
                raise
            safe = _as_safe_provider_error(e, decision.provider)
            errors.append(f"{decision.provider_name}/{decision.model} (last resort): {safe}")

        reraise_safe_provider_error(
            SafeProviderError(
                _scrub_attempt_diagnostics(f"All providers failed: {'; '.join(errors)}")
            )
        )

    async def chat_stream(
        self,
        messages: list[ChatMessage],
        model: str | None = None,
        temperature: float = 0.7,
    ) -> AsyncIterator[str]:
        """Stream tokens from the selected model with fallback.

        When ``model`` is explicitly specified by the user we respect that
        choice and do **not** silently fall back to another provider.
        """
        del messages, model, temperature
        raise RuntimeError(
            "Echo requires Echo-gated chat_stream_events() with "
            "before_model_call/after_model_call hooks; direct ModelRouter.chat_stream() "
            "is not a supported JS Agent runtime path."
        )
        yield ""  # pragma: no cover - keeps this API an async iterator

    async def chat_stream_events(
        self,
        messages: list[ChatMessage],
        model: str | None = None,
        temperature: float = 0.7,
        tools: list[dict[str, Any]] | None = None,
        max_tokens: int | None = None,
        before_model_call: Callable[
            [RoutingDecision, list[ChatMessage], list[dict[str, Any]] | None], Awaitable[Any]
        ]
        | None = None,
        after_model_call: Callable[
            [Any, ChatResponse | None, BaseException | None], Awaitable[None]
        ]
        | None = None,
        permit_grant: Callable[
            [RoutingDecision, list[ChatMessage], list[dict[str, Any]] | None], Any
        ]
        | None = None,
        attachments: Any = None,
        provenance: Any = None,
    ) -> AsyncGenerator[StreamEvent, None]:
        """Structured-event variant of ``chat_stream``.

        Returns one stream of ``StreamEvent`` (text_delta / thinking_delta /
        tool_call_delta / usage / done / error). When the chosen provider
        fails before emitting text AND ``model`` was auto-selected, we may
        fail over to the next healthy provider. Once text has been emitted,
        every error or incomplete close is terminal so fallback cannot
        duplicate output or bypass the completion budget.

        Every provider attempt (initial try, reconnect, fallback) consumes a
        fresh single-use permit from ``permit_grant``; without a valid permit
        the stream fails closed before any provider code runs.
        """

        if before_model_call is None or after_model_call is None or permit_grant is None:
            raise RuntimeError(
                "Echo requires before_model_call/after_model_call callbacks and "
                "a runtime-issued permit_grant for "
                "ModelRouter.chat_stream_events(); direct provider stream "
                "is only available through the Echo turn runtime."
            )
        if self._permit_verifier is None:
            raise ModelPermitError(
                "ModelRouter has no Echo permit verifier; direct provider calls "
                "are only available through the Echo turn runtime."
            )
        decision = await self.select_model(preferred=model)
        first_error: StreamEvent | None = None
        fallback_error: StreamEvent | None = None
        fallback_error_decision: RoutingDecision | None = None
        consumed_completion_tokens = 0

        attempt_limit = _provider_attempt_limit(decision.provider)
        for attempt in range(attempt_limit):
            attempt_max_tokens = (
                None if max_tokens is None else max(0, max_tokens - consumed_completion_tokens)
            )
            if attempt_max_tokens == 0:
                break
            primary_stream = self._chat_stream_events_for_decision(
                decision,
                messages=messages,
                tools=tools,
                temperature=temperature,
                max_tokens=attempt_max_tokens,
                before_model_call=before_model_call,
                after_model_call=after_model_call,
                permit_grant=permit_grant,
                attachments=attachments,
                provenance=provenance,
                attempt_kind="initial" if attempt == 0 else "stream_reconnect",
            )
            primary_emitted_output = False
            retry_requested = False
            try:
                async with aclosing(primary_stream):
                    async for ev in primary_stream:
                        if ev.kind in {"text_delta", "thinking_delta", "tool_call_delta"}:
                            primary_emitted_output = True
                        if ev.kind == "error":
                            first_error = ev
                            consumed_completion_tokens += _stream_failure_completion(ev, None)
                            retry_requested = (
                                bool(ev.meta.get("retryable"))
                                and not primary_emitted_output
                                and attempt + 1 < attempt_limit
                            )
                            if retry_requested:
                                break
                            if model is not None or primary_emitted_output:
                                yield ev
                                return
                            break
                        yield ev
                        if ev.kind == "done":
                            return
                if retry_requested:
                    delay = min(2**attempt, 30)
                    await asyncio.sleep(delay)
                    continue
                break
            except Exception as exc:
                if _is_no_router_fallback(exc) or primary_emitted_output:
                    raise
                safe = _as_safe_provider_error(exc, decision.provider)
                consumed_completion_tokens += _stream_failure_completion(None, safe)
                first_error = _rebuild_error_event(None, decision, safe)
                if is_retryable_provider_error(safe) and attempt + 1 < attempt_limit:
                    delay = min(2**attempt, 30)
                    await asyncio.sleep(delay)
                    continue
                if model is not None:
                    reraise_safe_provider_error(safe)
                break

        # Fallback path is only reached when ``model`` is None.
        for name, provider in self._providers.items():
            if name == decision.provider_name:
                continue
            fallback_emitted_output = False
            attempt_max_tokens = (
                None if max_tokens is None else max(0, max_tokens - consumed_completion_tokens)
            )
            if attempt_max_tokens == 0:
                break
            try:
                if not await self._provider_healthy(provider):
                    continue
                fallback_model = next(
                    (
                        m.id
                        for mid, (p, m) in self._model_map.items()
                        if p == name and "/" not in mid
                    ),
                    "",
                )
                if not fallback_model:
                    continue
                fallback_decision = self._decision(
                    provider=provider,
                    model=fallback_model,
                    provider_name=name,
                    reason=f"Fallback: {fallback_model}",
                )
                fallback_failed = False
                fallback_stream = self._chat_stream_events_for_decision(
                    fallback_decision,
                    messages=messages,
                    tools=tools,
                    temperature=temperature,
                    max_tokens=attempt_max_tokens,
                    before_model_call=before_model_call,
                    after_model_call=after_model_call,
                    permit_grant=permit_grant,
                    attachments=attachments,
                    provenance=provenance,
                    attempt_kind="fallback",
                )
                async with aclosing(fallback_stream):
                    async for ev in fallback_stream:
                        if ev.kind in {
                            "text_delta",
                            "thinking_delta",
                            "tool_call_delta",
                        }:
                            fallback_emitted_output = True
                        if ev.kind == "error":
                            fallback_error = ev
                            fallback_error_decision = fallback_decision
                            fallback_failed = True
                            consumed_completion_tokens += _stream_failure_completion(ev, None)
                            if fallback_emitted_output:
                                yield ev
                                return
                            break
                        yield ev
                        if ev.kind == "done":
                            return
                if fallback_failed:
                    continue
                return
            except Exception as e:
                if _is_no_router_fallback(e) or fallback_emitted_output:
                    raise
                safe = _as_safe_provider_error(e, provider)
                consumed_completion_tokens += _stream_failure_completion(None, safe)

        # All providers failed: emit the original error (or a synthesised one)
        # so the consumer always sees a terminal event.
        if fallback_error is not None:
            yield _rebuild_error_event(
                fallback_error,
                fallback_error_decision or decision,
                SafeProviderError(fallback_error.error or "<F>"),
                failure_meta=fallback_error.meta,
            )
        elif first_error is not None:
            yield _rebuild_error_event(
                first_error,
                decision,
                SafeProviderError(first_error.error or "<F>"),
                failure_meta=first_error.meta,
            )
        else:
            yield _rebuild_error_event(
                None,
                decision,
                SafeProviderError("<F>"),
            )

    async def _chat_stream_events_for_decision(
        self,
        decision: RoutingDecision,
        *,
        messages: list[ChatMessage],
        tools: list[dict[str, Any]] | None,
        temperature: float,
        max_tokens: int | None,
        before_model_call: Callable[
            [RoutingDecision, list[ChatMessage], list[dict[str, Any]] | None], Awaitable[Any]
        ]
        | None,
        after_model_call: Callable[
            [Any, ChatResponse | None, BaseException | None], Awaitable[None]
        ]
        | None,
        permit_grant: Callable[
            [RoutingDecision, list[ChatMessage], list[dict[str, Any]] | None], Any
        ]
        | None = None,
        attachments: Any = None,
        provenance: Any = None,
        attempt_kind: str = "initial",
    ) -> AsyncGenerator[StreamEvent, None]:
        """Stream one provider decision through the same model-gate hooks as chat()."""
        context: Any = None
        finalized = False
        text_parts: list[str] = []
        thinking_parts: list[str] = []
        usage: dict[str, int] = {}
        estimated_completion_tokens = 0
        estimated_completion_bytes = 0
        response_stream: _ProviderResponseStreamScrubber | None = None
        exact_scrubber: ProviderSecretScrubber | None = None
        before_completed = False
        hook_failure: _FailureSnapshot | None = None
        propagation_failure: _FailureSnapshot | None = None
        send_messages = messages
        send_tools = tools
        provider_max_tokens = self._clamp_stream_max_tokens(decision, max_tokens)

        async def _after(
            response: ChatResponse | None,
            error: BaseException | None,
        ) -> None:
            if after_model_call is None:
                return
            try:
                await after_model_call(context, response, error)
            except Exception as exc:
                _mark_no_router_fallback(exc)
                raise

        async def _finalize(
            response: ChatResponse | None,
            error: BaseException | None,
        ) -> None:
            nonlocal finalized
            if finalized:
                return
            finalized = True
            await _after(response, error)

        if permit_grant is None:
            raise ModelPermitError("Echo model stream attempt is missing its runtime permit grant")
        # Fail before consuming the permit or reserving an Echo finish slot if
        # this Provider generation cannot be scrubbed safely.
        exact_scrubber = self._scrubber_for_registered_decision(decision)
        response_stream = _ProviderResponseStreamScrubber(exact_scrubber)
        send_messages, send_tools, provider_max_tokens, context = (
            await self._authorize_egress_then_permit(
                decision,
                messages=messages,
                tools=tools,
                attachments=attachments,
                provenance=provenance,
                temperature=temperature,
                max_tokens=max_tokens,
                attempt_kind=attempt_kind,
                before_model_call=before_model_call,
                permit_grant=permit_grant,
            )
        )
        before_completed = True

        try:
            async for raw_ev in decision.provider.chat_stream_events(
                messages=send_messages,
                model=decision.model,
                tools=send_tools,
                temperature=temperature,
                max_tokens=provider_max_tokens,
            ):
                if type(raw_ev) is not StreamEvent:
                    raise _secret_scrub_failure()
                if raw_ev.kind == "error":
                    response_stream.discard()
                    # Re-scrub provider-aware: custom/legacy streams may emit raw secrets.
                    try:
                        safe_raw_error = exact_scrubber.redact_text(raw_ev.error or "<F>")
                    except ProviderSecretScrubError:
                        raise _secret_scrub_failure() from None
                    provisional_error = _as_safe_provider_error(
                        SafeProviderError(
                            safe_raw_error,
                            retryable=(
                                isinstance(raw_ev.meta, dict)
                                and type(raw_ev.meta.get("retryable")) is bool
                                and raw_ev.meta["retryable"]
                            ),
                        ),
                        decision.provider,
                    )
                    error = SafeProviderError(
                        _safe_outward_message(exact_scrubber, str(provisional_error)),
                        retryable=provisional_error.retryable,
                    )
                    failure_meta = _annotate_stream_failure(
                        error,
                        text="".join(text_parts),
                        usage=usage,
                        estimated_completion_tokens=estimated_completion_tokens,
                    )
                    # Do not retain the provider-owned event across the hook
                    # await: a hook failure traceback is an outward sink.
                    raw_ev = StreamEvent(kind="error")
                    await _finalize(None, error)
                    yield _rebuild_error_event(
                        None,
                        decision,
                        error,
                        failure_meta=failure_meta,
                    )
                    return

                if raw_ev.kind == "text_delta":
                    if type(raw_ev.text) is not str:
                        raise _secret_scrub_failure()
                    try:
                        estimated_completion_bytes += len(raw_ev.text.encode("utf-8"))
                    except UnicodeEncodeError:
                        raise _secret_scrub_failure() from None
                    estimated_completion_tokens = max(
                        1,
                        (estimated_completion_bytes + 3) // 4,
                    )
                    if max_tokens is not None and estimated_completion_tokens > max_tokens:
                        response_stream.discard()
                        budget_error = _StreamCompletionBudgetExceededError(
                            estimated_completion_tokens
                        )
                        failure_meta = _annotate_stream_failure(
                            budget_error,
                            text="".join(text_parts),
                            usage=usage,
                            estimated_completion_tokens=estimated_completion_tokens,
                        )
                        raw_ev = StreamEvent(kind="error")
                        await _finalize(None, budget_error)
                        yield _rebuild_error_event(
                            None,
                            decision,
                            budget_error,
                            failure_meta=failure_meta,
                        )
                        return
                    safe_text = response_stream.feed_text("text_delta", raw_ev.text)
                    if safe_text:
                        text_parts.append(safe_text)
                        yield StreamEvent(
                            kind="text_delta",
                            text=safe_text,
                            provider=decision.provider_name,
                            model=decision.model,
                        )
                elif raw_ev.kind == "thinking_delta":
                    safe_thinking = response_stream.feed_text(
                        "thinking_delta", raw_ev.text
                    )
                    if safe_thinking:
                        thinking_parts.append(safe_thinking)
                        yield StreamEvent(
                            kind="thinking_delta",
                            text=safe_thinking,
                            provider=decision.provider_name,
                            model=decision.model,
                        )
                elif raw_ev.kind == "tool_call_delta":
                    safe_tool_delta = response_stream.feed_tool(raw_ev.tool_call)
                    if safe_tool_delta is not None:
                        yield StreamEvent(
                            kind="tool_call_delta",
                            tool_call=safe_tool_delta,
                            provider=decision.provider_name,
                            model=decision.model,
                        )
                elif raw_ev.kind == "usage":
                    usage = _normalize_provider_usage(raw_ev.usage)
                    yield StreamEvent(
                        kind="usage",
                        usage=dict(usage),
                        provider=decision.provider_name,
                        model=decision.model,
                    )
                elif raw_ev.kind == "done":
                    text_tail, thinking_tail, tool_events, response_tools = (
                        response_stream.finish()
                    )
                    if text_tail:
                        text_parts.append(text_tail)
                        yield StreamEvent(
                            kind="text_delta",
                            text=text_tail,
                            provider=decision.provider_name,
                            model=decision.model,
                        )
                    if thinking_tail:
                        thinking_parts.append(thinking_tail)
                        yield StreamEvent(
                            kind="thinking_delta",
                            text=thinking_tail,
                            provider=decision.provider_name,
                            model=decision.model,
                        )
                    for tool_event in tool_events:
                        yield StreamEvent(
                            kind="tool_call_delta",
                            tool_call=tool_event,
                            provider=decision.provider_name,
                            model=decision.model,
                        )
                    raw_finish = raw_ev.finish_reason or "stop"
                    if type(raw_finish) is not str:
                        raise _secret_scrub_failure()
                    try:
                        finish_reason = exact_scrubber.redact_text(raw_finish)
                    except ProviderSecretScrubError:
                        raise _secret_scrub_failure() from None
                    raw_finish = ""
                    raw_ev = StreamEvent(kind="done")
                    await _finalize(
                        _stream_chat_response(
                            model=decision.model,
                            text="".join(text_parts),
                            usage=usage,
                            finish_reason=finish_reason,
                            estimated_completion_tokens=estimated_completion_tokens,
                            reasoning_content="".join(thinking_parts),
                            tool_calls=response_tools,
                        ),
                        None,
                    )
                    yield StreamEvent(
                        kind="done",
                        finish_reason=finish_reason,
                        provider=decision.provider_name,
                        model=decision.model,
                    )
                    return
                else:
                    raise _secret_scrub_failure()
            response_stream.discard()
            error = SafeProviderError(
                _safe_outward_message(
                    exact_scrubber,
                    "model stream ended without done event",
                )
            )
            failure_meta = _annotate_stream_failure(
                error,
                text="".join(text_parts),
                usage=usage,
                estimated_completion_tokens=estimated_completion_tokens,
            )
            raw_ev = StreamEvent(kind="error")
            await _finalize(None, error)
            yield _rebuild_error_event(
                None,
                decision,
                error,
                failure_meta=failure_meta,
            )
        except BaseException as exc:
            # A detached outward exception must not keep the last Provider
            # event reachable through this frame's locals.
            raw_ev = StreamEvent(kind="error")
            raw_finish = ""
            if response_stream is not None:
                response_stream.discard()
            if isinstance(exc, GeneratorExit):
                hook_failure = _FailureSnapshot(
                    category="closed",
                    message=_safe_outward_message(
                        exact_scrubber,
                        "model stream closed early",
                    ),
                    no_fallback=True,
                )
                propagation_failure = _FailureSnapshot(
                    category="generator_exit",
                    no_fallback=True,
                )
            else:
                snapshot_factory = _hook_failure_snapshot if finalized else _failure_snapshot
                propagation_failure = snapshot_factory(
                    exc, exact_scrubber, decision.provider
                )
                hook_failure = propagation_failure
            if text_parts and hook_failure is not None:
                hook_failure = _FailureSnapshot(
                    category=hook_failure.category,
                    message=hook_failure.message,
                    retryable=hook_failure.retryable,
                    no_fallback=True,
                )
            if text_parts and propagation_failure is not None:
                propagation_failure = _FailureSnapshot(
                    category=propagation_failure.category,
                    message=propagation_failure.message,
                    retryable=propagation_failure.retryable,
                    no_fallback=True,
                )

        if hook_failure is None or propagation_failure is None:
            return

        hook_error = _materialize_failure(hook_failure)
        if not isinstance(hook_error, GeneratorExit):
            _annotate_stream_failure(
                hook_error,
                text="".join(text_parts),
                usage=usage,
                estimated_completion_tokens=estimated_completion_tokens,
            )

        finalize_failure: _FailureSnapshot | None = None
        if before_completed and not finalized:
            try:
                await _finalize(None, hook_error)
            except BaseException as finalize_error:
                finalize_failure = _hook_failure_snapshot(
                    finalize_error,
                    exact_scrubber,
                    decision.provider,
                )
        if finalize_failure is not None:
            raise _materialize_failure(finalize_failure) from None

        propagated_error = _materialize_failure(propagation_failure)
        if not isinstance(propagated_error, GeneratorExit):
            _annotate_stream_failure(
                propagated_error,
                text="".join(text_parts),
                usage=usage,
                estimated_completion_tokens=estimated_completion_tokens,
            )
        raise propagated_error from None

    async def health_check(self) -> dict[str, bool]:
        """Return cached provider health without performing network I/O."""
        results: dict[str, bool] = {}
        for name, provider in self._providers.items():
            results[name] = await self._provider_healthy(provider)
        return results

    async def close(self) -> None:
        """Close all provider connections."""
        for provider in self._providers.values():
            try:
                await provider.close()
            except Exception:
                continue
        registry = getattr(self, "_registered_provider_secrets", {})
        if type(registry) is dict:
            registry.clear()
