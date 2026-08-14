"""One-use manual consent for real model Provider payload egress.

This module is the B2B-A data plane. It does not implement a Web modal.
Human consent is requested through :class:`EgressConsentBroker`; production
wires that to B2A ``ApprovalQueue`` / Echo authority with kind
``model_egress``.
"""

from __future__ import annotations

import hashlib
import json
import math
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlparse

from js.models.providers import ChatMessage
from js.security.approvals import (
    ApprovalDecisionType,
    ApprovalMode,
    ApprovalQueue,
)
from js.security.net_guard import is_canonical_loopback_literal

MODEL_EGRESS_KIND = "model_egress"
LOOPBACK_EXEMPTION_RECEIPT = "loopback-exemption"

_SNAPSHOT_MAX_UTF8_BYTES = 256 * 1024
_SNAPSHOT_MAX_DEPTH = 32
_SNAPSHOT_MAX_NODES = 8192
_SNAPSHOT_MAX_STRING_UTF8_BYTES = 64 * 1024
_SNAPSHOT_MAX_KEY_UTF8_BYTES = 512

_spent_receipts: set[tuple[str, str, str]] = set()
_spent_lock = threading.Lock()


class EgressConsentError(PermissionError):
    """Raised when model egress consent is missing, denied, or unusable."""


@dataclass(frozen=True, slots=True)
class EgressIdentityV1:
    product_id: str
    channel: str
    owner_key_hash: str
    session_id: str
    run_id: str
    appshell_epoch: str | None = None


@dataclass(frozen=True, slots=True)
class EgressAttemptV1:
    attempt_id: str
    attempt_kind: str
    product_id: str
    channel: str
    owner_key_hash: str
    session_id: str
    run_id: str
    provider_name: str
    provider_generation: str
    model: str
    endpoint_digest: str
    messages_digest: str
    tools_digest: str
    attachments_digest: str
    provenance_digest: str
    temperature: float
    effective_max_tokens: int | None
    appshell_epoch: str | None

    @property
    def attempt_hash(self) -> str:
        return hash_egress_attempt(self)


@dataclass(frozen=True, slots=True)
class EgressConsentReceiptV1:
    attempt_hash: str
    claim_receipt_hash: str
    expires_at: float
    nonce: str


class EgressConsentBroker(Protocol):
    async def request_and_claim(
        self,
        attempt: EgressAttemptV1,
        safe_summary: dict[str, Any],
    ) -> EgressConsentReceiptV1: ...


def _canonical_json(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def snapshot_jsonable(value: Any) -> Any:
    """Return a bounded exact-JSON deep snapshot with fixed safe errors."""

    nodes = 0
    aggregate_utf8_bytes = 0

    def limit() -> None:
        raise ValueError("egress snapshot exceeds limits")

    def unsafe() -> None:
        raise ValueError("egress snapshot is not JSON-safe")

    def bounded_utf8(text: str, maximum: int) -> None:
        nonlocal aggregate_utf8_bytes
        if len(text) > maximum:
            limit()
        try:
            byte_length = len(text.encode("utf-8"))
        except UnicodeEncodeError:
            unsafe()
        if byte_length > maximum:
            limit()
        aggregate_utf8_bytes += byte_length
        if aggregate_utf8_bytes > _SNAPSHOT_MAX_UTF8_BYTES:
            limit()

    def visit(item: Any, depth: int) -> Any:
        nonlocal nodes
        if depth > _SNAPSHOT_MAX_DEPTH:
            limit()
        nodes += 1
        if nodes > _SNAPSHOT_MAX_NODES:
            limit()
        if type(item) is dict:
            result: dict[str, Any] = {}
            for key, child in item.items():
                if type(key) is not str:
                    unsafe()
                bounded_utf8(key, _SNAPSHOT_MAX_KEY_UTF8_BYTES)
                result[key] = visit(child, depth + 1)
            return result
        if type(item) is list:
            return [visit(child, depth + 1) for child in item]
        if item is None or type(item) in {bool, int}:
            if type(item) is int:
                digit_upper_bound = (item.bit_length() * 30103 + 99_999) // 100_000
                if digit_upper_bound + int(item < 0) > _SNAPSHOT_MAX_UTF8_BYTES:
                    limit()
            return item
        if type(item) is float:
            if not math.isfinite(item):
                unsafe()
            return item
        if type(item) is str:
            bounded_utf8(item, _SNAPSHOT_MAX_STRING_UTF8_BYTES)
            return item
        unsafe()
        return None

    snapshot = visit(value, 0)
    encoder = json.JSONEncoder(
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    encoder.encode(snapshot)
    return snapshot


def digest_jsonable(value: Any) -> str:
    return hashlib.sha256(_canonical_json(snapshot_jsonable(value)).encode("utf-8")).hexdigest()


def freeze_messages(messages: list[ChatMessage]) -> list[ChatMessage]:
    frozen: list[ChatMessage] = []
    for message in messages:
        content = message.content
        if type(content) is str:
            frozen_content: str | list[dict[str, Any]] = content
        else:
            frozen_content = snapshot_jsonable(content)
        frozen.append(
            ChatMessage(
                role=message.role,
                content=frozen_content,
                tool_calls=(
                    snapshot_jsonable(message.tool_calls)
                    if message.tool_calls is not None
                    else None
                ),
                tool_call_id=message.tool_call_id,
                name=message.name,
                reasoning_content=message.reasoning_content,
            )
        )
    return frozen


def freeze_tools(tools: list[dict[str, Any]] | None) -> list[dict[str, Any]] | None:
    if tools is None:
        return None
    frozen = snapshot_jsonable(tools)
    if type(frozen) is not list:
        raise ValueError("egress tools snapshot is invalid")
    return frozen


def messages_digest(messages: list[ChatMessage]) -> str:
    from js.models.permit import hash_messages

    return hash_messages(messages)


def tools_digest(tools: list[dict[str, Any]] | None) -> str:
    from js.models.permit import hash_tools_schema

    return hash_tools_schema(tools)


_VALID_ENDPOINT_SCHEMES = frozenset({"http", "https"})


def canonical_provider_endpoint_url(url: Any) -> str | None:
    """Return a usable http(s) endpoint, or ``None`` when it is not classifiable."""

    if type(url) is not str:
        return None
    stripped = url.strip()
    if not stripped:
        return None
    try:
        parsed = urlparse(stripped)
        hostname = (parsed.hostname or "").lower()
        scheme = (parsed.scheme or "").lower()
    except ValueError:
        return None
    if scheme not in _VALID_ENDPOINT_SCHEMES or not hostname:
        return None
    return stripped


def endpoint_digest(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8")).hexdigest() if url else digest_jsonable("")


def provider_endpoint_url(provider: Any) -> str:
    snapshot = getattr(provider, "_endpoint_snapshot", None)
    if type(snapshot) is str and snapshot.strip():
        return snapshot.strip()
    config = getattr(provider, "config", None)
    url = getattr(config, "base_url", None)
    if type(url) is str:
        return url.strip()
    return ""


def provider_endpoint_digest(provider: Any) -> str:
    explicit = getattr(provider, "_endpoint_digest", None)
    if type(explicit) is str and explicit:
        return explicit
    return endpoint_digest(provider_endpoint_url(provider))


def classify_provider_endpoint(provider: Any) -> str:
    """Return ``literal_loopback``, ``remote``, or ``invalid`` for one attempt."""

    snapshot = getattr(provider, "_endpoint_snapshot", None)
    snapshot_url = canonical_provider_endpoint_url(snapshot)
    config = getattr(provider, "config", None)
    declared_url = (
        canonical_provider_endpoint_url(getattr(config, "base_url", None))
        if config is not None
        else None
    )
    url: str | None
    if snapshot_url is not None:
        if config is not None and declared_url != snapshot_url:
            return "invalid"
        url = snapshot_url
    else:
        url = declared_url
    if url is None:
        return "invalid"
    hostname = (urlparse(url).hostname or "").lower()
    if is_canonical_loopback_literal(hostname):
        return "literal_loopback"
    return "remote"


def provider_generation_of(provider: Any) -> str:
    explicit = getattr(provider, "_provider_generation", None)
    if isinstance(explicit, str) and explicit:
        return explicit
    config = getattr(provider, "config", None)
    configured = getattr(config, "generation", None)
    if isinstance(configured, str) and configured:
        return configured
    return f"id:{id(provider)}"


def sanitize_host_port(url: str) -> str:
    if not url:
        return "none"
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        port = parsed.port
    except ValueError:
        return "invalid"
    if not host:
        return "invalid"
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    if port is None:
        return host
    return f"{host}:{port}"


def hash_egress_attempt(attempt: EgressAttemptV1) -> str:
    payload = {
        "attempt_id": attempt.attempt_id,
        "attempt_kind": attempt.attempt_kind,
        "product_id": attempt.product_id,
        "channel": attempt.channel,
        "owner_key_hash": attempt.owner_key_hash,
        "session_id": attempt.session_id,
        "run_id": attempt.run_id,
        "provider_name": attempt.provider_name,
        "provider_generation": attempt.provider_generation,
        "model": attempt.model,
        "endpoint_digest": attempt.endpoint_digest,
        "messages_digest": attempt.messages_digest,
        "tools_digest": attempt.tools_digest,
        "attachments_digest": attempt.attachments_digest,
        "provenance_digest": attempt.provenance_digest,
        "temperature": attempt.temperature,
        "effective_max_tokens": attempt.effective_max_tokens,
        "appshell_epoch": attempt.appshell_epoch,
    }
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def build_egress_attempt(
    *,
    identity: EgressIdentityV1,
    attempt_kind: str,
    provider_name: str,
    provider_generation: str,
    model: str,
    endpoint_url: str,
    messages: list[ChatMessage],
    tools: list[dict[str, Any]] | None,
    attachments: Any,
    provenance: Any,
    temperature: float,
    effective_max_tokens: int | None,
) -> EgressAttemptV1:
    return EgressAttemptV1(
        attempt_id=uuid.uuid4().hex,
        attempt_kind=attempt_kind,
        product_id=identity.product_id,
        channel=identity.channel,
        owner_key_hash=identity.owner_key_hash,
        session_id=identity.session_id,
        run_id=identity.run_id,
        provider_name=provider_name,
        provider_generation=provider_generation,
        model=model,
        endpoint_digest=endpoint_digest(endpoint_url),
        messages_digest=messages_digest(messages),
        tools_digest=tools_digest(tools),
        attachments_digest=digest_jsonable(attachments or []),
        provenance_digest=digest_jsonable(provenance or {}),
        temperature=temperature,
        effective_max_tokens=effective_max_tokens,
        appshell_epoch=identity.appshell_epoch,
    )


def safe_egress_summary(
    attempt: EgressAttemptV1,
    *,
    endpoint_url: str,
    message_count: int,
    tool_count: int,
    source: str = "model_router",
) -> dict[str, Any]:
    return {
        "provider": attempt.provider_name,
        "model": attempt.model,
        "endpoint": sanitize_host_port(endpoint_url),
        "source": source,
        "attempt_kind": attempt.attempt_kind,
        "message_count": message_count,
        "tool_count": tool_count,
    }


def consume_egress_receipt(receipt: EgressConsentReceiptV1) -> None:
    """Spend one consent receipt. Replay or expiry fails closed."""

    if not isinstance(receipt, EgressConsentReceiptV1):
        raise EgressConsentError("egress consent receipt missing")
    if time.time() >= float(receipt.expires_at):
        raise EgressConsentError("egress consent receipt expired")
    key = (receipt.attempt_hash, receipt.claim_receipt_hash, receipt.nonce)
    with _spent_lock:
        if key in _spent_receipts:
            raise EgressConsentError("egress consent receipt replayed")
        _spent_receipts.add(key)


def closed_model_egress_arguments(
    attempt: EgressAttemptV1,
    safe_summary: dict[str, Any],
) -> dict[str, Any]:
    return {
        "attempt_hash": attempt.attempt_hash,
        "attempt_kind": attempt.attempt_kind,
        "provider": safe_summary.get("provider", attempt.provider_name),
        "model": safe_summary.get("model", attempt.model),
        "endpoint": safe_summary.get("endpoint", ""),
        "source": safe_summary.get("source", "model_router"),
        "message_count": int(safe_summary.get("message_count", 0) or 0),
        "tool_count": int(safe_summary.get("tool_count", 0) or 0),
    }


class ApprovalQueueEgressBroker:
    """B2A-backed one-use manual consent broker for ``model_egress``."""

    def __init__(
        self,
        queue: ApprovalQueue,
        *,
        resolver: Any | None = None,
    ) -> None:
        self._queue = queue
        self._resolver = resolver

    async def request_and_claim(
        self,
        attempt: EgressAttemptV1,
        safe_summary: dict[str, Any],
    ) -> EgressConsentReceiptV1:
        if not attempt.owner_key_hash or not attempt.session_id or not attempt.run_id:
            raise EgressConsentError("trusted owner required for model egress")
        arguments = closed_model_egress_arguments(attempt, safe_summary)
        decision = self._queue.request_decision(
            MODEL_EGRESS_KIND,
            arguments,
            context="web",
            mode=ApprovalMode.MANUAL,
            session_id=attempt.session_id,
            run_id=attempt.run_id,
            owner_key_hash=attempt.owner_key_hash,
            queue_if_unhandled=self._resolver is not None,
        )
        if decision.action is ApprovalDecisionType.PENDING:
            if self._resolver is None:
                raise EgressConsentError("egress consent adapter missing")
            resolved = await self._resolver(decision.request_id, safe_summary)
            if type(resolved) is not type(decision) and not hasattr(resolved, "action"):
                raise EgressConsentError("egress consent resolver is invalid")
            decision = resolved
        if decision.action is not ApprovalDecisionType.APPROVE:
            raise EgressConsentError("egress consent rejected")
        proof = self._queue.consume_approved_binding(
            decision.request_id,
            owner_key_hash=attempt.owner_key_hash,
            session_id=attempt.session_id,
            run_id=attempt.run_id,
            tool_name=MODEL_EGRESS_KIND,
            arguments_hash=ApprovalQueue.arguments_hash(arguments),
            require_manual=True,
        )
        if not proof.claimed_now or proof.action is not ApprovalDecisionType.APPROVE:
            raise EgressConsentError("egress consent claim failed")
        return EgressConsentReceiptV1(
            attempt_hash=attempt.attempt_hash,
            claim_receipt_hash=proof.journal_record_hash or proof.binding_hash,
            expires_at=time.time() + 60.0,
            nonce=proof.request_id,
        )


def embedder_endpoint_is_remote(embedder: Any) -> bool:
    url = getattr(embedder, "_base_url", None)
    if not isinstance(url, str) or not url:
        config = getattr(embedder, "config", None)
        url = getattr(config, "base_url", "")
    if not isinstance(url, str) or not url:
        return False
    try:
        hostname = (urlparse(url).hostname or "").lower()
    except ValueError:
        return True
    return not is_canonical_loopback_literal(hostname)
