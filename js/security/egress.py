"""One-use manual consent for model and non-model network egress.

B2B-A/B cover ``model_egress``. B2B-C covers versioned network kinds:
``web_search_egress``, ``connector_egress``, ``provider_discovery_egress``,
``browser_fetch_egress``, and ``skill_registry_egress``.
"""

from __future__ import annotations

import asyncio
import contextvars
import hashlib
import json
import math
import re
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol, cast
from urllib.parse import urlparse

from js.models.providers import ChatMessage
from js.security.approvals import (
    NETWORK_EGRESS_KINDS,
    ApprovalDecisionType,
    ApprovalMode,
    ApprovalQueue,
)
from js.security.net_guard import is_canonical_loopback_literal

MODEL_EGRESS_KIND = "model_egress"
LOOPBACK_EXEMPTION_RECEIPT = "loopback-exemption"
EGRESS_PROVENANCE_SCHEMA = "egress-provenance-v1"
NETWORK_PROVENANCE_SCHEMA = "network-egress-provenance-v1"
NETWORK_PROVENANCE_SOURCES = frozenset(
    {
        "echo_tool",
        "web_search",
        "connector",
        "provider_discovery",
        "browser_fetch",
        "skill_registry",
        "direct_user",
    }
)
_NETWORK_KIND_CODES = {
    "web_search_egress": "wse",
    "connector_egress": "cne",
    "provider_discovery_egress": "pde",
    "browser_fetch_egress": "bfe",
    "skill_registry_egress": "sre",
}
_NETWORK_EGRESS_REQUEST_RE = re.compile(r"^neg:(wse|cne|pde|bfe|sre):[0-9a-f]{32}$")
EGRESS_SOURCE_KINDS = frozenset(
    {
        "direct_user",
        "assistant_history",
        "system",
        "tool_result",
        "memory",
        "cold_capsule",
        "cron_persisted_prompt",
        "fleet_worker",
        "fleet_history",
        "attachment",
        "context_summary",
        "background_model",
    }
)
_WEB_EGRESS_CHANNELS = frozenset(
    {"api_chat", "ws_message", "ws_stream"}
)
_WEB_EGRESS_SUFFIXES = ("_api_chat", "_ws_message", "_ws_stream")
_WEB_NETWORK_ADAPTER_CHANNELS = frozenset(
    {"search", "provider_test_cloud", "provider_add_cloud"}
)
_WEB_NETWORK_ADAPTER_SUFFIXES = (
    "_search",
    "_provider_test_cloud",
    "_provider_add_cloud",
)
_DIGEST_RE = re.compile(r"^(?:sha256:)?[0-9a-f]{64}$")
_ATTEMPT_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_MODEL_EGRESS_REQUEST_RE = re.compile(r"^meg:[0-9a-f]{32}$")
_MAX_PROVENANCE_SOURCES = 256
_MAX_PROVENANCE_ATTACHMENTS = 64
_MAX_CAPSULE_SOURCE_IDS = 32
_MAX_CAPSULE_ID_CHARS = 256

_SNAPSHOT_MAX_UTF8_BYTES = 256 * 1024
_SNAPSHOT_MAX_DEPTH = 32
_SNAPSHOT_MAX_NODES = 8192
_SNAPSHOT_MAX_STRING_UTF8_BYTES = 64 * 1024
_SNAPSHOT_MAX_KEY_UTF8_BYTES = 512

_spent_receipts: set[tuple[str, str, str]] = set()
_spent_lock = threading.Lock()
_network_broker: contextvars.ContextVar[Any] = contextvars.ContextVar(
    "js_network_egress_broker", default=None
)
_network_issuer: contextvars.ContextVar[Any] = contextvars.ContextVar(
    "js_network_egress_issuer", default=None
)


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


class NetworkEgressKind(Enum):
    WEB_SEARCH = "web_search_egress"
    CONNECTOR = "connector_egress"
    PROVIDER_DISCOVERY = "provider_discovery_egress"
    BROWSER_FETCH = "browser_fetch_egress"
    SKILL_REGISTRY = "skill_registry_egress"


@dataclass(frozen=True, slots=True)
class NetworkEgressAttemptV1:
    version: int
    attempt_id: str
    kind: str
    product_id: str
    channel: str
    owner_key_hash: str
    session_id: str
    run_id: str
    target_identity: str
    endpoint_generation: str
    credential_generation: str
    method: str
    payload_digest: str
    extra_digest: str
    provenance_digest: str
    appshell_epoch: str | None

    @property
    def attempt_hash(self) -> str:
        return hash_network_egress_attempt(self)


@dataclass(frozen=True, slots=True)
class NetworkEgressSnapshotV1:
    endpoint_url: str
    method: str
    payload: Any
    extra: Any
    endpoint_generation: str
    credential_generation: str


@dataclass(frozen=True, slots=True)
class NetworkEgressAuthorizationV1:
    attempt: NetworkEgressAttemptV1
    receipt: EgressConsentReceiptV1
    permit: Any
    snapshot: NetworkEgressSnapshotV1


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


def _provenance_text(value: Any, label: str) -> str:
    if type(value) is not str:
        raise EgressConsentError(f"egress provenance {label} is invalid")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise EgressConsentError(f"egress provenance {label} is invalid") from None
    return value


def _provenance_int(value: Any, label: str) -> int:
    if type(value) is not int:
        raise EgressConsentError(f"egress provenance {label} is invalid")
    if value < 0:
        raise EgressConsentError(f"egress provenance {label} is invalid")
    return value


def _provenance_digest(value: Any, label: str) -> str:
    if type(value) is not str or not value:
        raise EgressConsentError(f"egress provenance {label} digest is invalid")
    if not _DIGEST_RE.fullmatch(value):
        raise EgressConsentError(f"egress provenance {label} digest is invalid")
    return value[7:] if value.startswith("sha256:") else value


def _provenance_id_tuple(value: Any, label: str) -> tuple[str, ...]:
    if type(value) is not list and type(value) is not tuple:
        raise EgressConsentError(f"egress provenance {label} is invalid")
    if len(value) > _MAX_CAPSULE_SOURCE_IDS:
        raise EgressConsentError("egress provenance exceeds limits")
    items: list[str] = []
    for item in value:
        text = _provenance_text(item, label)
        if not text or len(text) > _MAX_CAPSULE_ID_CHARS:
            raise EgressConsentError(f"egress provenance {label} is invalid")
        items.append(text)
    return tuple(items)


def _freeze_capsule_identity(source: dict[str, Any]) -> dict[str, Any]:
    ids = _provenance_id_tuple(source.get("source_record_ids"), "source record id")
    hashes = _provenance_id_tuple(source.get("source_hashes"), "source hash")
    if len(ids) != len(hashes):
        raise EgressConsentError("egress provenance capsule identity is invalid")
    if not ids:
        raise EgressConsentError("egress provenance capsule identity is invalid")
    frozen_ids: list[str] = []
    frozen_hashes: list[str] = []
    seen: dict[str, str] = {}
    for record_id, raw_hash in zip(ids, hashes, strict=True):
        digest = _provenance_digest(raw_hash, "capsule source")
        previous = seen.get(record_id)
        if previous is not None:
            if previous != digest:
                raise EgressConsentError("egress provenance source identity is duplicate")
            continue
        seen[record_id] = digest
        frozen_ids.append(record_id)
        frozen_hashes.append(digest)
    return {
        "source_record_ids": frozen_ids,
        "source_hashes": frozen_hashes,
        "source_set_hash": _provenance_digest(source.get("source_set_hash"), "source set"),
        "capsule_digest": _provenance_digest(source.get("capsule_digest"), "capsule"),
    }


def capsule_lineage_from_meta(
    meta: Any,
    capsule_text: str,
    *,
    session_id: str,
) -> dict[str, Any]:
    """Build privacy-safe ColdCapsule identity fields. Never stores raw text."""

    if type(meta) is not dict:
        meta = {}
    if type(capsule_text) is not str or not capsule_text:
        raise EgressConsentError("egress provenance capsule is invalid")
    if type(session_id) is not str or not session_id:
        raise EgressConsentError("egress provenance capsule session is invalid")
    version = meta.get("version", 1)
    if type(version) is not int or isinstance(version, bool) or version < 1:
        version = 1
    source_range = meta.get("source_range")
    range_part = source_range if type(source_range) is str and source_range else "none"
    record_id = f"capsule:{session_id}:v{version}:{range_part}"
    capsule_digest = hashlib.sha256(capsule_text.encode("utf-8")).hexdigest()
    source_hash = hashlib.sha256(f"{record_id}|{capsule_digest}".encode()).hexdigest()
    source_set_hash = digest_jsonable(
        {"source_record_ids": [record_id], "source_hashes": [source_hash]}
    )
    return {
        "source_record_ids": [record_id],
        "source_hashes": [source_hash],
        "source_set_hash": source_set_hash,
        "capsule_digest": capsule_digest,
    }


def memory_records_from_working(entries: Any) -> list[dict[str, Any]]:
    """Hash working-memory values without retaining raw text."""

    if type(entries) not in {list, tuple}:
        return []
    records: list[dict[str, Any]] = []
    for item in entries:
        if type(item) is not dict:
            continue
        key = item.get("key")
        value = item.get("value")
        if type(key) is not str or not key or type(value) is not str:
            continue
        records.append(
            {
                "record_id": f"working:{key}",
                "content_digest": hashlib.sha256(value.encode("utf-8")).hexdigest(),
            }
        )
        if len(records) >= _MAX_CAPSULE_SOURCE_IDS:
            break
    return records


def model_egress_request_id(attempt: EgressAttemptV1) -> str:
    """Stable consent request identity for one Router attempt."""

    if type(attempt.attempt_id) is not str or not _ATTEMPT_ID_RE.fullmatch(attempt.attempt_id):
        raise EgressConsentError("egress attempt identity is invalid")
    return f"meg:{attempt.attempt_id}"


def freeze_egress_provenance(value: Any) -> dict[str, Any]:
    """Validate and freeze a structured egress-provenance-v1 object."""

    if type(value) is not dict:
        raise EgressConsentError("egress provenance is not a JSON object")
    schema = value.get("schema")
    if schema != EGRESS_PROVENANCE_SCHEMA:
        raise EgressConsentError("egress provenance schema is invalid")
    sources = value.get("sources")
    if type(sources) is not list:
        raise EgressConsentError("egress provenance sources are invalid")
    if not sources:
        raise EgressConsentError("egress provenance sources are required")
    if len(sources) > _MAX_PROVENANCE_SOURCES:
        raise EgressConsentError("egress provenance exceeds limits")
    frozen_sources: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for source in sources:
        if type(source) is not dict:
            raise EgressConsentError("egress provenance source is invalid")
        kind = source.get("kind")
        if type(kind) is not str or kind not in EGRESS_SOURCE_KINDS:
            raise EgressConsentError("egress provenance source kind is invalid")
        record_id = _provenance_text(source.get("record_id"), "record id")
        if not record_id:
            raise EgressConsentError("egress provenance record id is invalid")
        if record_id in seen_ids:
            raise EgressConsentError("egress provenance source identity is duplicate")
        seen_ids.add(record_id)
        frozen_source = {
            "kind": kind,
            "record_id": record_id,
            "content_digest": _provenance_digest(source.get("content_digest"), "source"),
            "parent_turn_id": _provenance_text(
                source.get("parent_turn_id", ""), "parent turn"
            ),
            "parent_run_id": _provenance_text(source.get("parent_run_id", ""), "parent run"),
            "parent_attempt_id": _provenance_text(
                source.get("parent_attempt_id", ""), "parent attempt"
            ),
        }
        if kind == "cold_capsule":
            frozen_source.update(_freeze_capsule_identity(source))
        frozen_sources.append(frozen_source)
    attachments = value.get("attachments", [])
    if type(attachments) is not list:
        raise EgressConsentError("egress provenance attachments are invalid")
    if len(attachments) > _MAX_PROVENANCE_ATTACHMENTS:
        raise EgressConsentError("egress provenance exceeds limits")
    frozen_attachments: list[dict[str, Any]] = []
    for item in attachments:
        if type(item) is not dict:
            raise EgressConsentError("egress provenance attachment is invalid")
        frozen_attachments.append(
            {
                "index": _provenance_int(item.get("index"), "attachment index"),
                "media_type": _provenance_text(item.get("media_type"), "media type"),
                "size": _provenance_int(item.get("size"), "attachment size"),
                "content_digest": _provenance_digest(item.get("content_digest"), "attachment"),
            }
        )
    frozen = {
        "schema": EGRESS_PROVENANCE_SCHEMA,
        "sources": frozen_sources,
        "attachments": frozen_attachments,
        "parent_turn_id": _provenance_text(value.get("parent_turn_id", ""), "parent turn"),
        "parent_run_id": _provenance_text(value.get("parent_run_id", ""), "parent run"),
        "parent_attempt_id": _provenance_text(
            value.get("parent_attempt_id", ""), "parent attempt"
        ),
        "channel": _provenance_text(value.get("channel", ""), "channel"),
        "owner_key_hash": _provenance_text(value.get("owner_key_hash", ""), "owner"),
        "session_id": _provenance_text(value.get("session_id", ""), "session"),
        "run_id": _provenance_text(value.get("run_id", ""), "run"),
    }
    try:
        return cast("dict[str, Any]", snapshot_jsonable(frozen))
    except ValueError:
        raise EgressConsentError("egress provenance is invalid") from None


def normalize_egress_provenance(value: Any) -> Any:
    """Keep B2B-A empty snapshots; strictly validate structured provenance."""

    if value is None:
        return {}
    if type(value) is dict and not value:
        return {}
    return freeze_egress_provenance(value)


def _content_digest(value: Any) -> str:
    if type(value) is str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()
    return digest_jsonable(value)


def _user_source_kind(channel: str) -> str:
    if channel == "cron_chat":
        return "cron_persisted_prompt"
    if channel in {"fleet_worker", "fleet_coordinator"}:
        return "fleet_worker"
    if channel == "fleet_history":
        return "fleet_history"
    if channel == "context_summary":
        return "context_summary"
    if channel in {
        "background_model",
        "memory_extraction",
        "profile_update",
        "dreaming",
        "skill_evolution",
        "setup_model_test",
        "agent_api",
    }:
        return "background_model"
    return "direct_user"


def build_model_egress_provenance(
    *,
    messages: list[ChatMessage],
    attachments: Any,
    context: Any,
    parent_attempt_id: str = "",
    capsule: dict[str, Any] | None = None,
    capsule_text: str = "",
    memory_records: list[dict[str, Any]] | None = None,
    capsule_user_index: int | None = None,
) -> dict[str, Any]:
    """Build a privacy-safe v1 provenance snapshot from Echo messages."""

    sources: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    parent_turn_id = str(getattr(context, "parent_turn_id", "") or "") or "root"
    parent_run_id = str(getattr(context, "run_id", "") or "")

    def add(kind: str, record_id: str, digest: str, extra: dict[str, Any] | None = None) -> None:
        identity = record_id if record_id not in seen_ids else f"{record_id}:{len(sources)}"
        seen_ids.add(identity)
        record = {
            "kind": kind,
            "record_id": identity,
            "content_digest": digest,
            "parent_turn_id": parent_turn_id,
            "parent_run_id": parent_run_id,
            "parent_attempt_id": parent_attempt_id,
        }
        if extra:
            record.update(extra)
        sources.append(record)

    if type(capsule) is dict and type(capsule_text) is str and capsule_text:
        lineage = capsule_lineage_from_meta(
            capsule,
            capsule_text,
            session_id=str(getattr(context, "session_id", "") or ""),
        )
        add(
            "cold_capsule",
            "capsule:0",
            lineage["capsule_digest"],
            lineage,
        )

    for item in memory_records or []:
        if type(item) is not dict:
            continue
        record_id = item.get("record_id")
        digest = item.get("content_digest")
        if type(record_id) is not str or not record_id or type(digest) is not str:
            continue
        add("memory", record_id, digest)

    for index, message in enumerate(messages):
        digest = _content_digest(message.content)
        if message.role == "system":
            add("system", f"system:{index}", digest)
        elif message.role == "tool":
            add("tool_result", f"tool:{message.tool_call_id or index}", digest)
        elif message.role == "assistant":
            add("assistant_history", f"assistant:{index}", digest)
        elif message.role == "user":
            if capsule_user_index is not None and index == capsule_user_index:
                continue
            add(
                _user_source_kind(str(getattr(context, "channel", "") or "")),
                f"user:{index}",
                digest,
            )

    attachment_records: list[dict[str, Any]] = []
    manifest = attachments or []
    if type(manifest) not in {list, tuple}:
        manifest = []
    for index, item in enumerate(manifest):
        if type(item) is not dict:
            continue
        raw_digest = item.get("sha256") or item.get("content_digest") or ""
        digest = (
            _provenance_digest(raw_digest, "attachment")
            if type(raw_digest) is str and raw_digest
            else digest_jsonable(item)
        )
        add("attachment", f"attachment:{index}", digest)
        size = item.get("size", 0)
        media_type = item.get("media_type", "application/octet-stream")
        attachment_records.append(
            {
                "index": index,
                "media_type": media_type if type(media_type) is str else "application/octet-stream",
                "size": size if type(size) is int else 0,
                "content_digest": digest,
            }
        )

    return freeze_egress_provenance(
        {
            "schema": EGRESS_PROVENANCE_SCHEMA,
            "sources": sources,
            "attachments": attachment_records,
            "parent_turn_id": parent_turn_id,
            "parent_run_id": str(getattr(context, "run_id", "") or ""),
            "parent_attempt_id": parent_attempt_id,
            "channel": str(getattr(context, "channel", "") or ""),
            "owner_key_hash": str(getattr(context, "owner_key_hash", "") or ""),
            "session_id": str(getattr(context, "session_id", "") or ""),
            "run_id": str(getattr(context, "run_id", "") or ""),
        }
    )


def cli_is_interactive() -> bool:
    stdin_tty = getattr(sys.stdin, "isatty", None)
    stdout_tty = getattr(sys.stdout, "isatty", None)
    return bool(callable(stdin_tty) and stdin_tty() and callable(stdout_tty) and stdout_tty())


def channel_has_egress_adapter(channel: str) -> bool:
    if type(channel) is not str or not channel:
        return False
    if channel in _WEB_EGRESS_CHANNELS or channel.endswith(_WEB_EGRESS_SUFFIXES):
        return True
    return channel == "cli" and cli_is_interactive()


def channel_has_network_egress_adapter(channel: str) -> bool:
    if channel_has_egress_adapter(channel):
        return True
    if type(channel) is not str or not channel:
        return False
    if channel in _WEB_NETWORK_ADAPTER_CHANNELS:
        return True
    return channel.endswith(_WEB_NETWORK_ADAPTER_SUFFIXES)


def set_network_egress_runtime(broker: Any, issuer: Any) -> tuple[Any, Any]:
    return (_network_broker.set(broker), _network_issuer.set(issuer))


def reset_network_egress_runtime(tokens: tuple[Any, Any]) -> None:
    _network_broker.reset(tokens[0])
    _network_issuer.reset(tokens[1])


def current_network_egress_broker() -> Any:
    return _network_broker.get()


def current_network_egress_issuer() -> Any:
    return _network_issuer.get()


def prompt_cli_model_egress(safe_summary: dict[str, Any]) -> bool:
    """TTY-only yes/no prompt. Never prints raw prompt, tools, or paths."""

    print("Model egress consent required")
    for key in (
        "provider",
        "model",
        "endpoint",
        "attempt_kind",
        "message_count",
        "tool_count",
        "attachment_count",
        "source_kinds",
        "attempt_hash",
    ):
        if key in safe_summary:
            print(f"  {key}: {safe_summary[key]}")
    answer = input("Approve remote model egress? [y/N] ").strip().lower()
    return answer in {"y", "yes"}


async def poll_egress_decision(
    queue: ApprovalQueue,
    request_id: str,
    *,
    owner_key_hash: str,
    cancel_token: Any | None = None,
) -> Any:
    deadline = time.monotonic() + 300.0
    while time.monotonic() < deadline:
        if cancel_token is not None and bool(getattr(cancel_token, "is_set", lambda: False)()):
            raise EgressConsentError("egress consent cancelled")
        queue._cleanup_stale()
        decision = await asyncio.to_thread(
            queue.take_decision,
            request_id,
            owner_key_hash=owner_key_hash,
        )
        if decision is not None:
            return decision
        pending = queue.get_pending_request(request_id, owner_key_hash=owner_key_hash)
        if pending is None:
            raise EgressConsentError("egress consent rejected")
        await asyncio.sleep(0.05)
    raise EgressConsentError("egress consent timeout")


def make_product_egress_resolver(queue: ApprovalQueue) -> Any:
    async def resolve(request_id: str, safe_summary: dict[str, Any]) -> Any:
        from js.echo.turn_context import current_runtime_context

        context = current_runtime_context()
        if context is None:
            raise EgressConsentError("trusted owner required for model egress")
        if context.channel == "cli" and cli_is_interactive():
            kind = safe_summary.get("kind") if type(safe_summary) is dict else None
            if type(kind) is str and kind in NETWORK_EGRESS_KINDS:
                approved = await asyncio.to_thread(prompt_cli_network_egress, safe_summary)
            else:
                approved = await asyncio.to_thread(prompt_cli_model_egress, safe_summary)
            return queue.decide(
                request_id,
                ApprovalDecisionType.APPROVE if approved else ApprovalDecisionType.REJECT,
                owner_key_hash=context.owner_key_hash,
            )
        if channel_has_network_egress_adapter(context.channel):
            return await poll_egress_decision(
                queue,
                request_id,
                owner_key_hash=context.owner_key_hash,
                cancel_token=context.cancel_token,
            )
        raise EgressConsentError("egress consent adapter missing")

    return resolve


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
        provenance_digest=digest_jsonable(normalize_egress_provenance(provenance)),
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
    provenance: Any = None,
    attachment_count: int = 0,
) -> dict[str, Any]:
    kinds: list[str] = []
    if type(provenance) is dict:
        sources = provenance.get("sources")
        if type(sources) is list:
            seen: set[str] = set()
            for item in sources:
                if type(item) is not dict:
                    continue
                kind = item.get("kind")
                if type(kind) is str:
                    seen.add(kind)
            kinds = sorted(seen)
    return {
        "provider": attempt.provider_name,
        "model": attempt.model,
        "endpoint": sanitize_host_port(endpoint_url),
        "source": source,
        "attempt_kind": attempt.attempt_kind,
        "message_count": message_count,
        "tool_count": tool_count,
        "attachment_count": attachment_count,
        "source_kinds": kinds,
        "attempt_hash": attempt.attempt_hash,
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


def classify_network_endpoint_url(url: Any) -> str:
    if type(url) is not str:
        return "invalid"
    stripped = url.strip()
    if not stripped:
        return "invalid"
    try:
        parsed = urlparse(stripped)
        hostname = (parsed.hostname or "").lower()
        scheme = (parsed.scheme or "").lower()
    except ValueError:
        return "invalid"
    if scheme not in _VALID_ENDPOINT_SCHEMES or not hostname:
        return "invalid"
    if is_canonical_loopback_literal(hostname):
        return "literal_loopback"
    return "remote"


def endpoint_generation_of(url: str) -> str:
    classification = classify_network_endpoint_url(url)
    if classification == "invalid":
        raise EgressConsentError("network endpoint is invalid")
    parsed = urlparse(url.strip())
    hostname = (parsed.hostname or "").lower()
    scheme = (parsed.scheme or "").lower()
    port = parsed.port
    path = parsed.path or "/"
    material = {
        "scheme": scheme,
        "host": hostname,
        "port": port,
        "path": path,
    }
    return hashlib.sha256(_canonical_json(material).encode("utf-8")).hexdigest()


def credential_generation_of(secret: Any) -> str:
    if secret is None or secret == "":
        return "none"
    if type(secret) is not str:
        raise EgressConsentError("credential generation is invalid")
    return hashlib.sha256(b"js.network_egress.cred.v1\0" + secret.encode("utf-8")).hexdigest()


def normalize_network_provenance(value: Any) -> dict[str, Any]:
    if type(value) is not dict:
        raise EgressConsentError("network provenance is not a JSON object")
    schema = value.get("schema")
    if schema != NETWORK_PROVENANCE_SCHEMA:
        raise EgressConsentError("network provenance schema is invalid")
    kind = value.get("kind")
    if type(kind) is not str or kind not in NETWORK_EGRESS_KINDS:
        raise EgressConsentError("network provenance kind is invalid")
    source = value.get("source")
    if type(source) is not str or source not in NETWORK_PROVENANCE_SOURCES:
        raise EgressConsentError("network provenance source is invalid")
    tool_name = value.get("tool_name")
    if type(tool_name) is not str or not tool_name or len(tool_name) > 128:
        raise EgressConsentError("network provenance tool name is invalid")
    frozen = snapshot_jsonable(
        {
            "schema": NETWORK_PROVENANCE_SCHEMA,
            "kind": kind,
            "source": source,
            "tool_name": tool_name,
        }
    )
    if type(frozen) is not dict:
        raise EgressConsentError("network provenance snapshot is invalid")
    return frozen


def hash_network_egress_attempt(attempt: NetworkEgressAttemptV1) -> str:
    payload = {
        "mac_domain": "js.network_egress.attempt.v1",
        "version": attempt.version,
        "attempt_id": attempt.attempt_id,
        "kind": attempt.kind,
        "product_id": attempt.product_id,
        "channel": attempt.channel,
        "owner_key_hash": attempt.owner_key_hash,
        "session_id": attempt.session_id,
        "run_id": attempt.run_id,
        "target_identity": attempt.target_identity,
        "endpoint_generation": attempt.endpoint_generation,
        "credential_generation": attempt.credential_generation,
        "method": attempt.method,
        "payload_digest": attempt.payload_digest,
        "extra_digest": attempt.extra_digest,
        "provenance_digest": attempt.provenance_digest,
        "appshell_epoch": attempt.appshell_epoch,
    }
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _coerce_network_kind(kind: NetworkEgressKind | str) -> str:
    if isinstance(kind, NetworkEgressKind):
        return kind.value
    if type(kind) is str and kind in NETWORK_EGRESS_KINDS:
        return kind
    raise EgressConsentError("network egress kind is invalid")


def build_network_egress_attempt(
    *,
    identity: EgressIdentityV1,
    kind: NetworkEgressKind | str,
    target_identity: str,
    endpoint_url: str,
    method: str,
    payload: Any,
    provenance: Any,
    credential_generation: str,
    extra: Any = None,
) -> NetworkEgressAttemptV1:
    kind_value = _coerce_network_kind(kind)
    if type(target_identity) is not str or not target_identity or len(target_identity) > 128:
        raise EgressConsentError("network target identity is invalid")
    if type(method) is not str or method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"}:
        raise EgressConsentError("network method is invalid")
    if type(credential_generation) is not str or not credential_generation:
        raise EgressConsentError("credential generation is invalid")
    frozen_payload = snapshot_jsonable(payload)
    frozen_extra = snapshot_jsonable(extra or {})
    frozen_provenance = normalize_network_provenance(provenance)
    if frozen_provenance["kind"] != kind_value:
        raise EgressConsentError("network provenance kind mismatch")
    return NetworkEgressAttemptV1(
        version=1,
        attempt_id=uuid.uuid4().hex,
        kind=kind_value,
        product_id=identity.product_id,
        channel=identity.channel,
        owner_key_hash=identity.owner_key_hash,
        session_id=identity.session_id,
        run_id=identity.run_id,
        target_identity=target_identity,
        endpoint_generation=endpoint_generation_of(endpoint_url),
        credential_generation=credential_generation,
        method=method,
        payload_digest=digest_jsonable(frozen_payload),
        extra_digest=digest_jsonable(frozen_extra),
        provenance_digest=digest_jsonable(frozen_provenance),
        appshell_epoch=identity.appshell_epoch,
    )


def network_egress_request_id(attempt: NetworkEgressAttemptV1) -> str:
    if type(attempt.attempt_id) is not str or not _ATTEMPT_ID_RE.fullmatch(attempt.attempt_id):
        raise EgressConsentError("network attempt identity is invalid")
    code = _NETWORK_KIND_CODES.get(attempt.kind)
    if code is None:
        raise EgressConsentError("network egress kind is invalid")
    request_id = f"neg:{code}:{attempt.attempt_id}"
    if not _NETWORK_EGRESS_REQUEST_RE.fullmatch(request_id):
        raise EgressConsentError("network attempt identity is invalid")
    return request_id


def closed_network_egress_arguments(
    attempt: NetworkEgressAttemptV1,
    safe_summary: dict[str, Any],
) -> dict[str, Any]:
    return {
        "attempt_hash": attempt.attempt_hash,
        "kind": attempt.kind,
        "target": safe_summary.get("target", attempt.target_identity),
        "endpoint": safe_summary.get("endpoint", ""),
        "method": attempt.method,
        "source": safe_summary.get("source", attempt.kind),
        "attempt_id_prefix": attempt.attempt_id[:8],
    }


def safe_network_egress_summary(
    attempt: NetworkEgressAttemptV1,
    *,
    endpoint_url: str,
    source: str,
) -> dict[str, Any]:
    return {
        "kind": attempt.kind,
        "target": attempt.target_identity,
        "endpoint": sanitize_host_port(endpoint_url),
        "method": attempt.method,
        "source": source,
        "attempt_hash": attempt.attempt_hash,
    }


def prompt_cli_network_egress(safe_summary: dict[str, Any]) -> bool:
    print("Network egress consent required")
    for key in ("kind", "target", "endpoint", "method", "source", "attempt_hash"):
        if key in safe_summary:
            print(f"  {key}: {safe_summary[key]}")
    answer = input("Approve remote network egress? [y/N] ").strip().lower()
    return answer in {"y", "yes"}


def _runtime_identity() -> EgressIdentityV1:
    from js.echo.turn_context import current_runtime_context

    context = current_runtime_context()
    if context is None:
        raise EgressConsentError("trusted owner required for network egress")
    epoch = None
    binding = getattr(context, "appshell_epoch_binding", None)
    if binding is not None:
        epoch = str(getattr(binding, "epoch", "") or "") or None
    identity = EgressIdentityV1(
        product_id=str(context.product_id),
        channel=str(context.channel),
        owner_key_hash=str(context.owner_key_hash),
        session_id=str(context.session_id),
        run_id=str(context.run_id),
        appshell_epoch=epoch,
    )
    if not identity.owner_key_hash or not identity.session_id or not identity.run_id:
        raise EgressConsentError("trusted owner required for network egress")
    return identity


def _raise_if_network_cancelled() -> None:
    from js.echo.turn_context import current_runtime_context

    context = current_runtime_context()
    cancel = getattr(context, "cancel_token", None) if context is not None else None
    if cancel is not None and bool(getattr(cancel, "is_set", lambda: False)()):
        raise EgressConsentError("egress consent cancelled")


async def authorize_network_egress(
    *,
    kind: NetworkEgressKind | str,
    target_identity: str,
    endpoint_url: str,
    method: str,
    payload: Any,
    provenance: Any,
    credential_generation: str,
    extra: Any = None,
    broker: Any | None = None,
    permit_issuer: Any | None = None,
) -> NetworkEgressAuthorizationV1:
    from js.models.permit import NetworkEgressPermitIssuer

    _raise_if_network_cancelled()
    frozen_payload = snapshot_jsonable(payload)
    frozen_extra = snapshot_jsonable(extra or {})
    classification = classify_network_endpoint_url(endpoint_url)
    if classification == "invalid":
        raise EgressConsentError("network endpoint is invalid")
    identity = _runtime_identity()
    attempt = build_network_egress_attempt(
        identity=identity,
        kind=kind,
        target_identity=target_identity,
        endpoint_url=endpoint_url,
        method=method,
        payload=frozen_payload,
        provenance=provenance,
        credential_generation=credential_generation,
        extra=frozen_extra,
    )
    snapshot = NetworkEgressSnapshotV1(
        endpoint_url=endpoint_url.strip() if type(endpoint_url) is str else "",
        method=attempt.method,
        payload=frozen_payload,
        extra=frozen_extra,
        endpoint_generation=attempt.endpoint_generation,
        credential_generation=attempt.credential_generation,
    )
    bound_broker = broker if broker is not None else current_network_egress_broker()
    issuer = permit_issuer if permit_issuer is not None else current_network_egress_issuer()
    if not isinstance(issuer, NetworkEgressPermitIssuer):
        raise EgressConsentError("network egress permit issuer required")
    receipt: EgressConsentReceiptV1
    if classification == "literal_loopback":
        receipt = EgressConsentReceiptV1(
            attempt_hash=attempt.attempt_hash,
            claim_receipt_hash=LOOPBACK_EXEMPTION_RECEIPT,
            expires_at=time.time() + 60.0,
            nonce=f"loopback-{attempt.attempt_id}",
        )
    else:
        if bound_broker is None:
            raise EgressConsentError("egress consent broker required")
        if not channel_has_network_egress_adapter(identity.channel):
            raise EgressConsentError("egress consent adapter missing")
        summary = safe_network_egress_summary(
            attempt,
            endpoint_url=snapshot.endpoint_url,
            source=attempt.kind,
        )
        claim = getattr(bound_broker, "request_and_claim_network", None)
        if not callable(claim):
            claim = bound_broker.request_and_claim
        receipt = await claim(attempt, summary)
        if (
            not isinstance(receipt, EgressConsentReceiptV1)
            or receipt.attempt_hash != attempt.attempt_hash
            or not receipt.claim_receipt_hash
            or not receipt.nonce
        ):
            raise EgressConsentError("egress consent receipt does not match the attempt")
        consume_egress_receipt(receipt)
    current = _runtime_identity()
    if (
        current.owner_key_hash != attempt.owner_key_hash
        or current.session_id != attempt.session_id
        or current.run_id != attempt.run_id
        or current.channel != attempt.channel
        or current.product_id != attempt.product_id
        or (current.appshell_epoch or "") != (attempt.appshell_epoch or "")
    ):
        raise EgressConsentError("network egress identity changed after consent")
    if endpoint_generation_of(snapshot.endpoint_url) != attempt.endpoint_generation:
        raise EgressConsentError("network endpoint generation mismatch")
    if digest_jsonable(snapshot.payload) != attempt.payload_digest:
        raise EgressConsentError("network payload changed after consent")
    permit = issuer.issue(
        kind=attempt.kind,
        attempt_id=attempt.attempt_id,
        attempt_hash=attempt.attempt_hash,
        owner_key_hash=attempt.owner_key_hash,
        session_id=attempt.session_id,
        run_id=attempt.run_id,
        channel=attempt.channel,
        product_id=attempt.product_id,
        endpoint_generation=attempt.endpoint_generation,
        credential_generation=attempt.credential_generation,
        payload_digest=attempt.payload_digest,
        provenance_digest=attempt.provenance_digest,
        consent_receipt_hash=receipt.claim_receipt_hash,
        appshell_epoch=attempt.appshell_epoch,
        endpoint_digest=digest_jsonable(snapshot.endpoint_url),
    )
    issuer.verify_and_consume(
        permit,
        kind=attempt.kind,
        attempt_id=attempt.attempt_id,
        attempt_hash=attempt.attempt_hash,
        owner_key_hash=attempt.owner_key_hash,
        session_id=attempt.session_id,
        run_id=attempt.run_id,
        channel=attempt.channel,
        product_id=attempt.product_id,
        endpoint_generation=attempt.endpoint_generation,
        credential_generation=attempt.credential_generation,
        payload_digest=attempt.payload_digest,
        provenance_digest=attempt.provenance_digest,
        consent_receipt_hash=receipt.claim_receipt_hash,
        appshell_epoch=attempt.appshell_epoch,
        endpoint_digest=digest_jsonable(snapshot.endpoint_url),
    )
    _raise_if_network_cancelled()
    return NetworkEgressAuthorizationV1(
        attempt=attempt,
        receipt=receipt,
        permit=permit,
        snapshot=snapshot,
    )


def assert_network_authorization_fresh(auth: NetworkEgressAuthorizationV1) -> None:
    if not isinstance(auth, NetworkEgressAuthorizationV1):
        raise EgressConsentError("network authorization is invalid")
    identity = _runtime_identity()
    attempt = auth.attempt
    snapshot = auth.snapshot
    if (
        identity.owner_key_hash != attempt.owner_key_hash
        or identity.session_id != attempt.session_id
        or identity.run_id != attempt.run_id
        or identity.channel != attempt.channel
        or identity.product_id != attempt.product_id
        or (identity.appshell_epoch or "") != (attempt.appshell_epoch or "")
    ):
        raise EgressConsentError("network egress identity changed after consent")
    if snapshot.endpoint_generation != attempt.endpoint_generation:
        raise EgressConsentError("network endpoint generation mismatch")
    if endpoint_generation_of(snapshot.endpoint_url) != attempt.endpoint_generation:
        raise EgressConsentError("network endpoint generation mismatch")
    if snapshot.credential_generation != attempt.credential_generation:
        raise EgressConsentError("network credential generation mismatch")
    if digest_jsonable(snapshot.payload) != attempt.payload_digest:
        raise EgressConsentError("network payload changed after consent")
    _raise_if_network_cancelled()


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
        "attachment_count": int(safe_summary.get("attachment_count", 0) or 0),
        "source_kinds": list(safe_summary.get("source_kinds", []) or []),
    }


class ApprovalQueueEgressBroker:
    """B2A-backed one-use manual consent broker for ``model_egress``."""

    def __init__(
        self,
        queue: ApprovalQueue,
        *,
        resolver: Any | None = None,
        allow_queue: Any | None = None,
    ) -> None:
        self._queue = queue
        self._resolver = resolver
        self._allow_queue = allow_queue

    async def request_and_claim(
        self,
        attempt: EgressAttemptV1,
        safe_summary: dict[str, Any],
    ) -> EgressConsentReceiptV1:
        if not attempt.owner_key_hash or not attempt.session_id or not attempt.run_id:
            raise EgressConsentError("trusted owner required for model egress")
        can_queue = self._resolver is not None
        if callable(self._allow_queue):
            can_queue = can_queue and bool(self._allow_queue(attempt))
        if self._resolver is not None and not can_queue:
            raise EgressConsentError("egress consent adapter missing")
        arguments = closed_model_egress_arguments(attempt, safe_summary)
        request_id = model_egress_request_id(attempt)
        try:
            decision = self._queue.request_decision(
                MODEL_EGRESS_KIND,
                arguments,
                context="web",
                mode=ApprovalMode.MANUAL,
                session_id=attempt.session_id,
                run_id=attempt.run_id,
                owner_key_hash=attempt.owner_key_hash,
                queue_if_unhandled=can_queue,
                request_id=request_id,
            )
        except TypeError:
            raise EgressConsentError("egress consent request identity is unavailable") from None
        if decision.action is ApprovalDecisionType.PENDING:
            if self._resolver is None:
                raise EgressConsentError("egress consent adapter missing")
            resolved = await self._resolver(decision.request_id, safe_summary)
            if type(resolved) is not type(decision) and not hasattr(resolved, "action"):
                raise EgressConsentError("egress consent resolver is invalid")
            decision = resolved
        if decision.action is not ApprovalDecisionType.APPROVE:
            raise EgressConsentError("egress consent rejected")
        try:
            proof = self._queue.consume_approved_binding(
                decision.request_id,
                owner_key_hash=attempt.owner_key_hash,
                session_id=attempt.session_id,
                run_id=attempt.run_id,
                tool_name=MODEL_EGRESS_KIND,
                arguments_hash=ApprovalQueue.arguments_hash(arguments),
                require_manual=True,
            )
        except PermissionError as exc:
            raise EgressConsentError("egress consent claim failed") from exc
        if not proof.claimed_now or proof.action is not ApprovalDecisionType.APPROVE:
            raise EgressConsentError("egress consent claim failed")
        return EgressConsentReceiptV1(
            attempt_hash=attempt.attempt_hash,
            claim_receipt_hash=proof.journal_record_hash or proof.binding_hash,
            expires_at=time.time() + 60.0,
            nonce=proof.request_id,
        )

    async def request_and_claim_network(
        self,
        attempt: NetworkEgressAttemptV1,
        safe_summary: dict[str, Any],
    ) -> EgressConsentReceiptV1:
        if not isinstance(attempt, NetworkEgressAttemptV1):
            raise EgressConsentError("network egress attempt is invalid")
        if attempt.kind not in NETWORK_EGRESS_KINDS:
            raise EgressConsentError("network egress kind is invalid")
        if not attempt.owner_key_hash or not attempt.session_id or not attempt.run_id:
            raise EgressConsentError("trusted owner required for network egress")
        can_queue = self._resolver is not None
        if callable(self._allow_queue):
            can_queue = can_queue and bool(self._allow_queue(attempt))
        if self._resolver is not None and not can_queue:
            raise EgressConsentError("egress consent adapter missing")
        arguments = closed_network_egress_arguments(attempt, safe_summary)
        request_id = network_egress_request_id(attempt)
        try:
            decision = self._queue.request_decision(
                attempt.kind,
                arguments,
                context="web",
                mode=ApprovalMode.MANUAL,
                session_id=attempt.session_id,
                run_id=attempt.run_id,
                owner_key_hash=attempt.owner_key_hash,
                queue_if_unhandled=can_queue,
                request_id=request_id,
            )
        except TypeError:
            raise EgressConsentError("egress consent request identity is unavailable") from None
        if decision.action is ApprovalDecisionType.PENDING:
            if self._resolver is None:
                raise EgressConsentError("egress consent adapter missing")
            resolved = await self._resolver(decision.request_id, safe_summary)
            if type(resolved) is not type(decision) and not hasattr(resolved, "action"):
                raise EgressConsentError("egress consent resolver is invalid")
            decision = resolved
        if decision.action is not ApprovalDecisionType.APPROVE:
            raise EgressConsentError("egress consent rejected")
        try:
            proof = self._queue.consume_approved_binding(
                decision.request_id,
                owner_key_hash=attempt.owner_key_hash,
                session_id=attempt.session_id,
                run_id=attempt.run_id,
                tool_name=attempt.kind,
                arguments_hash=ApprovalQueue.arguments_hash(arguments),
                require_manual=True,
            )
        except PermissionError as exc:
            raise EgressConsentError("egress consent claim failed") from exc
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
