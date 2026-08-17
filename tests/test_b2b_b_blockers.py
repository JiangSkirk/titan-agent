"""B2B-B Grok BLOCKER oracles: attempt identity, lineage, privacy, DOM.

These tests hit real production entries. They must not touch a real Provider,
Keychain, ~/.js, ~/.js-work, or the network.
"""

from __future__ import annotations

import ast
import asyncio
import hashlib
import inspect
import json
import logging
import secrets
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from test_b2b_model_egress_core import (
    LOOPBACK_URL,
    SYNTH_PROMPT,
    _assert_no_transport,
    _chat_kwargs,
    _FakeBroker,
    _install_transport_spies,
    _router,
    _runtime_context,
    _SpyProvider,
)
from test_b2b_product_consent import (
    DIGEST_A,
    DIGEST_B,
    _add_loopback,
    _add_remote,
    _capture_attempts,
    _isolate_agent,
    _loopback_turn,
    _valid_provenance,
    _web_app,
    _web_client,
)

from js.echo.turn_context import reset_runtime_context, set_runtime_context
from js.echo.turn_runtime import run_echo_turn
from js.models.permit import ModelPermitError, ModelPermitIssuer
from js.models.providers import ChatMessage
from js.security.approvals import (
    ApprovalDecisionType,
    ApprovalEchoAuthority,
    ApprovalQueue,
)
from js.security.egress import (
    EgressAttemptV1,
    EgressConsentError,
    EgressIdentityV1,
    build_egress_attempt,
    consume_egress_receipt,
    freeze_egress_provenance,
    hash_egress_attempt,
    safe_egress_summary,
)

HOSTILE_ENDPOINT = (
    "https://user:SYNTH_ENDPOINT_SECRET@evil.example.test:8443/v1"
    "?api_key=SYNTH_QUERY_SECRET#fragment"
)
SYNTH_ENDPOINT_SECRET = "SYNTH_ENDPOINT_SECRET"
SYNTH_QUERY_SECRET = "SYNTH_QUERY_SECRET"
CAPSULE_RAW = "CAPSULE_RAW_NEVER_PERSIST_z8k earlier project timeline notes"
MEMORY_RAW = "MEMORY_RAW_NEVER_PERSIST_m4p preferred timezone is UTC"
PARENT_TURN = "parent-turn-known-7f3a"
ROOT_SENTINEL = "root"


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _product_id(agent: Any) -> str:
    authority = getattr(agent.approvals, "_echo_authority", None)
    return str(getattr(authority, "_product_id", None) or "js-agent")


def _identity(**overrides: Any) -> EgressIdentityV1:
    values = {
        "product_id": "js-agent",
        "channel": "api_chat",
        "owner_key_hash": "owner-a",
        "session_id": "session-a",
        "run_id": "run-a",
        "appshell_epoch": None,
    }
    values.update(overrides)
    return EgressIdentityV1(**values)


def _attempt(**overrides: Any) -> EgressAttemptV1:
    kwargs: dict[str, Any] = {
        "identity": _identity(),
        "attempt_kind": "initial",
        "provider_name": "remote",
        "provider_generation": "gen-1",
        "model": "m1",
        "endpoint_url": "https://api.example.test/v1",
        "messages": [ChatMessage(role="user", content=SYNTH_PROMPT)],
        "tools": None,
        "attachments": [],
        "provenance": _valid_provenance(),
        "temperature": 0.7,
        "effective_max_tokens": 16,
    }
    kwargs.update(overrides)
    return build_egress_attempt(**kwargs)


def _summary(attempt: EgressAttemptV1) -> dict[str, Any]:
    return safe_egress_summary(
        attempt,
        endpoint_url="https://api.example.test/v1",
        message_count=1,
        tool_count=0,
        provenance=_valid_provenance(),
    )


def _auto_resolver(queue: ApprovalQueue, owner: str = "owner-a") -> Any:
    async def resolver(request_id: str, _summary: Any) -> Any:
        return queue.decide(
            request_id,
            ApprovalDecisionType.APPROVE,
            owner_key_hash=owner,
        )

    return resolver


def _second_queue(agent: Any, path: Path) -> ApprovalQueue:
    queue = ApprovalQueue(ledger_path=path)
    queue.set_echo_authority(
        ApprovalEchoAuthority(agent.echo_safety_service, product_id=_product_id(agent))
    )
    return queue


def _wrap_claims(agent: Any) -> list[Any]:
    seen: list[Any] = []
    service = agent.echo_safety_service
    original = service.claim_approval_binding_once

    def wrapped(**kwargs: Any) -> Any:
        receipt = original(**kwargs)
        seen.append(receipt)
        return receipt

    service.claim_approval_binding_once = wrapped  # type: ignore[method-assign]
    return seen


def _capsule_source(provenance: dict[str, Any]) -> dict[str, Any]:
    sources = provenance.get("sources")
    assert isinstance(sources, list)
    matches = [item for item in sources if item.get("kind") == "cold_capsule"]
    assert matches, f"missing cold_capsule in {sources!r}"
    return matches[0]


def _memory_source(provenance: dict[str, Any]) -> dict[str, Any]:
    sources = provenance.get("sources")
    assert isinstance(sources, list)
    matches = [item for item in sources if item.get("kind") == "memory"]
    assert matches, f"missing memory in {sources!r}"
    return matches[0]


def _walk_log_blob(records: list[logging.LogRecord]) -> str:
    chunks: list[str] = []

    def walk(value: Any, depth: int = 0) -> None:
        if depth > 8:
            return
        if value is None:
            return
        if isinstance(value, str):
            chunks.append(value)
            return
        if isinstance(value, bytes):
            chunks.append(value.decode("utf-8", errors="replace"))
            return
        if isinstance(value, BaseException):
            walk(value.args, depth + 1)
            walk(getattr(value, "__dict__", {}), depth + 1)
            walk(value.__traceback__, depth + 1)
            return
        if isinstance(value, dict):
            for key, item in value.items():
                walk(str(key), depth + 1)
                walk(item, depth + 1)
            return
        if isinstance(value, (list, tuple, set)):
            for item in value:
                walk(item, depth + 1)
            return
        chunks.append(repr(value))

    for record in records:
        walk(record.msg)
        walk(record.args)
        walk(record.exc_info)
        walk(getattr(record, "__dict__", {}))
        walk(getattr(record, "exc_text", None))
    return "\n".join(chunks)


# ---------------------------------------------------------------------------
# A. Same-attempt exactly-once
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_same_attempt_two_brokers_claim_once_concurrently(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent = _isolate_agent(tmp_path)
    provider = _SpyProvider()
    _add_remote(agent, provider)
    spies = _install_transport_spies(monkeypatch)
    claims = _wrap_claims(agent)
    issued: list[Any] = []
    issuer = agent.router._permit_verifier
    assert issuer is not None
    original_issue = issuer.issue

    def _issue(**kwargs: Any) -> Any:
        permit = original_issue(**kwargs)
        issued.append(permit)
        return permit

    issuer.issue = _issue  # type: ignore[method-assign]

    attempt = _attempt()
    summary = _summary(attempt)
    queue_a = agent.approvals
    queue_b = _second_queue(agent, tmp_path / "echo_approvals_b.jsonl")
    from js.security.egress import ApprovalQueueEgressBroker

    broker_a = ApprovalQueueEgressBroker(queue_a, resolver=_auto_resolver(queue_a))
    broker_b = ApprovalQueueEgressBroker(queue_b, resolver=_auto_resolver(queue_b))
    barrier = asyncio.Barrier(2)
    results: list[Any] = []

    async def _claim(broker: Any) -> None:
        await barrier.wait()
        try:
            receipt = await broker.request_and_claim(attempt, summary)
            results.append(("ok", receipt))
        except Exception as exc:
            results.append(("err", exc))

    await asyncio.gather(_claim(broker_a), _claim(broker_b))
    winners = [item for item in results if item[0] == "ok"]
    losers = [item for item in results if item[0] == "err"]
    assert len(winners) == 1, f"same attempt must yield one receipt: {results!r}"
    assert len(losers) == 1
    receipt = winners[0][1]
    consume_egress_receipt(receipt)
    with pytest.raises(EgressConsentError):
        consume_egress_receipt(receipt)
    claimed_now = [item for item in claims if getattr(item, "claimed_now", False)]
    assert len(claimed_now) == 1
    lookup = agent.approvals._echo_authority.lookup_claim(
        tenant_id=attempt.owner_key_hash,
        session_id=attempt.session_id,
        request_id=receipt.nonce,
    )
    assert lookup is not None
    await agent.close()
    assert provider.calls == 0
    assert issued == []
    _assert_no_transport(spies)
    assert spies["pinned"] == []


@pytest.mark.asyncio
async def test_same_attempt_claim_cannot_replay_after_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent = _isolate_agent(tmp_path)
    provider = _SpyProvider()
    _add_remote(agent, provider)
    spies = _install_transport_spies(monkeypatch)
    attempt = _attempt()
    summary = _summary(attempt)
    from js.security.egress import ApprovalQueueEgressBroker

    first = ApprovalQueueEgressBroker(agent.approvals, resolver=_auto_resolver(agent.approvals))
    receipt = await first.request_and_claim(attempt, summary)
    consume_egress_receipt(receipt)

    restarted = _second_queue(agent, tmp_path / "echo_approvals_restart.jsonl")
    replay = ApprovalQueueEgressBroker(restarted, resolver=_auto_resolver(restarted))
    with pytest.raises((EgressConsentError, PermissionError)):
        await replay.request_and_claim(attempt, summary)
    await agent.close()
    assert provider.calls == 0
    _assert_no_transport(spies)


@pytest.mark.asyncio
async def test_distinct_identical_payload_attempts_are_not_content_deduped(
    tmp_path: Path,
) -> None:
    first = _attempt()
    second = _attempt()
    assert first.messages_digest == second.messages_digest
    assert first.attempt_id != second.attempt_id
    assert first.attempt_hash != second.attempt_hash
    agent = _isolate_agent(tmp_path)
    from js.security.egress import ApprovalQueueEgressBroker

    broker = ApprovalQueueEgressBroker(agent.approvals, resolver=_auto_resolver(agent.approvals))
    receipt_a = await broker.request_and_claim(first, _summary(first))
    receipt_b = await broker.request_and_claim(second, _summary(second))
    consume_egress_receipt(receipt_a)
    consume_egress_receipt(receipt_b)
    await agent.close()
    assert receipt_a.attempt_hash != receipt_b.attempt_hash


def test_build_egress_attempt_does_not_accept_caller_attempt_id() -> None:
    params = inspect.signature(build_egress_attempt).parameters
    assert "attempt_id" not in params
    assert "attempt_nonce" not in params


@pytest.mark.asyncio
async def test_invalid_attempt_id_is_rejected_before_claim(tmp_path: Path) -> None:
    agent = _isolate_agent(tmp_path)
    from js.security.egress import ApprovalQueueEgressBroker

    broker = ApprovalQueueEgressBroker(agent.approvals, resolver=_auto_resolver(agent.approvals))
    valid = _attempt()
    for bad_id in ("", "x", "A" * 32, "n" * 33, "../evil", "attempt id"):
        forged = replace(valid, attempt_id=bad_id)
        with pytest.raises(EgressConsentError):
            await broker.request_and_claim(forged, _summary(forged))
    await agent.close()


@pytest.mark.asyncio
async def test_attempt_object_copy_keeps_same_identity(tmp_path: Path) -> None:
    agent = _isolate_agent(tmp_path)
    from js.security.egress import ApprovalQueueEgressBroker

    original = _attempt()
    copied = replace(original)
    assert copied is not original
    assert copied.attempt_id == original.attempt_id
    queue_b = _second_queue(agent, tmp_path / "echo_approvals_copy.jsonl")
    broker_a = ApprovalQueueEgressBroker(agent.approvals, resolver=_auto_resolver(agent.approvals))
    broker_b = ApprovalQueueEgressBroker(queue_b, resolver=_auto_resolver(queue_b))
    first = await broker_a.request_and_claim(original, _summary(original))
    with pytest.raises((EgressConsentError, PermissionError)):
        await broker_b.request_and_claim(copied, _summary(copied))
    consume_egress_receipt(first)
    await agent.close()


@pytest.mark.asyncio
async def test_old_receipt_does_not_authorize_new_attempt(tmp_path: Path) -> None:
    provider = _SpyProvider()
    router, issuer = _router(tmp_path, provider)
    receipts: list[Any] = []

    class _ReuseBroker:
        receipt: Any = None

        async def request_and_claim(self, attempt: Any, safe_summary: Any) -> Any:
            del safe_summary
            from js.security.egress import EgressConsentReceiptV1

            if self.receipt is None:
                self.receipt = EgressConsentReceiptV1(
                    attempt_hash=attempt.attempt_hash,
                    claim_receipt_hash="claim-old",
                    expires_at=8_000_000_000.0,
                    nonce="nonce-old",
                )
            receipts.append(self.receipt)
            return self.receipt

    from test_b2b_model_egress_core import _bind_broker

    _bind_broker(router, _ReuseBroker())
    token = set_runtime_context(_runtime_context(tmp_path))
    try:
        await router.chat(
            [ChatMessage(role="user", content=SYNTH_PROMPT)],
            provenance=_valid_provenance(),
            **_chat_kwargs(issuer),
        )
        with pytest.raises(EgressConsentError):
            await router.chat(
                [ChatMessage(role="user", content=SYNTH_PROMPT)],
                provenance=_valid_provenance(),
                **_chat_kwargs(issuer),
            )
    finally:
        reset_runtime_context(token)
    assert provider.calls == 1
    assert len(receipts) >= 1


@pytest.mark.asyncio
async def test_permit_binds_attempt_id(tmp_path: Path) -> None:
    provider = _SpyProvider()
    router, issuer = _router(tmp_path, provider)
    issued: list[Any] = []
    original = issuer.issue

    def _issue(**kwargs: Any) -> Any:
        permit = original(**kwargs)
        issued.append(permit)
        return permit

    issuer.issue = _issue  # type: ignore[method-assign]
    seen: list[Any] = []
    from js.models import router as router_mod
    from js.security import egress as egress_mod

    real = egress_mod.build_egress_attempt

    def wrapped(**kwargs: Any) -> Any:
        attempt = real(**kwargs)
        seen.append(attempt)
        return attempt

    router_mod.build_egress_attempt = wrapped  # type: ignore[method-assign]
    egress_mod.build_egress_attempt = wrapped  # type: ignore[method-assign]
    from test_b2b_model_egress_core import _bind_broker

    _bind_broker(router, _FakeBroker(action="approve"))
    token = set_runtime_context(_runtime_context(tmp_path))
    try:
        await router.chat(
            [ChatMessage(role="user", content=SYNTH_PROMPT)],
            provenance=_valid_provenance(),
            **_chat_kwargs(issuer),
        )
    finally:
        reset_runtime_context(token)
    assert provider.calls == 1
    assert seen
    assert issued
    assert getattr(issued[0], "attempt_id", "") == seen[0].attempt_id
    assert issued[0].attempt_hash == seen[0].attempt_hash


def test_model_permit_mac_binds_attempt_id() -> None:
    """Black-box: MAC must bind attempt_id, not only the object field.

    Forged verify uses expected_attempt_id=B so a field compare cannot fail
    first. If ``ModelPermit._payload`` omits ``attempt_id``, this test must
    go red because the forged permit would verify.
    """

    issuer = ModelPermitIssuer(ttl_seconds=60.0)
    messages = [ChatMessage(role="user", content="permit-mac-bind")]
    tools = [{"type": "function", "function": {"name": "noop"}}]
    attempt_id_a = "a" * 32
    attempt_id_b = "b" * 32
    issue_kwargs: dict[str, Any] = {
        "provider_name": "remote",
        "model": "m1",
        "messages": messages,
        "tools": tools,
        "owner_key_hash": "owner-a",
        "session_id": "session-a",
        "run_id": "run-a",
        "attempt_hash": "1" * 64,
        "consent_receipt_hash": "2" * 64,
        "channel": "api_chat",
        "provider_generation": "gen-1",
        "endpoint_digest": "3" * 64,
        "attachments_digest": "4" * 64,
        "provenance_digest": "5" * 64,
        "temperature": 0.7,
        "effective_max_tokens": 16,
        "appshell_epoch": None,
    }
    original = issuer.issue(**issue_kwargs, attempt_id=attempt_id_a)
    assert original.attempt_id == attempt_id_a
    assert original.nonce
    spent_before = issuer.spent_nonce_count()

    forged = replace(original, attempt_id=attempt_id_b)
    assert forged.mac == original.mac
    assert forged.nonce == original.nonce
    assert forged.attempt_hash == original.attempt_hash
    assert forged.attempt_id == attempt_id_b
    assert forged.attempt_id != original.attempt_id

    def _verify(permit: Any, expected_attempt_id: str) -> None:
        issuer.verify_and_consume(
            permit,
            provider_name=permit.provider_name,
            model=permit.model,
            messages=messages,
            tools=tools,
            owner_key_hash=permit.owner_key_hash,
            session_id=permit.session_id,
            run_id=permit.run_id,
            attempt_hash=permit.attempt_hash,
            attempt_id=expected_attempt_id,
            consent_receipt_hash=permit.consent_receipt_hash,
            channel=permit.channel,
            provider_generation=permit.provider_generation,
            endpoint_digest=permit.endpoint_digest,
            attachments_digest=permit.attachments_digest,
            provenance_digest=permit.provenance_digest,
            temperature=permit.temperature,
            effective_max_tokens=permit.effective_max_tokens,
            appshell_epoch=permit.appshell_epoch,
        )

    with pytest.raises(ModelPermitError, match="MAC"):
        _verify(forged, attempt_id_b)
    assert issuer.spent_nonce_count() == spent_before

    _verify(original, attempt_id_a)
    assert issuer.spent_nonce_count() == spent_before + 1

    with pytest.raises(ModelPermitError, match="replay"):
        _verify(original, attempt_id_a)


@pytest.mark.asyncio
async def test_attempt_id_mismatch_with_hash_is_rejected(tmp_path: Path) -> None:
    valid = _attempt()
    mutated = replace(valid, attempt_id=secrets.token_hex(16))
    assert mutated.attempt_id != valid.attempt_id
    assert hash_egress_attempt(mutated) != valid.attempt_hash
    agent = _isolate_agent(tmp_path)
    from js.security.egress import ApprovalQueueEgressBroker

    broker = ApprovalQueueEgressBroker(agent.approvals, resolver=_auto_resolver(agent.approvals))
    receipt = await broker.request_and_claim(valid, _summary(valid))
    assert receipt.attempt_hash == valid.attempt_hash
    assert receipt.attempt_hash != mutated.attempt_hash
    await agent.close()


# ---------------------------------------------------------------------------
# B. ColdCapsule four-tuple + parent lineage
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_real_cold_capsule_preserves_identity_tuple_and_parent_lineage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent = _isolate_agent(tmp_path)
    provider = _add_loopback(agent)
    seen = _capture_attempts(monkeypatch)
    agent.settings.memory.capsule_enabled = True
    stored = agent.memory.store_capsule(
        "session-a",
        CAPSULE_RAW,
        owner_key_hash="owner-a",
        version=2,
        source_range="0-3",
        run_quality_check=False,
    )
    loaded = agent.memory.get_capsule("session-a", owner_key_hash="owner-a")
    assert loaded is not None
    assert CAPSULE_RAW in str(loaded.get("capsule_text") or stored.get("capsule_text") or "")
    parent = agent.echo_runtime.build_context(
        channel="api_chat",
        owner_key_hash="owner-a",
        session_id="session-a",
        run_id=PARENT_TURN,
        capabilities=(),
    )
    token = set_runtime_context(parent)
    try:
        state = await run_echo_turn(
            agent,
            SYNTH_PROMPT,
            channel="api_chat",
            owner_key_hash="owner-a",
            session_id="session-a",
            model="loop/m1",
        )
    finally:
        reset_runtime_context(token)
        await agent.close()
    assert state.status == "completed"
    assert provider.calls == 1
    provenance = seen[-1]["provenance"]
    source = _capsule_source(provenance)
    ids = tuple(source["source_record_ids"])
    hashes = tuple(source["source_hashes"])
    assert ids
    assert hashes
    assert len(ids) == len(hashes)
    assert source["source_set_hash"]
    assert source["capsule_digest"] == _sha(str(loaded.get("capsule_text") or CAPSULE_RAW))
    assert provenance["parent_turn_id"] == PARENT_TURN
    assert provenance["parent_turn_id"] != provenance["run_id"]
    blob = json.dumps(provenance)
    assert CAPSULE_RAW not in blob
    summary = safe_egress_summary(
        _attempt(provenance=provenance),
        endpoint_url=LOOPBACK_URL,
        message_count=2,
        tool_count=0,
        provenance=provenance,
    )
    assert CAPSULE_RAW not in json.dumps(summary)


@pytest.mark.asyncio
async def test_cold_capsule_malformed_tuple_is_rejected_before_consent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    provider = _SpyProvider(base_url=LOOPBACK_URL)
    router, issuer = _router(tmp_path, provider)
    spies = _install_transport_spies(monkeypatch)
    token = set_runtime_context(_runtime_context(tmp_path))
    base_source = {
        "kind": "cold_capsule",
        "record_id": "capsule:1",
        "content_digest": DIGEST_A,
        "parent_turn_id": PARENT_TURN,
        "parent_run_id": "run-a",
        "parent_attempt_id": "",
        "source_record_ids": ["mem:rec-1", "mem:rec-2"],
        "source_hashes": [DIGEST_A, DIGEST_B],
        "source_set_hash": DIGEST_A,
        "capsule_digest": DIGEST_B,
    }
    cases = [
        {**base_source, "source_record_ids": ["mem:rec-1"]},
        {**base_source, "source_hashes": [DIGEST_A]},
        {**base_source, "source_record_ids": ["mem:rec-1", "mem:rec-1"],
         "source_hashes": [DIGEST_A, DIGEST_B]},
        {**base_source, "capsule_digest": "not-a-digest"},
        {k: v for k, v in base_source.items() if k != "source_record_ids"},
        {k: v for k, v in base_source.items() if k != "source_hashes"},
        {k: v for k, v in base_source.items() if k != "source_set_hash"},
        {k: v for k, v in base_source.items() if k != "capsule_digest"},
    ]
    try:
        for source in cases:
            payload = _valid_provenance(sources=[source])
            with pytest.raises(EgressConsentError):
                freeze_egress_provenance(payload)
            with pytest.raises(EgressConsentError):
                await router.chat(
                    [ChatMessage(role="user", content=SYNTH_PROMPT)],
                    provenance=payload,
                    **_chat_kwargs(issuer, model="remote/m1"),
                )
    finally:
        reset_runtime_context(token)
    assert provider.calls == 0
    _assert_no_transport(spies)


def test_compression_cold_capsule_has_no_model_hop() -> None:
    root = Path(__file__).resolve().parents[1]
    turn_loop = (root / "js" / "echo" / "turn_loop.py").read_text(encoding="utf-8")
    agent_init = (root / "js" / "agent" / "__init__.py").read_text(encoding="utf-8")
    compression = (root / "js" / "memory" / "compression.py").read_text(encoding="utf-8")
    assert "memory.layers.contracts" not in turn_loop
    assert "ColdCapsule" not in turn_loop
    assert "from js.memory.layers.contracts import ColdCapsule" not in agent_init
    tree = ast.parse(compression)
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
    assert "js.echo.turn_runtime" not in imported
    assert "js.models.router" not in imported
    assert "js.echo.effect_interpreter" not in imported
    assert "run_echo_turn" not in compression
    assert "router.chat" not in compression


# ---------------------------------------------------------------------------
# C. Real memory retrieval
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_real_memory_context_preserves_source_lineage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent = _isolate_agent(tmp_path)
    provider = _add_loopback(agent)
    seen = _capture_attempts(monkeypatch)
    agent.memory.store_working(
        "session-a",
        "timezone",
        MEMORY_RAW,
        category="preference",
        importance=8,
        owner_key_hash="owner-a",
    )
    context_string = agent.memory.get_context_string(
        query=SYNTH_PROMPT,
        session_id="session-a",
        owner_key_hash="owner-a",
    )
    assert MEMORY_RAW[:40] in context_string or "timezone" in context_string
    parent = agent.echo_runtime.build_context(
        channel="api_chat",
        owner_key_hash="owner-a",
        session_id="session-a",
        run_id=PARENT_TURN,
        capabilities=(),
    )
    token = set_runtime_context(parent)
    try:
        state = await run_echo_turn(
            agent,
            SYNTH_PROMPT,
            channel="api_chat",
            owner_key_hash="owner-a",
            session_id="session-a",
            model="loop/m1",
        )
    finally:
        reset_runtime_context(token)
        await agent.close()
    assert state.status == "completed"
    assert provider.calls == 1
    provenance = seen[-1]["provenance"]
    memory = _memory_source(provenance)
    assert memory.get("source_record_ids") or memory.get("record_id")
    assert memory.get("content_digest") or memory.get("source_hashes")
    assert provenance["parent_turn_id"] == PARENT_TURN
    assert MEMORY_RAW not in json.dumps(provenance)
    assert MEMORY_RAW not in json.dumps(
        safe_egress_summary(
            _attempt(provenance=provenance),
            endpoint_url=LOOPBACK_URL,
            message_count=2,
            tool_count=0,
            provenance=provenance,
        )
    )


@pytest.mark.asyncio
async def test_mixed_capsule_and_memory_lineage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent = _isolate_agent(tmp_path)
    _add_loopback(agent)
    seen = _capture_attempts(monkeypatch)
    agent.settings.memory.capsule_enabled = True
    agent.memory.store_capsule(
        "session-a",
        CAPSULE_RAW,
        owner_key_hash="owner-a",
        version=1,
        source_range="0-1",
        run_quality_check=False,
    )
    agent.memory.store_working(
        "session-a",
        "timezone",
        MEMORY_RAW,
        owner_key_hash="owner-a",
    )
    context_string = agent.memory.get_context_string(
        query=SYNTH_PROMPT,
        session_id="session-a",
        owner_key_hash="owner-a",
    )
    assert "timezone" in context_string or MEMORY_RAW[:20] in context_string
    state = await _loopback_turn(agent, SYNTH_PROMPT)
    await agent.close()
    assert state.status == "completed"
    kinds = {item["kind"] for item in seen[-1]["provenance"]["sources"]}
    assert {"cold_capsule", "memory", "direct_user"} <= kinds
    blob = json.dumps(seen[-1]["provenance"])
    assert CAPSULE_RAW not in blob
    assert MEMORY_RAW not in blob


# ---------------------------------------------------------------------------
# D. Endpoint sanitization
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_model_egress_pending_strips_endpoint_userinfo_query_fragment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    agent = _isolate_agent(tmp_path)
    provider = _SpyProvider(base_url=HOSTILE_ENDPOINT)
    _add_remote(agent, provider)
    spies = _install_transport_spies(monkeypatch)
    caplog.set_level(logging.DEBUG)
    app, key, _owner = _web_app(agent)
    forbidden = (
        SYNTH_ENDPOINT_SECRET,
        SYNTH_QUERY_SECRET,
        "user:SYNTH_ENDPOINT_SECRET",
        "/v1",
        "api_key=",
        "#fragment",
        HOSTILE_ENDPOINT,
    )
    async with await _web_client(app, key) as client:
        chat_task = asyncio.create_task(
            client.post(
                "/api/chat",
                json={
                    "message": SYNTH_PROMPT,
                    "session_id": "web-hostile",
                    "model": "remote/m1",
                },
            )
        )
        pending = None
        for _ in range(80):
            await asyncio.sleep(0.05)
            items = (await client.get("/api/echo/approvals")).json()["approvals"]
            found = [item for item in items if item.get("tool_name") == "model_egress"]
            if found:
                pending = found[0]
                break
        assert pending is not None
        sinks = [
            pending,
            pending.get("safe_summary"),
            pending.get("arguments"),
            _walk_log_blob(list(caplog.records)),
        ]
        blob = json.dumps(sinks, default=str)
        assert "evil.example.test:8443" in blob
        for needle in forbidden:
            assert needle not in blob
        chat_task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await chat_task
    await agent.close()
    assert provider.calls == 0
    _assert_no_transport(spies)


@pytest.mark.asyncio
async def test_root_turn_uses_explicit_root_parent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent = _isolate_agent(tmp_path)
    _add_loopback(agent)
    seen = _capture_attempts(monkeypatch)
    state = await _loopback_turn(agent, SYNTH_PROMPT, session="root-session")
    await agent.close()
    assert state.status == "completed"
    provenance = seen[-1]["provenance"]
    assert provenance["parent_turn_id"] == ROOT_SENTINEL
    assert provenance["parent_turn_id"] != provenance["run_id"]
    assert provenance["parent_turn_id"] != SYNTH_PROMPT


@pytest.mark.asyncio
async def test_fleet_worker_keeps_parent_lineage_when_remote_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent = _isolate_agent(tmp_path)
    provider = _SpyProvider()
    _add_remote(agent, provider)
    spies = _install_transport_spies(monkeypatch)
    seen = _capture_attempts(monkeypatch)
    parent = agent.echo_runtime.build_context(
        channel="api_chat",
        owner_key_hash="owner-a",
        session_id="fleet-session",
        run_id=PARENT_TURN,
        capabilities=(),
    )
    token = set_runtime_context(parent)
    try:
        state = await run_echo_turn(
            agent,
            SYNTH_PROMPT,
            channel="fleet_worker",
            owner_key_hash="owner-a",
            session_id="fleet-session",
            model="remote/m1",
        )
    finally:
        reset_runtime_context(token)
        await agent.close()
    assert state.status == "error"
    assert provider.calls == 0
    _assert_no_transport(spies)
    assert seen, "fail-closed fleet still constructs an attempt/provenance"
    provenance = seen[-1]["provenance"]
    assert provenance["parent_turn_id"] == PARENT_TURN
    assert provenance["parent_turn_id"] != provenance["run_id"]
    kinds = {item["kind"] for item in provenance["sources"]}
    assert "fleet_worker" in kinds


# ---------------------------------------------------------------------------
# G. Cron raw-prompt log
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cron_logs_never_include_raw_prompt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent = _isolate_agent(tmp_path)
    provider = _SpyProvider()
    _add_remote(agent, provider)
    spies = _install_transport_spies(monkeypatch)
    from js.cron.engine import ScheduledJob
    from js.daemon import core as daemon_core
    from js.daemon.core import JSDaemon

    prompt = "CRON_" + secrets.token_hex(32)
    assert 8 <= len(prompt) <= 512
    captured_logs: list[str] = []

    def _capture(method: str) -> Any:
        original = getattr(daemon_core.logger, method)

        def wrapped(msg: Any, *args: Any, **kwargs: Any) -> Any:
            captured_logs.append(str(msg))
            captured_logs.append(repr(args))
            captured_logs.append(repr(kwargs))
            return original(msg, *args, **kwargs)

        return wrapped

    for method in ("info", "warning", "error", "debug", "exception"):
        if hasattr(daemon_core.logger, method):
            monkeypatch.setattr(daemon_core.logger, method, _capture(method))
    records: list[logging.LogRecord] = []

    class _Handler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    handler = _Handler()
    std_logger = logging.getLogger("js.daemon")
    std_logger.addHandler(handler)
    std_logger.setLevel(logging.DEBUG)
    daemon = JSDaemon(agent.settings, agent=agent)
    job = ScheduledJob(
        id="job-privacy",
        name="chat",
        cron_expr="* * * * *",
        task_type="chat",
        payload={"prompt": prompt},
        owner_key_hash="owner-a",
        session_id="cron-session",
    )
    try:
        with pytest.raises((RuntimeError, PermissionError, EgressConsentError, ValueError)):
            await daemon._cb_chat(job)
    finally:
        std_logger.removeHandler(handler)
        await agent.close()
    blob = _walk_log_blob(records) + "\n".join(captured_logs)
    assert prompt not in blob
    assert prompt[:8] not in blob
    assert prompt[-8:] not in blob
    assert provider.calls == 0
    _assert_no_transport(spies)


def test_freeze_rejects_bool_and_list_subclass_for_capsule_fields() -> None:
    class _List(list):
        pass

    with pytest.raises(EgressConsentError):
        freeze_egress_provenance(
            _valid_provenance(
                sources=[
                    {
                        "kind": "cold_capsule",
                        "record_id": "capsule:1",
                        "content_digest": DIGEST_A,
                        "parent_turn_id": PARENT_TURN,
                        "parent_run_id": "run-a",
                        "parent_attempt_id": "",
                        "source_record_ids": _List(["mem:1"]),
                        "source_hashes": [DIGEST_A],
                        "source_set_hash": DIGEST_A,
                        "capsule_digest": DIGEST_B,
                    }
                ]
            )
        )
