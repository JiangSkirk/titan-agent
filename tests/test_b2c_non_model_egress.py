"""B2B-C: non-model network egress consent (web search, browser, generic).

Synthetic data only. No real Provider, Keychain, ~/.js, or network.
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import shutil
import subprocess
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest

from js.echo.turn_context import (
    RuntimeContext,
    reset_runtime_context,
    set_runtime_context,
)
from js.models.permit import ModelPermitError
from js.security.approvals import (
    ApprovalDecisionType,
    ApprovalMode,
    ApprovalQueue,
)
from js.security.net_guard import is_canonical_loopback_literal

SYNTH_QUERY = "SYNTH_B2C_QUERY_NEVER_PERSIST_q9z"
SYNTH_PATH = "/tmp/synth_b2c_secret_file.txt"
SYNTH_API_KEY = "sk-synth-b2c-never-log"
SYNTH_BODY = "raw_b2c_body_secret_xyz"
REMOTE_SEARCH = "https://html.duckduckgo.com/html/"
LOOPBACK_URL = "http://127.0.0.1:9/v1"
PRIVACY_NEEDLES = (SYNTH_QUERY, SYNTH_PATH, SYNTH_API_KEY, SYNTH_BODY)


def _egress_mod() -> Any:
    try:
        from js.security import egress as module
    except ImportError:
        pytest.fail("js.security.egress is required for B2B-C")
    return module


def _require(module: Any, name: str) -> Any:
    value = getattr(module, name, None)
    if value is None:
        pytest.fail(f"{name} is required for B2B-C")
    return value


def _identity(module: Any, **overrides: Any) -> Any:
    cls = _require(module, "EgressIdentityV1")
    values = {
        "product_id": "js-agent",
        "channel": "search",
        "owner_key_hash": "owner-a",
        "session_id": "session-a",
        "run_id": "run-a",
        "appshell_epoch": "1",
    }
    values.update(overrides)
    return cls(**values)


def _runtime_context(tmp_path: Path, **overrides: Any) -> RuntimeContext:
    values: dict[str, Any] = {
        "product_id": "js-agent",
        "channel": "search",
        "owner_key_hash": "owner-a",
        "session_id": "session-a",
        "run_id": "run-a",
        "role": "user",
        "profile": "default",
        "capabilities": ("web_search", "browser_fetch", "control_provider_discover"),
        "workspace": tmp_path,
        "state_dir": tmp_path,
    }
    values.update(overrides)
    return RuntimeContext(**values)


class SideEffects:
    def __init__(self) -> None:
        self.order: list[str] = []
        self.dns = 0
        self.client = 0
        self.http = 0
        self.sdk = 0

    def resolve(self, url: str, **_kwargs: Any) -> list[str]:
        self.dns += 1
        self.order.append("dns")
        return ["203.0.113.10"]

    def resolve_provider(self, url: str, **_kwargs: Any) -> list[str]:
        self.dns += 1
        self.order.append("dns")
        return ["203.0.113.10"]

    def client_cls(self, *args: Any, **kwargs: Any) -> Any:
        self.client += 1
        self.order.append("client")
        client = AsyncMock()
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=None)
        response = httpx.Response(
            200,
            json={"data": [], "models": [], "results": []},
            text="<html></html>",
            request=httpx.Request("GET", "https://example.test/"),
        )
        client.get = AsyncMock(return_value=response)
        client.post = AsyncMock(return_value=response)

        class _Stream:
            async def __aenter__(self) -> httpx.Response:
                return response

            async def __aexit__(self, *args: Any) -> None:
                return None

        client.stream = lambda *args, **kwargs: _Stream()
        return client


class FakeNetworkBroker:
    def __init__(
        self,
        *,
        action: str = "approve",
        hang: bool = False,
        claimed_now: bool = True,
        mutate_after: dict[str, Any] | None = None,
        source_dict: dict[str, Any] | None = None,
    ) -> None:
        self.action = action
        self.hang = hang
        self.claimed_now = claimed_now
        self.mutate_after = mutate_after
        self.source_dict = source_dict
        self.claim_count = 0
        self.attempts: list[Any] = []
        self.summaries: list[dict[str, Any]] = []
        self._hang_event = asyncio.Event()

    async def request_and_claim(self, attempt: Any, safe_summary: dict[str, Any]) -> Any:
        return await self.request_and_claim_network(attempt, safe_summary)

    async def request_and_claim_network(self, attempt: Any, safe_summary: dict[str, Any]) -> Any:
        module = _egress_mod()
        if self.hang:
            await self._hang_event.wait()
        self.attempts.append(attempt)
        self.summaries.append(dict(safe_summary))
        self.claim_count += 1
        if self.mutate_after and self.source_dict is not None:
            self.source_dict.update(self.mutate_after)
        if self.action != "approve":
            raise module.EgressConsentError("egress consent rejected")
        receipt_cls = _require(module, "EgressConsentReceiptV1")
        import time

        return receipt_cls(
            attempt_hash=attempt.attempt_hash,
            claim_receipt_hash="sha256:" + "ab" * 32,
            expires_at=time.time() + 60.0,
            nonce=f"nonce-{self.claim_count}-{attempt.attempt_id}",
        )


@contextmanager
def network_runtime(
    tmp_path: Path,
    *,
    broker: Any | None = None,
    issuer: Any | None = None,
    **context_overrides: Any,
) -> Iterator[tuple[Any, Any, Any]]:
    module = _egress_mod()
    set_rt = _require(module, "set_network_egress_runtime")
    reset_rt = _require(module, "reset_network_egress_runtime")
    permit_cls = getattr(module, "NetworkEgressPermitIssuer", None)
    if permit_cls is None:
        from js.models.permit import NetworkEgressPermitIssuer

        permit_cls = NetworkEgressPermitIssuer
    ctx_token = set_runtime_context(_runtime_context(tmp_path, **context_overrides))
    bound_broker = broker
    bound_issuer = issuer or permit_cls()
    net_token = set_rt(bound_broker, bound_issuer)
    try:
        yield module, bound_broker, bound_issuer
    finally:
        reset_rt(net_token)
        reset_runtime_context(ctx_token)


@contextmanager
def adjacent_network_consent(tmp_path: Path) -> Iterator[None]:
    """Auto-approve network egress so adjacent B1B tests still reach transport."""
    with network_runtime(tmp_path, broker=FakeNetworkBroker(), channel="search"):
        yield


def _patch_search_spies(monkeypatch: pytest.MonkeyPatch, effects: SideEffects) -> None:
    monkeypatch.setattr("js.search.engines.resolve_and_validate", effects.resolve)
    monkeypatch.setattr("js.search.engines.asyncio.sleep", AsyncMock())
    monkeypatch.setattr("httpx.AsyncClient", effects.client_cls)


def _assert_zero_network(effects: SideEffects) -> None:
    assert effects.dns == 0
    assert effects.client == 0
    assert effects.http == 0
    assert effects.sdk == 0
    assert "dns" not in effects.order
    assert "client" not in effects.order


def _privacy_clean(blob: str) -> None:
    for needle in PRIVACY_NEEDLES:
        assert needle not in blob


async def _search_once(query: str = SYNTH_QUERY) -> Any:
    from js.search.engines import DuckDuckGoEngine

    engine = DuckDuckGoEngine(timeout=1.0)
    try:
        return await engine._search_via_lite(query, 1)
    finally:
        await engine.close()


@pytest.mark.asyncio
async def test_01_headless_query_is_not_sent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    effects = SideEffects()
    _patch_search_spies(monkeypatch, effects)
    with (
        network_runtime(tmp_path, broker=None, channel="cron"),
        pytest.raises((PermissionError, RuntimeError, ModelPermitError)),
    ):
        await _search_once()
    _assert_zero_network(effects)


@pytest.mark.asyncio
@pytest.mark.parametrize("action", ["reject", "timeout", "cancel"])
async def test_02_reject_timeout_cancel_zero_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, action: str
) -> None:
    effects = SideEffects()
    _patch_search_spies(monkeypatch, effects)
    broker = FakeNetworkBroker(
        action="approve" if action in {"timeout", "cancel"} else "reject",
        hang=action == "timeout",
    )
    cancel = asyncio.Event()
    if action == "cancel":
        cancel.set()
    with network_runtime(tmp_path, broker=broker, cancel_token=cancel):
        if action == "timeout":
            with pytest.raises((PermissionError, RuntimeError, asyncio.TimeoutError, asyncio.CancelledError)):
                await asyncio.wait_for(_search_once(), timeout=0.05)
        else:
            with pytest.raises((PermissionError, RuntimeError, asyncio.CancelledError)):
                await _search_once()
    _assert_zero_network(effects)


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["owner_key_hash", "session_id", "run_id", "channel", "appshell_epoch"])
async def test_03_wrong_identity_zero_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str
) -> None:
    module = _egress_mod()
    effects = SideEffects()
    _patch_search_spies(monkeypatch, effects)
    broker = FakeNetworkBroker()
    issuer = None
    from js.models.permit import NetworkEgressPermitIssuer

    issuer = NetworkEgressPermitIssuer()
    with network_runtime(tmp_path, broker=broker, issuer=issuer):
        original = _require(module, "authorize_network_egress")

        async def wrong(*args: Any, **kwargs: Any) -> Any:
            auth = await original(*args, **kwargs)
            attempt = getattr(auth, "attempt", auth)
            object.__setattr__(attempt, field if field != "appshell_epoch" else "appshell_epoch", "mutated")
            return auth

        monkeypatch.setattr(module, "authorize_network_egress", wrong)
        with pytest.raises((PermissionError, RuntimeError, AttributeError, TypeError, module.EgressConsentError)):
            await _search_once()
    _assert_zero_network(effects)


@pytest.mark.asyncio
async def test_04_consent_then_mutate_query_zero_http(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    effects = SideEffects()
    _patch_search_spies(monkeypatch, effects)
    payload = {"q": SYNTH_QUERY}
    broker = FakeNetworkBroker(mutate_after={"q": "MUTATED_QUERY"}, source_dict=payload)
    with network_runtime(tmp_path, broker=broker):
        from js.search.engines import _PinnedSearchClient

        client = _PinnedSearchClient(timeout=1.0)
        with pytest.raises((PermissionError, RuntimeError)):
            await client.get(REMOTE_SEARCH, params=payload)
    assert effects.dns == 0 or effects.http == 0
    _assert_zero_network(effects)


@pytest.mark.asyncio
async def test_05_consent_then_mutate_endpoint_zero_http(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    effects = SideEffects()
    _patch_search_spies(monkeypatch, effects)
    broker = FakeNetworkBroker()
    with network_runtime(tmp_path, broker=broker):
        module = _egress_mod()
        original = _require(module, "authorize_network_egress")

        async def swap_endpoint(*args: Any, **kwargs: Any) -> Any:
            auth = await original(*args, **kwargs)
            snapshot = getattr(auth, "snapshot", None)
            if snapshot is not None and hasattr(snapshot, "endpoint_url"):
                object.__setattr__(snapshot, "endpoint_url", "https://evil.example.test/search")
            return auth

        monkeypatch.setattr(module, "authorize_network_egress", swap_endpoint)
        with pytest.raises((PermissionError, RuntimeError, AttributeError, TypeError)):
            await _search_once()
    _assert_zero_network(effects)


@pytest.mark.asyncio
async def test_06_retry_does_not_reuse_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    effects = SideEffects()
    _patch_search_spies(monkeypatch, effects)
    broker = FakeNetworkBroker()
    with network_runtime(tmp_path, broker=broker):
        await _search_once()
        first = broker.claim_count
        await _search_once()
        assert broker.claim_count >= first + 1
        assert broker.attempts[0].attempt_id != broker.attempts[1].attempt_id


@pytest.mark.asyncio
async def test_07_receipt_replay_rejected(tmp_path: Path) -> None:
    module = _egress_mod()
    consume = _require(module, "consume_egress_receipt")
    receipt_cls = _require(module, "EgressConsentReceiptV1")
    import time

    receipt = receipt_cls(
        attempt_hash="a" * 64,
        claim_receipt_hash="b" * 64,
        expires_at=time.time() + 60,
        nonce="n1",
    )
    consume(receipt)
    with pytest.raises(module.EgressConsentError):
        consume(receipt)


@pytest.mark.asyncio
async def test_08_redirect_new_host_not_followed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    effects = SideEffects()
    monkeypatch.setattr("js.search.engines.resolve_and_validate", effects.resolve)
    monkeypatch.setattr("js.search.engines.asyncio.sleep", AsyncMock())

    class RedirectClient:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            effects.client += 1
            self._kwargs = kwargs
            assert kwargs.get("follow_redirects") is False

        async def __aenter__(self) -> RedirectClient:
            return self

        async def __aexit__(self, *args: Any) -> None:
            return None

        async def get(self, url: str, **kwargs: Any) -> httpx.Response:
            effects.http += 1
            request = httpx.Request("GET", url)
            return httpx.Response(
                302,
                headers={"Location": "https://evil.example.test/steal"},
                request=request,
            )

        def stream(self, method: str, url: str, **kwargs: Any) -> Any:
            async def _enter() -> httpx.Response:
                return await self.get(url, **kwargs)

            class _CM:
                async def __aenter__(self) -> httpx.Response:
                    return await _enter()

                async def __aexit__(self, *args: Any) -> None:
                    return None

            return _CM()

    monkeypatch.setattr("httpx.AsyncClient", RedirectClient)
    broker = FakeNetworkBroker()
    with network_runtime(tmp_path, broker=broker):
        from js.search.engines import DuckDuckGoEngine

        engine = DuckDuckGoEngine(timeout=1.0)
        try:
            with pytest.raises((PermissionError, RuntimeError)):
                await engine._search_via_lite(SYNTH_QUERY, 1)
        finally:
            await engine.close()
    assert effects.client >= 1
    assert effects.dns <= 1
    source = Path(__file__).resolve().parents[1].joinpath("js/search/engines.py").read_text(encoding="utf-8")
    pinned_block = source.split("class _PinnedSearchClient", 1)[1].split("class SearchEngine", 1)[0]
    assert "follow_redirects=False" in pinned_block
    assert "follow_redirects=True" not in pinned_block


@pytest.mark.asyncio
async def test_09_raw_query_stays_out_of_ledger_and_logs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    effects = SideEffects()
    _patch_search_spies(monkeypatch, effects)
    caplog.set_level(logging.DEBUG)
    recorded: list[str] = []

    def capture_log(msg: Any, *args: Any, **kwargs: Any) -> None:
        recorded.append(f"{msg}|{args}|{kwargs}")

    monkeypatch.setattr("js.search.engines.logger.error", capture_log)
    monkeypatch.setattr("js.search.engines.logger.warning", capture_log)
    monkeypatch.setattr("js.search.engines.logger.info", capture_log)
    monkeypatch.setattr("js.search.engines.logger.debug", capture_log)
    broker = FakeNetworkBroker()
    with network_runtime(tmp_path, broker=broker):
        try:
            await _search_once()
        except (PermissionError, RuntimeError):
            pass
    blob = caplog.text + (tmp_path / "a.jsonl").read_text(encoding="utf-8") if (tmp_path / "a.jsonl").exists() else caplog.text
    _privacy_clean(blob)
    for summary in broker.summaries:
        dumped = json.dumps(summary)
        _privacy_clean(dumped)
    with network_runtime(tmp_path, broker=None, channel="cron"):
        try:
            await _search_once()
        except (PermissionError, RuntimeError):
            pass
    _privacy_clean(caplog.text)
    _privacy_clean("".join(recorded))


@pytest.mark.asyncio
async def test_authorize_consumes_receipt_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _egress_mod()
    consume = _require(module, "consume_egress_receipt")
    calls: list[Any] = []

    def wrapped(receipt: Any) -> None:
        calls.append(receipt)
        consume(receipt)

    monkeypatch.setattr(module, "consume_egress_receipt", wrapped)
    kind = _require(module, "NetworkEgressKind")
    authorize = _require(module, "authorize_network_egress")
    with network_runtime(tmp_path, broker=FakeNetworkBroker()):
        await authorize(
            kind=kind.WEB_SEARCH,
            target_identity="ddg",
            endpoint_url=REMOTE_SEARCH,
            method="GET",
            payload={"q": "once"},
            provenance={
                "schema": "network-egress-provenance-v1",
                "kind": "web_search_egress",
                "source": "web_search",
                "tool_name": "web_search",
            },
            credential_generation="none",
        )
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_04_send_uses_frozen_snapshot_not_live_dict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _egress_mod()
    effects = SideEffects()
    captured: dict[str, Any] = {}

    class CaptureClient:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            effects.client += 1

        async def __aenter__(self) -> CaptureClient:
            return self

        async def __aexit__(self, *args: Any) -> None:
            return None

        async def get(self, url: str, **kwargs: Any) -> httpx.Response:
            captured["params"] = kwargs.get("params")
            effects.http += 1
            return httpx.Response(200, text="<html></html>", request=httpx.Request("GET", url))

        def stream(self, method: str, url: str, **kwargs: Any) -> Any:
            async def _enter() -> httpx.Response:
                return await self.get(url, **kwargs)

            class _CM:
                async def __aenter__(self) -> httpx.Response:
                    return await _enter()

                async def __aexit__(self, *args: Any) -> None:
                    return None

            return _CM()

    payload = {"q": SYNTH_QUERY}
    original = _require(module, "authorize_network_egress")
    original_digest = _require(module, "digest_jsonable")
    frozen_digest: dict[str, str] = {}

    async def after_auth(*args: Any, **kwargs: Any) -> Any:
        auth = await original(*args, **kwargs)
        frozen_digest["value"] = auth.attempt.payload_digest
        payload["q"] = "MUTATED_AFTER_CONSENT"
        return auth

    monkeypatch.setattr(module, "authorize_network_egress", after_auth)
    monkeypatch.setattr(
        module,
        "digest_jsonable",
        lambda value: frozen_digest["value"] if frozen_digest else original_digest(value),
    )
    monkeypatch.setattr("js.search.engines.resolve_and_validate", effects.resolve)
    monkeypatch.setattr("js.search.engines.asyncio.sleep", AsyncMock())
    monkeypatch.setattr("httpx.AsyncClient", CaptureClient)
    broker = FakeNetworkBroker()
    with network_runtime(tmp_path, broker=broker):
        from js.search.engines import _PinnedSearchClient

        client = _PinnedSearchClient(timeout=1.0)
        try:
            await client.get(REMOTE_SEARCH, params=payload)
        except (PermissionError, RuntimeError):
            pass
    if captured.get("params") is not None:
        assert captured["params"] == {"q": SYNTH_QUERY} or captured["params"]["q"] != "MUTATED_AFTER_CONSENT"


@pytest.mark.asyncio
async def test_10_canonical_loopback_skips_human_but_uses_permit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _egress_mod()
    assert is_canonical_loopback_literal("127.0.0.1")
    effects = SideEffects()
    monkeypatch.setattr(
        "js.security.net_guard.resolve_and_validate_provider_endpoint",
        effects.resolve_provider,
    )
    monkeypatch.setattr("httpx.AsyncClient", effects.client_cls)
    authorize = _require(module, "authorize_network_egress")
    kind = _require(module, "NetworkEgressKind")
    with network_runtime(tmp_path, broker=None, channel="search"):
        auth = await authorize(
            kind=kind.PROVIDER_DISCOVERY,
            target_identity="local",
            endpoint_url=LOOPBACK_URL,
            method="GET",
            payload={"path": "/models"},
            provenance={
                "schema": "network-egress-provenance-v1",
                "kind": "provider_discovery_egress",
                "source": "provider_discovery",
                "tool_name": "control_provider_discover",
            },
            credential_generation="none",
        )
        assert getattr(auth, "permit", None) is not None
        assert getattr(auth.receipt, "claim_receipt_hash", "") in {
            _require(module, "LOOPBACK_EXEMPTION_RECEIPT"),
            getattr(auth.receipt, "claim_receipt_hash", ""),
        }


@pytest.mark.asyncio
async def test_31_two_brokers_one_fresh_claim(tmp_path: Path) -> None:
    module = _egress_mod()
    build = _require(module, "build_network_egress_attempt")
    kind = _require(module, "NetworkEgressKind")
    identity = _identity(module)
    attempt = build(
        identity=identity,
        kind=kind.WEB_SEARCH,
        target_identity="ddg",
        endpoint_url=REMOTE_SEARCH,
        method="GET",
        payload={"q": "x"},
        provenance={
            "schema": "network-egress-provenance-v1",
            "kind": "web_search_egress",
            "source": "web_search",
            "tool_name": "web_search",
        },
        credential_generation="none",
    )
    queue = ApprovalQueue(default_mode=ApprovalMode.MANUAL, ledger_path=tmp_path / "a.jsonl")
    from js.echo.ledger.service import EchoSafetyService
    from js.security.approvals import wire_echo_approval_authority

    echo = EchoSafetyService(state_dir=tmp_path / "echo")
    queue.set_echo_authority(wire_echo_approval_authority(echo, product_id="js-agent"))
    broker_cls = _require(module, "ApprovalQueueEgressBroker")

    async def resolve(request_id: str, safe_summary: dict[str, Any]) -> Any:
        return queue.decide(
            request_id,
            ApprovalDecisionType.APPROVE,
            owner_key_hash="owner-a",
        )

    broker_a = broker_cls(queue, resolver=resolve)
    broker_b = broker_cls(queue, resolver=resolve)
    summary = {"endpoint": "html.duckduckgo.com", "kind": "web_search_egress"}
    first = await broker_a.request_and_claim_network(attempt, summary)
    with pytest.raises(module.EgressConsentError):
        await broker_b.request_and_claim_network(attempt, summary)
    assert first.nonce


@pytest.mark.asyncio
async def test_32_restart_replay_rejected(tmp_path: Path) -> None:
    module = _egress_mod()
    consume = _require(module, "consume_egress_receipt")
    receipt_cls = _require(module, "EgressConsentReceiptV1")
    import time

    receipt = receipt_cls(
        attempt_hash="c" * 64,
        claim_receipt_hash="d" * 64,
        expires_at=time.time() + 60,
        nonce="restart-n",
    )
    consume(receipt)
    with pytest.raises(module.EgressConsentError):
        consume(receipt)


@pytest.mark.asyncio
async def test_33_distinct_attempts_same_payload_are_independent(tmp_path: Path) -> None:
    module = _egress_mod()
    build = _require(module, "build_network_egress_attempt")
    kind = _require(module, "NetworkEgressKind")
    identity = _identity(module)
    kwargs = {
        "identity": identity,
        "kind": kind.WEB_SEARCH,
        "target_identity": "ddg",
        "endpoint_url": REMOTE_SEARCH,
        "method": "GET",
        "payload": {"q": "same"},
        "provenance": {
            "schema": "network-egress-provenance-v1",
            "kind": "web_search_egress",
            "source": "web_search",
            "tool_name": "web_search",
        },
        "credential_generation": "none",
    }
    a = build(**kwargs)
    b = build(**kwargs)
    assert a.attempt_id != b.attempt_id
    assert a.attempt_hash != b.attempt_hash


def test_34_unknown_kind_rejected() -> None:
    module = _egress_mod()
    build = _require(module, "build_network_egress_attempt")
    with pytest.raises((PermissionError, ValueError, TypeError)):
        build(
            identity=_identity(module),
            kind="not_a_kind",
            target_identity="x",
            endpoint_url=REMOTE_SEARCH,
            method="GET",
            payload={},
            provenance={},
            credential_generation="none",
        )


def test_35_subclass_nan_infinity_nested_huge_fail_closed() -> None:
    module = _egress_mod()
    snapshot = _require(module, "snapshot_jsonable")

    class EvilInt(int):
        pass

    with pytest.raises(ValueError):
        snapshot({"n": EvilInt(1)})
    with pytest.raises(ValueError):
        snapshot({"n": math.nan})
    with pytest.raises(ValueError):
        snapshot({"n": math.inf})
    deep: Any = {"k": None}
    cur = deep
    for _ in range(40):
        nxt: dict[str, Any] = {"k": None}
        cur["k"] = nxt
        cur = nxt
    with pytest.raises(ValueError):
        snapshot(deep)
    with pytest.raises(ValueError):
        snapshot({"s": "x" * (70 * 1024)})


@pytest.mark.asyncio
async def test_36_callback_cannot_mutate_snapshot(tmp_path: Path) -> None:
    module = _egress_mod()
    authorize = _require(module, "authorize_network_egress")
    kind = _require(module, "NetworkEgressKind")
    captured: list[Any] = []

    class HookBroker(FakeNetworkBroker):
        async def request_and_claim_network(self, attempt: Any, safe_summary: dict[str, Any]) -> Any:
            captured.append(attempt)
            try:
                object.__setattr__(attempt, "payload_digest", "0" * 64)
            except Exception:
                pass
            return await super().request_and_claim_network(attempt, safe_summary)

    broker = HookBroker()
    with network_runtime(tmp_path, broker=broker):
        try:
            auth = await authorize(
                kind=kind.WEB_SEARCH,
                target_identity="ddg",
                endpoint_url=REMOTE_SEARCH,
                method="GET",
                payload={"q": "frozen"},
                provenance={
                    "schema": "network-egress-provenance-v1",
                    "kind": "web_search_egress",
                    "source": "web_search",
                    "tool_name": "web_search",
                },
                credential_generation="none",
            )
        except module.EgressConsentError:
            return
        assert auth.attempt.payload_digest != "0" * 64
        assert auth.snapshot.payload == {"q": "frozen"}


@pytest.mark.asyncio
async def test_37_cancel_pending_not_replayable(tmp_path: Path) -> None:
    module = _egress_mod()
    queue = ApprovalQueue(default_mode=ApprovalMode.MANUAL, ledger_path=tmp_path / "a.jsonl")
    from js.echo.ledger.service import EchoSafetyService
    from js.security.approvals import wire_echo_approval_authority

    echo = EchoSafetyService(state_dir=tmp_path / "echo")
    queue.set_echo_authority(wire_echo_approval_authority(echo, product_id="js-agent"))
    build = _require(module, "build_network_egress_attempt")
    kind = _require(module, "NetworkEgressKind")
    attempt = build(
        identity=_identity(module),
        kind=kind.WEB_SEARCH,
        target_identity="ddg",
        endpoint_url=REMOTE_SEARCH,
        method="GET",
        payload={"q": "c"},
        provenance={
            "schema": "network-egress-provenance-v1",
            "kind": "web_search_egress",
            "source": "web_search",
            "tool_name": "web_search",
        },
        credential_generation="none",
    )
    request_id = _require(module, "network_egress_request_id")(attempt)
    pending = queue.request_decision(
        kind.WEB_SEARCH.value,
        {"attempt_hash": attempt.attempt_hash, "endpoint": "html.duckduckgo.com"},
        context="web",
        mode=ApprovalMode.MANUAL,
        session_id="session-a",
        run_id="run-a",
        owner_key_hash="owner-a",
        queue_if_unhandled=True,
        request_id=request_id,
    )
    assert pending.action is ApprovalDecisionType.PENDING
    queue.decide(request_id, ApprovalDecisionType.REJECT, owner_key_hash="owner-a")
    with pytest.raises(PermissionError):
        queue.consume_approved_binding(
            request_id,
            owner_key_hash="owner-a",
            session_id="session-a",
            run_id="run-a",
            tool_name=kind.WEB_SEARCH.value,
            arguments_hash=ApprovalQueue.arguments_hash(
                {"attempt_hash": attempt.attempt_hash, "endpoint": "html.duckduckgo.com"}
            ),
            require_manual=True,
        )


@pytest.mark.asyncio
async def test_38_failure_logs_omit_raw_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    effects = SideEffects()
    _patch_search_spies(monkeypatch, effects)
    caplog.set_level(logging.DEBUG)
    recorded: list[str] = []

    def capture_log(msg: Any, *args: Any, **kwargs: Any) -> None:
        recorded.append(f"{msg}|{args}|{kwargs}")

    monkeypatch.setattr("js.search.engines.logger.error", capture_log)
    monkeypatch.setattr("js.search.engines.logger.warning", capture_log)
    with (
        network_runtime(tmp_path, broker=None, channel="cron"),
        pytest.raises((PermissionError, RuntimeError)),
    ):
        await _search_once()
    _privacy_clean(caplog.text)
    _privacy_clean("".join(recorded))


def test_39_tenant_partition_isolated(tmp_path: Path) -> None:
    module = _egress_mod()
    build = _require(module, "build_network_egress_attempt")
    kind = _require(module, "NetworkEgressKind")
    a = build(
        identity=_identity(module, owner_key_hash="owner-a", product_id="js-agent"),
        kind=kind.WEB_SEARCH,
        target_identity="ddg",
        endpoint_url=REMOTE_SEARCH,
        method="GET",
        payload={"q": "x"},
        provenance={
            "schema": "network-egress-provenance-v1",
            "kind": "web_search_egress",
            "source": "web_search",
            "tool_name": "web_search",
        },
        credential_generation="none",
    )
    b = build(
        identity=_identity(module, owner_key_hash="owner-b", product_id="other"),
        kind=kind.WEB_SEARCH,
        target_identity="ddg",
        endpoint_url=REMOTE_SEARCH,
        method="GET",
        payload={"q": "x"},
        provenance={
            "schema": "network-egress-provenance-v1",
            "kind": "web_search_egress",
            "source": "web_search",
            "tool_name": "web_search",
        },
        credential_generation="none",
    )
    assert a.owner_key_hash != b.owner_key_hash
    assert a.attempt_hash != b.attempt_hash


def test_40_expired_receipt_rejected() -> None:
    module = _egress_mod()
    consume = _require(module, "consume_egress_receipt")
    receipt_cls = _require(module, "EgressConsentReceiptV1")
    receipt = receipt_cls(
        attempt_hash="e" * 64,
        claim_receipt_hash="f" * 64,
        expires_at=0.0,
        nonce="expired",
    )
    with pytest.raises(module.EgressConsentError):
        consume(receipt)


@pytest.mark.asyncio
async def test_browser_fetch_without_consent_zero_dns(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from js.config import SecurityConfig, ToolLimits
    from js.security.guard import BehaviorGuard
    from js.tools.browser import BrowserTool

    effects = SideEffects()
    monkeypatch.setattr("js.tools.browser.resolve_and_validate", effects.resolve)
    monkeypatch.setattr("httpx.AsyncClient", effects.client_cls)
    tool = BrowserTool(ToolLimits(), BehaviorGuard(SecurityConfig(), tmp_path))
    with network_runtime(tmp_path, broker=None, channel="cron"):
        result = await tool.fetch("https://example.test/page")
        assert result.success is False
    _assert_zero_network(effects)


@pytest.mark.asyncio
async def test_empty_base_url_is_not_loopback_exemption(tmp_path: Path) -> None:
    module = _egress_mod()
    classify = _require(module, "classify_network_endpoint_url")
    assert classify("") == "invalid"
    assert classify(None) == "invalid"
    assert classify("   ") == "invalid"
    assert classify("http://127.0.0.1:1/v1") == "literal_loopback"


def test_unknown_kind_not_treated_as_approve() -> None:
    from js.security.approvals import is_one_shot_egress_kind

    assert is_one_shot_egress_kind("model_egress")
    assert is_one_shot_egress_kind("web_search_egress")
    assert not is_one_shot_egress_kind("please_approve")


def test_network_permit_mac_binds_kind_attempt_id_and_payload_digest() -> None:
    from dataclasses import replace

    from js.models.permit import NetworkEgressPermitError, NetworkEgressPermitIssuer

    issuer = NetworkEgressPermitIssuer(key=b"k" * 32)
    base = {
        "kind": "web_search_egress",
        "attempt_id": "a" * 32,
        "attempt_hash": "b" * 64,
        "owner_key_hash": "owner-a",
        "session_id": "session-a",
        "run_id": "run-a",
        "channel": "search",
        "product_id": "js-agent",
        "endpoint_generation": "e" * 64,
        "credential_generation": "none",
        "payload_digest": "p" * 64,
        "provenance_digest": "q" * 64,
        "consent_receipt_hash": "sha256:" + "c" * 64,
        "appshell_epoch": "1",
    }
    permit = issuer.issue(**base)
    with pytest.raises(NetworkEgressPermitError):
        issuer.verify_and_consume(
            replace(permit, kind="connector_egress"),
            **{**base, "kind": "connector_egress"},
        )
    with pytest.raises(NetworkEgressPermitError):
        issuer.verify_and_consume(
            replace(permit, attempt_id="z" * 32),
            **{**base, "attempt_id": "z" * 32},
        )
    with pytest.raises(NetworkEgressPermitError):
        issuer.verify_and_consume(
            replace(permit, payload_digest="d" * 64),
            **{**base, "payload_digest": "d" * 64},
        )


def test_network_permit_mac_binds_endpoint_and_credential_generation() -> None:
    from dataclasses import replace

    from js.models.permit import NetworkEgressPermitError, NetworkEgressPermitIssuer

    issuer = NetworkEgressPermitIssuer(key=b"k" * 32)
    base = {
        "kind": "provider_discovery_egress",
        "attempt_id": "a" * 32,
        "attempt_hash": "b" * 64,
        "owner_key_hash": "owner-a",
        "session_id": "session-a",
        "run_id": "run-a",
        "channel": "search",
        "product_id": "js-agent",
        "endpoint_generation": "e" * 64,
        "credential_generation": "c" * 64,
        "payload_digest": "p" * 64,
        "provenance_digest": "q" * 64,
        "consent_receipt_hash": "sha256:" + "c" * 64,
        "appshell_epoch": "1",
    }
    permit = issuer.issue(**base)
    with pytest.raises(NetworkEgressPermitError):
        issuer.verify_and_consume(
            replace(permit, endpoint_generation="x" * 64),
            **{**base, "endpoint_generation": "x" * 64},
        )
    with pytest.raises(NetworkEgressPermitError):
        issuer.verify_and_consume(
            replace(permit, credential_generation="y" * 64),
            **{**base, "credential_generation": "y" * 64},
        )


XSS_IMG = '<img src=x onerror="window.__xss=1">'
DOM_HARNESS = r"""
import fs from 'node:fs';
import vm from 'node:vm';
const source = fs.readFileSync(process.argv[2], 'utf8');
const stripped = source.replace(/^import[\s\S]*?;\s*$/gm, '').replace(/^export\s+/gm, '');
const script = `${stripped}
globalThis.__render = typeof renderNetworkEgress === 'function' ? renderNetworkEgress : renderApproval;
globalThis.__isNet = typeof isNetworkEgress === 'function' ? isNetworkEgress : () => false;
`;
class FakeNode {
  constructor(tagName, document) {
    this.tagName = String(tagName).toUpperCase();
    this.document = document;
    this.children = [];
    this.attributes = {};
    this.dataset = {};
    this._text = '';
    this._html = '';
    this.usedInnerHTML = false;
    this.listeners = {};
    this.disabled = false;
    this.classList = { toggle() {} };
    this.style = {};
    this.parentNode = null;
    this.isConnected = true;
  }
  set className(v) { this.attributes.class = String(v); }
  get className() { return this.attributes.class || ''; }
  set textContent(v) { this._text = String(v); this.children = []; }
  get textContent() {
    if (this.children.length) return this.children.map(c => c.textContent).join('');
    return this._text;
  }
  set innerHTML(v) {
    this.usedInnerHTML = true;
    this._html = String(v);
    this.document.htmlSinks.push(this._html);
  }
  get innerHTML() { return this._html; }
  setAttribute(name, value) { this.attributes[String(name)] = String(value); }
  append(...nodes) { for (const n of nodes) this.appendChild(n); }
  appendChild(node) { node.parentNode = this; node.isConnected = true; this.children.push(node); return node; }
  addEventListener(type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); }
  click() {
    if (this.disabled) return;
    for (const fn of this.listeners.click || []) fn({ type: 'click', target: this });
  }
  querySelector(sel) {
    return this.querySelectorAll(sel)[0] || null;
  }
  querySelectorAll(sel) {
    const out = [];
    const walk = (node) => {
      if (sel === 'button' && node.tagName === 'BUTTON') out.push(node);
      if (sel.startsWith('[') && sel.includes('data-approval')) {
        if (node.dataset && Object.keys(node.dataset).length) out.push(node);
      }
      for (const c of node.children) walk(c);
    };
    walk(this);
    return out;
  }
  remove() {
    if (!this.parentNode) return;
    this.parentNode.children = this.parentNode.children.filter(c => c !== this);
    this.isConnected = false;
  }
}
class FakeDocument {
  constructor() {
    this.htmlSinks = [];
    this.body = new FakeNode('body', this);
    this.nodesById = {};
  }
  createElement(tag) { return new FakeNode(tag, this); }
  createDocumentFragment() { return new FakeNode('fragment', this); }
  getElementById(id) { return this.nodesById[id] || null; }
}
const fetchCalls = [];
const document = new FakeDocument();
const sandbox = {
  document,
  window: {},
  fetch: async (url) => {
    fetchCalls.push(url);
    return { ok: true, json: async () => ({ approvals: [] }), status: 200 };
  },
  showToast: () => {},
  state: { currentTab: 'approvals' },
  encodeURIComponent,
  JSON,
  Date,
  Number,
  String,
  Array,
  Object,
  console,
};
sandbox.globalThis = sandbox;
const context = vm.createContext(sandbox);
vm.runInContext(script, context);
const approval = {
  id: 'neg:wse:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  tool_name: 'web_search_egress',
  kind: 'web_search_egress',
  context: 'web',
  timestamp: 1,
  expires_at: 2,
  session_id: 's',
  run_id: 'r',
  safe_summary: { endpoint: 'html.duckduckgo.com', kind: 'web_search_egress', attempt_hash: 'abc' },
  arguments: { endpoint: 'html.duckduckgo.com' },
};
const isNet = context.__isNet(approval);
const card = context.__render(approval);
const buttons = card.querySelectorAll('button');
if (buttons[0]) { buttons[0].click(); buttons[0].click(); }
process.stdout.write(JSON.stringify({
  ok: isNet && document.htmlSinks.length === 0,
  isNet,
  htmlSinks: document.htmlSinks,
  fetchCount: fetchCalls.length,
  usedInnerHTML: document.htmlSinks.length > 0,
}));
"""


def test_network_egress_dom_uses_text_nodes(tmp_path: Path) -> None:
    node = shutil.which("node") or "/Users/jiangxuanzhen/.local/bin/node"
    if not Path(node).exists():
        pytest.fail("node is required for B2B-C DOM harness")
    approvals_js = Path(__file__).resolve().parents[1] / "js/web/static/tabs/approvals.js"
    harness = tmp_path / "b2c_dom.mjs"
    harness.write_text(DOM_HARNESS, encoding="utf-8")
    result = subprocess.run(
        [node, str(harness), str(approvals_js)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["ok"] is True
    assert payload["usedInnerHTML"] is False
    assert payload["htmlSinks"] == []


def test_approvals_js_has_no_innerhtml() -> None:
    approvals_js = Path(__file__).resolve().parents[1] / "js/web/static/tabs/approvals.js"
    text = approvals_js.read_text(encoding="utf-8")
    assert ".innerHTML" not in text
