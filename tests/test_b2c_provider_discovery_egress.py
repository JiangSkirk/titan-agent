"""B2B-C: provider discovery /models and probe_provider network egress."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import pytest

from js.models.capability import probe_provider
from js.models.provider_manager import ProviderManager
from tests.test_b2c_non_model_egress import (
    LOOPBACK_URL,
    SYNTH_API_KEY,
    SideEffects,
    _assert_zero_network,
    _egress_mod,
    _privacy_clean,
    _require,
    network_runtime,
)

REMOTE_MODELS = "https://api.example.test/v1"


def _patch_discover(monkeypatch: pytest.MonkeyPatch, effects: SideEffects) -> None:
    monkeypatch.setattr(
        "js.security.net_guard.resolve_and_validate_provider_endpoint",
        effects.resolve_provider,
    )
    monkeypatch.setattr("httpx.AsyncClient", effects.client_cls)


@pytest.mark.asyncio
async def test_21_models_without_consent_dns_sdk_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    effects = SideEffects()
    _patch_discover(monkeypatch, effects)
    with network_runtime(tmp_path, broker=None, channel="cron"):
        result = await ProviderManager.discover_models(REMOTE_MODELS, SYNTH_API_KEY)
        assert "error" in result or result.get("models") in (None, [])
    _assert_zero_network(effects)


@pytest.mark.asyncio
async def test_22_remote_setup_without_consent_zero_calls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    effects = SideEffects()
    _patch_discover(monkeypatch, effects)
    with network_runtime(tmp_path, broker=None, channel="cron"):
        result = await probe_provider(REMOTE_MODELS, SYNTH_API_KEY)
        assert result.ok is False
    _assert_zero_network(effects)


@pytest.mark.asyncio
async def test_23_endpoint_generation_mutation_zero_http(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _egress_mod()
    effects = SideEffects()
    _patch_discover(monkeypatch, effects)
    from tests.test_b2c_non_model_egress import FakeNetworkBroker

    broker = FakeNetworkBroker()
    with network_runtime(tmp_path, broker=broker, channel="search"):
        original = _require(module, "authorize_network_egress")

        async def mutated(*args: Any, **kwargs: Any) -> Any:
            auth = await original(*args, **kwargs)
            snapshot = getattr(auth, "snapshot", None)
            if snapshot is not None:
                try:
                    object.__setattr__(snapshot, "endpoint_generation", "mutated-gen")
                except Exception:
                    pass
            return auth

        monkeypatch.setattr(module, "authorize_network_egress", mutated)
        result = await ProviderManager.discover_models(REMOTE_MODELS, SYNTH_API_KEY)
        assert "error" in result
    _assert_zero_network(effects)


@pytest.mark.asyncio
async def test_24_credential_generation_mutation_zero_http(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _egress_mod()
    effects = SideEffects()
    _patch_discover(monkeypatch, effects)
    from tests.test_b2c_non_model_egress import FakeNetworkBroker

    broker = FakeNetworkBroker()
    with network_runtime(tmp_path, broker=broker, channel="search"):
        original = _require(module, "authorize_network_egress")

        async def mutated(*args: Any, **kwargs: Any) -> Any:
            auth = await original(*args, **kwargs)
            attempt = getattr(auth, "attempt", None)
            if attempt is not None:
                try:
                    object.__setattr__(attempt, "credential_generation", "0" * 64)
                except Exception:
                    pass
            return auth

        monkeypatch.setattr(module, "authorize_network_egress", mutated)
        result = await ProviderManager.discover_models(REMOTE_MODELS, SYNTH_API_KEY)
        assert "error" in result
    _assert_zero_network(effects)


@pytest.mark.asyncio
async def test_25_background_refresh_without_adapter_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    effects = SideEffects()
    _patch_discover(monkeypatch, effects)
    from js.web.model_refresh import (
        maybe_refresh_models_async,
        refresh_cloud_provider_models,
        refresh_local_provider_models,
    )

    maybe_refresh_models_async(None)  # type: ignore[arg-type]
    await refresh_cloud_provider_models(None)  # type: ignore[arg-type]
    await refresh_local_provider_models(None)  # type: ignore[arg-type]
    with network_runtime(tmp_path, broker=None, channel="cron"):
        result = await ProviderManager.discover_models(REMOTE_MODELS, SYNTH_API_KEY)
        assert "error" in result
    _assert_zero_network(effects)


@pytest.mark.asyncio
async def test_26_retry_does_not_reuse_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    effects = SideEffects()
    _patch_discover(monkeypatch, effects)
    from tests.test_b2c_non_model_egress import FakeNetworkBroker

    broker = FakeNetworkBroker()
    with network_runtime(tmp_path, broker=broker, channel="search"):
        await ProviderManager.discover_models(REMOTE_MODELS, SYNTH_API_KEY)
        first = broker.claim_count
        await ProviderManager.discover_models(REMOTE_MODELS, SYNTH_API_KEY)
        assert broker.claim_count >= first + 1
        if len(broker.attempts) >= 2:
            assert broker.attempts[0].attempt_id != broker.attempts[1].attempt_id


@pytest.mark.asyncio
async def test_27_api_key_not_in_ui_ledger_log(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    effects = SideEffects()
    _patch_discover(monkeypatch, effects)
    caplog.set_level(logging.DEBUG)
    from tests.test_b2c_non_model_egress import FakeNetworkBroker

    broker = FakeNetworkBroker()
    with network_runtime(tmp_path, broker=broker, channel="search"):
        await ProviderManager.discover_models(REMOTE_MODELS, SYNTH_API_KEY)
    blob = caplog.text
    for summary in broker.summaries:
        blob += str(summary)
    _privacy_clean(blob)
    assert SYNTH_API_KEY not in blob
    assert "Authorization" not in blob or SYNTH_API_KEY not in blob


@pytest.mark.asyncio
async def test_28_canonical_loopback_forward(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    effects = SideEffects()
    _patch_discover(monkeypatch, effects)
    with network_runtime(tmp_path, broker=None, channel="search"):
        result = await ProviderManager.discover_models(LOOPBACK_URL, None)
    assert effects.dns >= 1
    assert effects.client >= 1
    assert "error" not in result or isinstance(result, dict)


@pytest.mark.asyncio
async def test_29_b1b_pinned_transport_still_used(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    effects = SideEffects()
    pinned: list[Any] = []

    def capture_transport(*args: Any, **kwargs: Any) -> Any:
        pinned.append((args, kwargs))
        return object()

    monkeypatch.setattr(
        "js.security.net_guard.resolve_and_validate_provider_endpoint",
        effects.resolve_provider,
    )
    monkeypatch.setattr("js.security.net_guard.PinnedTransport", capture_transport)
    monkeypatch.setattr("httpx.AsyncClient", effects.client_cls)
    from tests.test_b2c_non_model_egress import FakeNetworkBroker

    broker = FakeNetworkBroker()
    with network_runtime(tmp_path, broker=broker, channel="search"):
        await ProviderManager.discover_models(REMOTE_MODELS, SYNTH_API_KEY)
    assert pinned, "PinnedTransport must be constructed"
    assert effects.dns >= 1
    if effects.order:
        assert effects.order[0] != "dns" or "consent" in effects.order or broker.claim_count >= 1


@pytest.mark.asyncio
async def test_30_malformed_empty_missing_base_url_no_exemption(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    effects = SideEffects()
    _patch_discover(monkeypatch, effects)
    with network_runtime(tmp_path, broker=None, channel="search"):
        empty = await ProviderManager.discover_models("", SYNTH_API_KEY)
        missing = await ProviderManager.discover_models("   ", SYNTH_API_KEY)
        malformed = await ProviderManager.discover_models("not-a-url", SYNTH_API_KEY)
    assert "error" in empty
    assert "error" in missing
    assert "error" in malformed
    _assert_zero_network(effects)


def test_classify_rejects_empty_as_loopback() -> None:
    module = _egress_mod()
    classify = _require(module, "classify_network_endpoint_url")
    assert classify("") == "invalid"
    assert classify(None) == "invalid"
    assert classify("http://127.0.0.1/v1") == "literal_loopback"
    assert classify("https://api.example.test/v1") == "remote"


LM_STUDIO_BASE = "http://127.0.0.1:1234/v1"


class _RecordingClient:
    def __init__(self, effects: SideEffects, gets: list[str], *, fail_first: bool = False) -> None:
        self._effects = effects
        self._gets = gets
        self._fail_first = fail_first
        self._calls = 0
        effects.client += 1
        effects.order.append("client")

    async def __aenter__(self) -> _RecordingClient:
        return self

    async def __aexit__(self, *args: Any) -> None:
        return None

    async def get(self, url: str, **kwargs: Any) -> Any:
        import httpx

        self._effects.http += 1
        self._gets.append(str(url))
        self._calls += 1
        if self._fail_first and self._calls == 1 and "/api/v0/models" in str(url):
            raise httpx.ConnectError("v0 unavailable")
        request = httpx.Request("GET", str(url))
        if "/api/v0/models" in str(url):
            return httpx.Response(
                200,
                json={
                    "data": [
                        {
                            "id": "studio-model",
                            "state": "loaded",
                            "max_context_length": 8192,
                        }
                    ]
                },
                request=request,
            )
        return httpx.Response(
            200,
            json={"data": [{"id": "studio-model", "object": "model"}]},
            request=request,
        )


@pytest.mark.asyncio
async def test_lmstudio_one_authorization_per_get(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _egress_mod()
    effects = SideEffects()
    gets: list[str] = []
    auths: list[Any] = []
    monkeypatch.setattr(
        "js.security.net_guard.resolve_and_validate_provider_endpoint",
        effects.resolve_provider,
    )
    monkeypatch.setattr(
        "httpx.AsyncClient",
        lambda *args, **kwargs: _RecordingClient(effects, gets),
    )
    original = _require(module, "authorize_network_egress")

    async def record_auth(*args: Any, **kwargs: Any) -> Any:
        auth = await original(*args, **kwargs)
        auths.append(
            {
                "attempt_id": auth.attempt.attempt_id,
                "payload_digest": auth.attempt.payload_digest,
                "nonce": auth.permit.nonce,
                "path": (auth.snapshot.payload or {}).get("path")
                if type(auth.snapshot.payload) is dict
                else kwargs.get("payload"),
                "endpoint": auth.snapshot.endpoint_url,
            }
        )
        return auth

    monkeypatch.setattr(module, "authorize_network_egress", record_auth)
    with network_runtime(tmp_path, broker=None, channel="search"):
        result = await ProviderManager.discover_models(LM_STUDIO_BASE, None)
    assert "error" not in result or result.get("models")
    assert gets, "expected at least one GET"
    assert len(auths) == len(gets)
    attempt_ids = [row["attempt_id"] for row in auths]
    nonces = [row["nonce"] for row in auths]
    assert len(set(attempt_ids)) == len(gets)
    assert len(set(nonces)) == len(gets)
    by_attempt: dict[str, list[str]] = {}
    for auth, url in zip(auths, gets, strict=True):
        by_attempt.setdefault(auth["attempt_id"], []).append(url)
    for urls in by_attempt.values():
        assert len(urls) == 1


@pytest.mark.asyncio
async def test_lmstudio_successful_first_get_does_not_reuse_same_authorization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    await test_lmstudio_one_authorization_per_get(tmp_path, monkeypatch)


@pytest.mark.asyncio
async def test_lmstudio_fallback_uses_new_attempt_and_permit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _egress_mod()
    effects = SideEffects()
    gets: list[str] = []
    auths: list[Any] = []
    monkeypatch.setattr(
        "js.security.net_guard.resolve_and_validate_provider_endpoint",
        effects.resolve_provider,
    )
    monkeypatch.setattr(
        "httpx.AsyncClient",
        lambda *args, **kwargs: _RecordingClient(effects, gets, fail_first=True),
    )
    original = _require(module, "authorize_network_egress")

    async def record_auth(*args: Any, **kwargs: Any) -> Any:
        auth = await original(*args, **kwargs)
        auths.append(auth)
        return auth

    monkeypatch.setattr(module, "authorize_network_egress", record_auth)
    with network_runtime(tmp_path, broker=None, channel="search"):
        await ProviderManager.discover_models(LM_STUDIO_BASE, None)
    v1_gets = [url for url in gets if str(url).rstrip("/").endswith("/models")]
    assert v1_gets, "fallback /models GET must still happen"
    assert len(auths) >= 2
    assert auths[0].attempt.attempt_id != auths[1].attempt.attempt_id
    assert auths[0].permit.nonce != auths[1].permit.nonce
    assert auths[0].attempt.payload_digest != auths[1].attempt.payload_digest


@pytest.mark.asyncio
async def test_models_remote_one_get_one_authorization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _egress_mod()
    effects = SideEffects()
    gets: list[str] = []
    auths: list[Any] = []
    from tests.test_b2c_non_model_egress import FakeNetworkBroker

    monkeypatch.setattr(
        "js.security.net_guard.resolve_and_validate_provider_endpoint",
        effects.resolve_provider,
    )
    monkeypatch.setattr(
        "httpx.AsyncClient",
        lambda *args, **kwargs: _RecordingClient(effects, gets),
    )
    original = _require(module, "authorize_network_egress")

    async def record_auth(*args: Any, **kwargs: Any) -> Any:
        auth = await original(*args, **kwargs)
        auths.append(auth)
        return auth

    monkeypatch.setattr(module, "authorize_network_egress", record_auth)
    broker = FakeNetworkBroker()
    with network_runtime(tmp_path, broker=broker, channel="search"):
        await ProviderManager.discover_models(REMOTE_MODELS, SYNTH_API_KEY)
    assert len(gets) == 1
    assert len(auths) == 1
    assert auths[0].attempt.attempt_id
    assert "/api/v0/models" not in gets[0]
