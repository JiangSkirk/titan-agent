"""B1B Provider Transport Security: HTTPS, DNS classification, pinned transport.

Red tests covering the full provider transport security contract:

1. Remote HTTP rejected at config / discovery / probe / embed client creation.
2. Canonical literal loopback (127.0.0.0/8, ::1) allowed; localhost / 0.0.0.0 /
   127.1 / integer / hex / domain-with-localhost rejected as loopback exemption.
3. Mixed DNS (public + private) fail closed.
4. Chat / stream / health / embed share the same pinned transport.
5. DNS rebinding: second resolution cannot redirect the pinned connection.
6. Public IPv6 allowed.
7. Redirects forbidden (follow_redirects=False).
8. trust_env=False, verify=True on all provider clients.
9. Synchronous embedding uses pinned transport.
10. Async backend is a working AnyIOBackend, not the abstract base.
"""

from __future__ import annotations

import asyncio
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpcore
import httpx
import pytest

from js.security.net_guard import (
    OutboundURLError,
    PinnedIPBackend,
    PinnedSyncTransport,
    PinnedTransport,
    resolve_and_validate,
    resolve_and_validate_provider_endpoint,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_resolver(mapping: dict[str, list[str]]):
    def _resolve(host: str, port: int | None) -> list[str]:
        if host in mapping:
            return mapping[host]
        raise OutboundURLError(f"unmapped host {host!r}")

    return _resolve


class _AsyncTLSStream(httpcore.AsyncNetworkStream):
    def __init__(self) -> None:
        self._reads = [
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        ]
        self.writes: list[bytes] = []
        self.server_hostname: str | None = None
        self.ssl_context: ssl.SSLContext | None = None

    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        del max_bytes, timeout
        return self._reads.pop(0) if self._reads else b""

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        del timeout
        self.writes.append(buffer)

    async def aclose(self) -> None:
        return None

    async def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> httpcore.AsyncNetworkStream:
        del timeout
        self.ssl_context = ssl_context
        self.server_hostname = server_hostname
        return self


class _AsyncTLSBackend(httpcore.AsyncNetworkBackend):
    def __init__(self, stream: _AsyncTLSStream) -> None:
        self.stream = stream
        self.calls: list[tuple[Any, ...]] = []

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Any = None,
    ) -> httpcore.AsyncNetworkStream:
        self.calls.append((host, port, timeout, local_address, socket_options))
        return self.stream

    async def connect_unix_socket(self, *args: Any, **kwargs: Any) -> Any:
        raise AssertionError("unix socket is forbidden in provider TLS test")

    async def sleep(self, seconds: float) -> None:
        raise AssertionError(f"unexpected sleep: {seconds}")


class _SyncTLSStream(httpcore.NetworkStream):
    def __init__(self) -> None:
        self._reads = [
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        ]
        self.writes: list[bytes] = []
        self.server_hostname: str | None = None
        self.ssl_context: ssl.SSLContext | None = None

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        del max_bytes, timeout
        return self._reads.pop(0) if self._reads else b""

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        del timeout
        self.writes.append(buffer)

    def close(self) -> None:
        return None

    def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> httpcore.NetworkStream:
        del timeout
        self.ssl_context = ssl_context
        self.server_hostname = server_hostname
        return self


class _SyncTLSBackend(httpcore.NetworkBackend):
    def __init__(self, stream: _SyncTLSStream) -> None:
        self.stream = stream
        self.calls: list[tuple[Any, ...]] = []

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Any = None,
    ) -> httpcore.NetworkStream:
        self.calls.append((host, port, timeout, local_address, socket_options))
        return self.stream

    def connect_unix_socket(self, *args: Any, **kwargs: Any) -> Any:
        raise AssertionError("unix socket is forbidden in provider TLS test")

    def sleep(self, seconds: float) -> None:
        raise AssertionError(f"unexpected sleep: {seconds}")


# ---------------------------------------------------------------------------
# 1. Remote HTTP rejected before client creation
# ---------------------------------------------------------------------------


class TestRemoteHttpRejected:
    """HTTP to non-loopback must be rejected at every entry point."""

    def test_config_rejects_remote_http(self) -> None:
        from js.config import ModelProviderConfig

        with pytest.raises(ValueError):
            ModelProviderConfig(name="evil", base_url="http://93.184.216.34/v1")

    @pytest.mark.asyncio
    async def test_discover_models_rejects_remote_http(self) -> None:
        from js.models.provider_manager import ProviderManager

        result = await ProviderManager.discover_models("http://93.184.216.34/v1")
        assert "error" in result
        assert "安全策略" in result["error"]

    @pytest.mark.asyncio
    async def test_probe_provider_rejects_remote_http(self) -> None:
        from js.models.capability import probe_provider

        result = await probe_provider("http://93.184.216.34/v1", "sk-test")
        assert result.ok is False
        assert "policy" in result.error.lower() or "address" in result.error.lower()

    @pytest.mark.asyncio
    async def test_embed_client_rejects_remote_http(self) -> None:
        from js.memory.embeddings import LLMEmbedder

        with pytest.raises(OutboundURLError):
            LLMEmbedder(base_url="http://93.184.216.34/v1", api_key="sk-test")

    def test_provider_rejects_remote_http_at_init(self) -> None:
        from js.config import ModelProviderConfig
        from js.models.providers import OpenAICompatibleProvider

        with pytest.raises(ValueError):
            OpenAICompatibleProvider(
                ModelProviderConfig(name="evil", base_url="http://93.184.216.34/v1")
            )


# ---------------------------------------------------------------------------
# 2. Canonical literal loopback policy
# ---------------------------------------------------------------------------


class TestCanonicalLoopback:
    """Only 127.0.0.0/8 and ::1 literals get the loopback exemption."""

    @pytest.mark.parametrize("ip", ["127.0.0.1", "127.0.0.2", "127.255.255.255", "127.0.0.8"])
    def test_loopback_ipv4_range_allowed(self, ip: str) -> None:
        ips = resolve_and_validate(f"http://{ip}:1234/v1", allow_loopback=True)
        assert ip in ips

    def test_loopback_ipv6_allowed(self) -> None:
        ips = resolve_and_validate("http://[::1]:1234/v1", allow_loopback=True)
        assert "::1" in ips

    def test_localhost_hostname_not_loopback_exempt(self) -> None:
        """localhost must NOT get loopback exemption — it must be resolved."""
        resolver = _mock_resolver({"localhost": ["127.0.0.1"]})
        with pytest.raises(OutboundURLError, match="loopback"):
            resolve_and_validate(
                "http://localhost:1234/v1",
                allow_loopback=False,
                resolver=resolver,
            )

    def test_localhost_resolving_to_loopback_blocked_without_exemption(self) -> None:
        """Even when allow_loopback=True, localhost resolving to 127.0.0.1
        must be blocked unless the literal check passes."""
        # localhost is not a canonical literal, so it must go through DNS resolution
        # and if it resolves to loopback, allow_loopback must apply.
        resolver = _mock_resolver({"localhost": ["127.0.0.1"]})
        with pytest.raises(OutboundURLError, match="loopback"):
            resolve_and_validate(
                "http://localhost:1234/v1",
                allow_loopback=True,
                resolver=resolver,
            )

    def test_0000_not_loopback_exempt(self) -> None:
        """0.0.0.0 is not a canonical loopback and must not be exempt."""
        resolver = _mock_resolver({"0.0.0.0": ["0.0.0.0"]})
        with pytest.raises(OutboundURLError):
            resolve_and_validate(
                "http://0.0.0.0:1234/v1",
                allow_loopback=True,
                allow_private=False,
                resolver=resolver,
            )

    def test_127_1_not_loopback_exempt(self) -> None:
        """127.1 is a short-form that resolves to 127.0.0.1 but is not a canonical literal."""
        with pytest.raises(OutboundURLError):
            resolve_and_validate("http://127.1:1234/v1", allow_loopback=False)

    def test_integer_ip_not_loopback_exempt(self) -> None:
        """2130706433 is decimal-encoded 127.0.0.1, not a canonical literal."""
        with pytest.raises(OutboundURLError):
            resolve_and_validate("http://2130706433:1234/v1", allow_loopback=False)

    def test_hex_ip_not_loopback_exempt(self) -> None:
        """0x7f000001 is hex-encoded 127.0.0.1, not a canonical literal."""
        with pytest.raises(OutboundURLError):
            resolve_and_validate("http://0x7f000001:1234/v1", allow_loopback=False)

    def test_domain_containing_localhost_not_exempt(self) -> None:
        """foo.localhost must not get a special exemption."""
        resolver = _mock_resolver({"foo.localhost": ["127.0.0.1"]})
        with pytest.raises(OutboundURLError):
            resolve_and_validate(
                "http://foo.localhost:1234/v1",
                allow_loopback=False,
                resolver=resolver,
            )


# ---------------------------------------------------------------------------
# 3. Mixed DNS fail closed
# ---------------------------------------------------------------------------


class TestMixedDNSFailClosed:
    """If DNS returns both public and private addresses, the whole group is rejected."""

    def test_mixed_public_private_fails_closed(self) -> None:
        resolver = _mock_resolver({"evil.example": ["93.184.216.34", "10.0.0.5"]})
        with pytest.raises(OutboundURLError):
            resolve_and_validate("https://evil.example/", resolver=resolver)

    def test_mixed_private_public_fails_closed_regardless_of_dns_order(self) -> None:
        resolver = _mock_resolver({"evil.example": ["10.0.0.5", "93.184.216.34"]})
        with pytest.raises(OutboundURLError):
            resolve_and_validate("https://evil.example/", resolver=resolver)

    def test_mixed_public_loopback_fails_closed(self) -> None:
        resolver = _mock_resolver({"evil.example": ["93.184.216.34", "127.0.0.1"]})
        with pytest.raises(OutboundURLError, match="loopback"):
            resolve_and_validate("https://evil.example/", resolver=resolver)

    def test_mixed_public_metadata_fails_closed(self) -> None:
        resolver = _mock_resolver({"evil.example": ["93.184.216.34", "169.254.169.254"]})
        with pytest.raises(OutboundURLError):
            resolve_and_validate("https://evil.example/", resolver=resolver)

    def test_https_allows_private_when_allow_private_set(self) -> None:
        resolver = _mock_resolver({"gpu.lan": ["192.168.1.50"]})
        ips = resolve_and_validate(
            "https://gpu.lan:1234/v1",
            allow_private=True,
            resolver=resolver,
        )
        assert ips == ["192.168.1.50"]

    @pytest.mark.parametrize(
        "address",
        ["169.254.169.254", "100.100.100.200", "fd00:ec2::254"],
    )
    def test_metadata_always_blocked_even_with_allow_private(
        self, address: str
    ) -> None:
        resolver = _mock_resolver({"meta.example": [address]})
        with pytest.raises(OutboundURLError):
            resolve_and_validate(
                "https://meta.example/",
                allow_private=True,
                resolver=resolver,
            )

    def test_link_local_always_blocked(self) -> None:
        resolver = _mock_resolver({"link.example": ["fe80::1"]})
        with pytest.raises(OutboundURLError):
            resolve_and_validate(
                "https://link.example/",
                allow_private=True,
                resolver=resolver,
            )

    def test_reserved_always_blocked(self) -> None:
        resolver = _mock_resolver({"reserved.example": ["240.0.0.1"]})
        with pytest.raises(OutboundURLError):
            resolve_and_validate(
                "https://reserved.example/",
                allow_private=True,
                resolver=resolver,
            )

    @pytest.mark.parametrize(
        "address",
        [
            "100.64.0.1",
            "192.0.2.1",
            "192.88.99.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "2001:db8::1",
            "fec0::1",
        ],
    )
    def test_special_purpose_ranges_stay_blocked_with_private_authority(
        self, address: str
    ) -> None:
        resolver = _mock_resolver({"special.example": [address]})
        with pytest.raises(OutboundURLError):
            resolve_and_validate(
                "https://special.example/v1",
                allow_private=True,
                resolver=resolver,
            )

    @pytest.mark.parametrize(
        "address",
        ["10.0.0.1", "172.16.0.1", "192.168.0.1", "fc00::1"],
    )
    def test_only_rfc1918_and_ula_are_enabled_by_private_authority(
        self, address: str
    ) -> None:
        resolver = _mock_resolver({"private.example": [address]})
        with pytest.raises(OutboundURLError):
            resolve_and_validate(
                "https://private.example/v1",
                allow_private=False,
                resolver=resolver,
            )
        assert resolve_and_validate(
            "https://private.example/v1",
            allow_private=True,
            resolver=resolver,
        ) == [address]

    @pytest.mark.parametrize(
        "address",
        ["::ffff:169.254.169.254", "::ffff:100.100.100.200"],
    )
    def test_mapped_metadata_is_always_blocked(self, address: str) -> None:
        resolver = _mock_resolver({"mapped-meta.example": [address]})
        with pytest.raises(OutboundURLError):
            resolve_and_validate(
                "https://mapped-meta.example/v1",
                allow_private=True,
                resolver=resolver,
            )

    def test_mapped_private_obeys_private_authority(self) -> None:
        address = "::ffff:10.0.0.1"
        resolver = _mock_resolver({"mapped-private.example": [address]})
        with pytest.raises(OutboundURLError):
            resolve_and_validate(
                "https://mapped-private.example/v1",
                allow_private=False,
                resolver=resolver,
            )
        assert resolve_and_validate(
            "https://mapped-private.example/v1",
            allow_private=True,
            resolver=resolver,
        ) == [address]

    @pytest.mark.parametrize("allow_private", [False, True])
    def test_mapped_loopback_never_inherits_private_network_authority(
        self, allow_private: bool
    ) -> None:
        resolver = _mock_resolver({"mapped-loopback.example": ["::ffff:127.0.0.1"]})
        with pytest.raises(OutboundURLError, match="loopback"):
            resolve_and_validate(
                "https://mapped-loopback.example/v1",
                allow_private=allow_private,
                resolver=resolver,
            )


# ---------------------------------------------------------------------------
# 4. Chat / stream / health / embed share pinned transport
# ---------------------------------------------------------------------------


class TestSharedPinnedTransport:
    """The provider must lazily create a single pinned transport shared across all calls."""

    @pytest.mark.asyncio
    async def test_provider_lazy_single_flight_pinned_transport(self) -> None:
        from js.config import ModelProviderConfig
        from js.models.providers import OpenAICompatibleProvider

        resolutions = 0

        def resolve_once(*_args: Any, **_kwargs: Any) -> list[str]:
            nonlocal resolutions
            resolutions += 1
            time.sleep(0.02)
            return ["93.184.216.34"]

        with patch(
            "js.security.net_guard.resolve_and_validate_provider_endpoint",
            side_effect=resolve_once,
        ):
            provider = OpenAICompatibleProvider(
                ModelProviderConfig(
                    name="test",
                    base_url="https://api.example.com/v1",
                )
            )
            assert resolutions == 0
            clients = await asyncio.gather(
                *(provider._ensure_client() for _ in range(12))
            )
            assert resolutions == 1
            assert all(client is clients[0] for client in clients)
            assert provider._http_client is not None
            assert clients[0]._client is provider._http_client
            assert isinstance(provider._http_client._transport, PinnedTransport)
            await provider.close()

    @pytest.mark.asyncio
    async def test_failed_initialisation_wave_is_single_flight_and_retryable(self) -> None:
        from js.config import ModelProviderConfig
        from js.models.providers import OpenAICompatibleProvider

        entered = asyncio.Event()
        release = asyncio.Event()
        failing = True

        async def controlled_resolution(
            _resolver: Any, *_args: Any, **_kwargs: Any
        ) -> list[str]:
            entered.set()
            await release.wait()
            if failing:
                raise OutboundURLError("synthetic resolution failure")
            return ["93.184.216.34"]

        provider = OpenAICompatibleProvider(
            ModelProviderConfig(
                name="test",
                base_url="https://api.example.com/v1",
            )
        )
        with patch(
            "js.models.providers.asyncio.to_thread",
            new_callable=AsyncMock,
            side_effect=controlled_resolution,
        ) as to_thread:
            tasks = [asyncio.create_task(provider._ensure_client()) for _ in range(12)]
            await asyncio.wait_for(entered.wait(), timeout=1.0)
            await asyncio.sleep(0)
            release.set()
            results = await asyncio.gather(*tasks, return_exceptions=True)

            assert to_thread.await_count == 1
            assert all(isinstance(item, OutboundURLError) for item in results)
            assert {str(item) for item in results} == {"synthetic resolution failure"}

            failing = False
            client = await provider._ensure_client()
            assert client is provider.client
            assert to_thread.await_count == 2
            await provider.close()

    @pytest.mark.asyncio
    async def test_provider_close_waits_for_inflight_health_request(self) -> None:
        from js.config import ModelProviderConfig
        from js.models.providers import OpenAICompatibleProvider

        entered = asyncio.Event()
        release = asyncio.Event()
        closed = asyncio.Event()

        class _Models:
            async def list(self) -> list[Any]:
                entered.set()
                await release.wait()
                assert not closed.is_set(), "SDK client closed while request was active"
                return []

        class _FakeSDK:
            models = _Models()

            async def close(self) -> None:
                closed.set()

        provider = OpenAICompatibleProvider(
            ModelProviderConfig(name="test", base_url="https://api.example.com/v1")
        )
        provider.client = _FakeSDK()  # type: ignore[assignment]
        request = asyncio.create_task(provider.health_check())
        await asyncio.wait_for(entered.wait(), timeout=1.0)
        closing = asyncio.create_task(provider.close())
        await asyncio.sleep(0)
        try:
            assert not closed.is_set()
            assert not closing.done()
        finally:
            release.set()
            assert await asyncio.wait_for(request, timeout=1.0) is True
            await asyncio.wait_for(closing, timeout=1.0)

    @pytest.mark.asyncio
    async def test_close_waits_for_inflight_first_client_initialisation(self) -> None:
        from js.config import ModelProviderConfig
        from js.models.providers import OpenAICompatibleProvider

        entered = asyncio.Event()
        release = asyncio.Event()
        close_order: list[str] = []

        async def controlled_resolution(
            _resolver: Any,
            *_args: Any,
            **_kwargs: Any,
        ) -> list[str]:
            entered.set()
            await release.wait()
            return ["93.184.216.34"]

        class _FakeHTTPClient:
            async def aclose(self) -> None:
                close_order.append("http_close")

        class _Models:
            async def list(self) -> list[Any]:
                close_order.append("models_list")
                return []

        class _FakeSDK:
            models = _Models()

            def __init__(self, http_client: _FakeHTTPClient) -> None:
                self._http_client = http_client

            async def close(self) -> None:
                close_order.append("sdk_close")
                await self._http_client.aclose()

        http_client = _FakeHTTPClient()
        provider = OpenAICompatibleProvider(
            ModelProviderConfig(name="test", base_url="https://api.example.com/v1")
        )
        with (
            patch(
                "js.models.providers.asyncio.to_thread",
                new_callable=AsyncMock,
                side_effect=controlled_resolution,
            ),
            patch("js.models.providers.httpx.AsyncClient", return_value=http_client),
            patch(
                "js.models.providers.AsyncOpenAI",
                side_effect=lambda **kwargs: _FakeSDK(kwargs["http_client"]),
            ),
        ):
            request = asyncio.create_task(provider.health_check())
            await asyncio.wait_for(entered.wait(), timeout=1.0)
            closing = asyncio.create_task(provider.close())
            await asyncio.sleep(0)
            assert not closing.done()
            release.set()

            assert await asyncio.wait_for(request, timeout=1.0) is True
            await asyncio.wait_for(closing, timeout=1.0)

        assert close_order == ["models_list", "sdk_close", "http_close"]
        assert provider.client is None

    def test_llm_embedder_close_waits_for_inflight_post(self) -> None:
        from js.memory.embeddings import LLMEmbedder

        entered = threading.Event()
        release = threading.Event()
        closed = threading.Event()

        class _Response:
            def raise_for_status(self) -> None:
                return None

            def json(self) -> dict[str, Any]:
                return {"data": [{"embedding": [1.0]}]}

        class _FakeClient:
            def post(self, *_args: Any, **_kwargs: Any) -> _Response:
                entered.set()
                assert release.wait(1.0)
                assert not closed.is_set(), "HTTP client closed while request was active"
                return _Response()

            def close(self) -> None:
                closed.set()

        embedder = LLMEmbedder(
            "http://127.0.0.1:1234/v1",
            "synthetic-key",
            max_retries=1,
        )
        embedder.client = _FakeClient()  # type: ignore[assignment]
        with ThreadPoolExecutor(max_workers=2) as pool:
            request = pool.submit(embedder.embed_batch, ["x"])
            assert entered.wait(1.0)
            closing = pool.submit(embedder.close)
            try:
                assert not closed.wait(0.1)
                assert not closing.done()
            finally:
                release.set()
                assert request.result(1.0) == [[1.0]]
                closing.result(1.0)

    @pytest.mark.asyncio
    async def test_dns_policy_failure_never_creates_unpinned_fallback(self) -> None:
        from js.config import ModelProviderConfig
        from js.models.providers import OpenAICompatibleProvider

        with (
            patch(
                "js.security.net_guard.resolve_and_validate_provider_endpoint",
                side_effect=OutboundURLError("blocked destination"),
            ),
            patch("js.models.providers.AsyncOpenAI") as openai_client,
            patch("js.models.providers.httpx.AsyncClient") as http_client,
        ):
            provider = OpenAICompatibleProvider(
                ModelProviderConfig(
                    name="test",
                    base_url="https://api.example.com/v1",
                )
            )
            assert provider._http_client is None
            assert provider.client is None
            with pytest.raises(OutboundURLError, match="blocked"):
                await provider._ensure_client()
            openai_client.assert_not_called()
            http_client.assert_not_called()

    @pytest.mark.asyncio
    async def test_provider_http_client_uses_pinned_transport(self) -> None:
        from js.config import ModelProviderConfig
        from js.models.providers import OpenAICompatibleProvider

        with (
            patch(
                "js.security.net_guard.resolve_and_validate_provider_endpoint",
                return_value=["93.184.216.34"],
            ),
        ):
            provider = OpenAICompatibleProvider(
                ModelProviderConfig(
                    name="test",
                    base_url="https://api.example.com/v1",
                )
            )
            await provider._ensure_client()
            http_client = provider._http_client
            assert http_client is not None
            assert isinstance(getattr(http_client, "_transport", None), PinnedTransport)
            await provider.close()

    @pytest.mark.asyncio
    async def test_all_runtime_entrypoints_share_one_injected_pinned_client(self) -> None:
        from js.config import ModelProviderConfig
        from js.models.providers import ChatMessage, OpenAICompatibleProvider

        calls: list[tuple[str, str | None, int, int]] = []

        class _MemoryStream:
            def __init__(self) -> None:
                self._remaining = 1

            async def __aenter__(self) -> _MemoryStream:
                return self

            async def __aexit__(self, *_args: Any) -> None:
                return None

            def __aiter__(self) -> _MemoryStream:
                return self

            async def __anext__(self) -> Any:
                if not self._remaining:
                    raise StopAsyncIteration
                self._remaining -= 1
                return SimpleNamespace(
                    usage=None,
                    choices=[
                        SimpleNamespace(
                            delta=SimpleNamespace(
                                content="token",
                                reasoning_content=None,
                                thinking=None,
                                reasoning=None,
                                tool_calls=[],
                            ),
                            finish_reason="stop",
                        )
                    ],
                )

        class _FakeHTTPClient:
            def __init__(self, **kwargs: Any) -> None:
                self._transport = kwargs["transport"]
                self.closed = False

            async def aclose(self) -> None:
                self.closed = True

        class _FakeSDK:
            def __init__(self, http_client: _FakeHTTPClient) -> None:
                self._client = http_client
                self.chat = SimpleNamespace(
                    completions=SimpleNamespace(create=self._chat_create)
                )
                self.models = SimpleNamespace(list=self._models_list)
                self.embeddings = SimpleNamespace(create=self._embed_create)

            def _record(self, kind: str, model: str | None = None) -> None:
                calls.append((kind, model, id(self), id(self._client)))

            async def _chat_create(self, **kwargs: Any) -> Any:
                model = kwargs.get("model")
                self._record("stream" if kwargs.get("stream") else "chat", model)
                if kwargs.get("stream"):
                    return _MemoryStream()
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
                    model=model,
                )

            async def _models_list(self) -> list[Any]:
                self._record("health")
                return []

            async def _embed_create(self, **kwargs: Any) -> Any:
                self._record("embed", kwargs.get("model"))
                return SimpleNamespace(data=[SimpleNamespace(embedding=[0.25, 0.75])])

            async def close(self) -> None:
                await self._client.aclose()

        http_clients: list[_FakeHTTPClient] = []
        sdk_clients: list[_FakeSDK] = []

        def make_http_client(**kwargs: Any) -> _FakeHTTPClient:
            client = _FakeHTTPClient(**kwargs)
            http_clients.append(client)
            return client

        def make_sdk(**kwargs: Any) -> _FakeSDK:
            sdk = _FakeSDK(kwargs["http_client"])
            sdk_clients.append(sdk)
            return sdk

        provider = OpenAICompatibleProvider(
            ModelProviderConfig(
                name="test",
                base_url="https://api.example.com/v1",
            )
        )
        messages = [ChatMessage(role="user", content="hello")]
        with (
            patch(
                "js.security.net_guard.resolve_and_validate_provider_endpoint",
                return_value=["93.184.216.34"],
            ) as resolver,
            patch("js.models.providers.httpx.AsyncClient", side_effect=make_http_client),
            patch("js.models.providers.AsyncOpenAI", side_effect=make_sdk),
        ):
            assert (await provider.chat(messages, model="chat-model")).content == "ok"
            assert [item async for item in provider.chat_stream(messages, "legacy-model")] == [
                "token"
            ]
            events = [
                event
                async for event in provider.chat_stream_events(messages, "events-model")
            ]
            assert [event.kind for event in events] == ["text_delta", "done"]
            assert await provider.health_check() is True
            with pytest.raises(PermissionError, match="remote embedding is disabled"):
                await provider.embed(["x"], model="embed-model")

        resolver.assert_called_once()
        assert resolver.call_args.args[0] == "https://api.example.com/v1"
        assert len(http_clients) == len(sdk_clients) == 1
        assert provider.client is sdk_clients[0]
        assert provider._http_client is http_clients[0]
        assert sdk_clients[0]._client is provider._http_client
        assert provider._http_client._transport is provider._pinned_transport
        assert isinstance(provider._pinned_transport, PinnedTransport)
        assert {entry[2] for entry in calls} == {id(provider.client)}
        assert {entry[3] for entry in calls} == {id(provider._http_client)}
        assert [(kind, model) for kind, model, *_ids in calls] == [
            ("chat", "chat-model"),
            ("stream", "legacy-model"),
            ("stream", "events-model"),
            ("health", None),
        ]
        await provider.close()

    @pytest.mark.asyncio
    async def test_loopback_embed_shares_one_injected_pinned_client(self) -> None:
        from js.config import ModelProviderConfig
        from js.models.providers import OpenAICompatibleProvider

        http_clients: list[Any] = []
        sdk_clients: list[Any] = []

        class _FakeHTTPClient:
            def __init__(self, **kwargs: Any) -> None:
                self._transport = kwargs["transport"]

            async def aclose(self) -> None:
                return None

        class _FakeSDK:
            def __init__(self, http_client: _FakeHTTPClient) -> None:
                self._client = http_client
                self.embeddings = SimpleNamespace(create=self._embed_create)

            async def _embed_create(self, **kwargs: Any) -> Any:
                del kwargs
                return SimpleNamespace(data=[SimpleNamespace(embedding=[0.25, 0.75])])

            async def close(self) -> None:
                return None

        def make_http_client(**kwargs: Any) -> _FakeHTTPClient:
            client = _FakeHTTPClient(**kwargs)
            http_clients.append(client)
            return client

        def make_sdk(**kwargs: Any) -> _FakeSDK:
            sdk = _FakeSDK(kwargs["http_client"])
            sdk_clients.append(sdk)
            return sdk

        provider = OpenAICompatibleProvider(
            ModelProviderConfig(
                name="local",
                base_url="http://127.0.0.1:1234/v1",
            )
        )
        with (
            patch(
                "js.security.net_guard.resolve_and_validate_provider_endpoint",
                return_value=["127.0.0.1"],
            ) as resolver,
            patch("js.models.providers.httpx.AsyncClient", side_effect=make_http_client),
            patch("js.models.providers.AsyncOpenAI", side_effect=make_sdk),
        ):
            assert await provider.embed(["x"], model="embed-model") == [[0.25, 0.75]]
            assert await provider.embed(["y"], model="embed-model") == [[0.25, 0.75]]

        resolver.assert_called_once()
        assert resolver.call_args.args[0] == "http://127.0.0.1:1234/v1"
        assert len(http_clients) == len(sdk_clients) == 1
        assert provider.client is sdk_clients[0]
        assert provider._http_client is http_clients[0]
        assert isinstance(provider._pinned_transport, PinnedTransport)
        await provider.close()

    @pytest.mark.asyncio
    async def test_suspended_stream_releases_before_provider_client_closes(self) -> None:
        from js.config import ModelProviderConfig
        from js.models.providers import ChatMessage, OpenAICompatibleProvider

        close_order: list[str] = []

        class _SuspendedStream:
            def __init__(self) -> None:
                self._remaining = 1

            async def __aenter__(self) -> _SuspendedStream:
                return self

            async def __aexit__(self, *_args: Any) -> None:
                close_order.append("stream_aclose")

            def __aiter__(self) -> _SuspendedStream:
                return self

            async def __anext__(self) -> Any:
                if not self._remaining:
                    raise StopAsyncIteration
                self._remaining -= 1
                return SimpleNamespace(
                    usage=None,
                    choices=[
                        SimpleNamespace(
                            delta=SimpleNamespace(content="token"),
                            finish_reason=None,
                        )
                    ],
                )

        class _FakeSDK:
            def __init__(self) -> None:
                self.chat = SimpleNamespace(
                    completions=SimpleNamespace(create=self._create)
                )

            async def _create(self, **_kwargs: Any) -> _SuspendedStream:
                return _SuspendedStream()

            async def close(self) -> None:
                close_order.append("sdk_close")

        provider = OpenAICompatibleProvider(
            ModelProviderConfig(name="test", base_url="https://api.example.com/v1")
        )
        provider.client = _FakeSDK()  # type: ignore[assignment]
        stream = provider.chat_stream(
            [ChatMessage(role="user", content="hello")],
            "stream-model",
        )
        assert await stream.__anext__() == "token"
        closing = asyncio.create_task(provider.close())
        await asyncio.sleep(0)
        assert not closing.done()
        assert close_order == []
        await stream.aclose()
        await asyncio.wait_for(closing, timeout=1.0)
        assert close_order == ["stream_aclose", "sdk_close"]

    @pytest.mark.asyncio
    async def test_cancelled_waiters_do_not_cancel_shared_init_or_close(self) -> None:
        from js.config import ModelProviderConfig
        from js.models.providers import OpenAICompatibleProvider

        entered = asyncio.Event()
        release = asyncio.Event()
        resolve_count = 0
        close_count = 0

        async def controlled_resolution(
            _resolver: Any, *_args: Any, **_kwargs: Any
        ) -> list[str]:
            nonlocal resolve_count
            resolve_count += 1
            entered.set()
            await release.wait()
            return ["93.184.216.34"]

        class _FakeSDK:
            async def close(self) -> None:
                nonlocal close_count
                close_count += 1

        provider = OpenAICompatibleProvider(
            ModelProviderConfig(name="test", base_url="https://api.example.com/v1")
        )
        with (
            patch(
                "js.models.providers.asyncio.to_thread",
                new_callable=AsyncMock,
                side_effect=controlled_resolution,
            ),
            patch("js.models.providers.AsyncOpenAI", return_value=_FakeSDK()),
        ):
            first = asyncio.create_task(provider._ensure_client())
            second = asyncio.create_task(provider._ensure_client())
            await asyncio.wait_for(entered.wait(), timeout=1.0)
            await asyncio.sleep(0)
            first.cancel()
            with pytest.raises(asyncio.CancelledError):
                await first
            release.set()
            assert await asyncio.wait_for(second, timeout=1.0) is provider.client
            assert resolve_count == 1

        async with provider._operation_lease():
            close_waiter = asyncio.create_task(provider.close())
            await asyncio.sleep(0)
            close_waiter.cancel()
            with pytest.raises(asyncio.CancelledError):
                await close_waiter
            assert close_count == 0
        await asyncio.wait_for(provider.close(), timeout=1.0)
        assert close_count == 1

    @pytest.mark.asyncio
    async def test_async_close_supports_legacy_fixture_without_client_lock(self) -> None:
        from js.models.providers import OpenAICompatibleProvider

        close_count = 0

        class _FakeSDK:
            async def close(self) -> None:
                nonlocal close_count
                close_count += 1

        provider = OpenAICompatibleProvider.__new__(OpenAICompatibleProvider)
        provider.client = _FakeSDK()  # type: ignore[assignment]

        await provider.close()

        assert close_count == 1
        assert provider.client is None

    @pytest.mark.asyncio
    async def test_async_close_failure_preserves_client_and_can_retry(self) -> None:
        from js.config import ModelProviderConfig
        from js.models.providers import OpenAICompatibleProvider

        close_count = 0

        class _FlakySDK:
            async def close(self) -> None:
                nonlocal close_count
                close_count += 1
                if close_count == 1:
                    raise asyncio.CancelledError

        provider = OpenAICompatibleProvider(
            ModelProviderConfig(name="test", base_url="https://api.example.com/v1")
        )
        sdk = _FlakySDK()
        provider.client = sdk  # type: ignore[assignment]

        with pytest.raises(asyncio.CancelledError):
            await provider.close()
        assert provider.client is sdk

        await provider.close()
        assert close_count == 2
        assert provider.client is None

    @pytest.mark.asyncio
    async def test_async_close_failure_is_shared_by_concurrent_waiters(self) -> None:
        from js.config import ModelProviderConfig
        from js.models.providers import OpenAICompatibleProvider

        entered = asyncio.Event()
        release = asyncio.Event()
        fail = True
        close_count = 0

        class _FlakySDK:
            async def close(self) -> None:
                nonlocal close_count
                close_count += 1
                entered.set()
                await release.wait()
                if fail:
                    raise RuntimeError("synthetic async close failure")

        provider = OpenAICompatibleProvider(
            ModelProviderConfig(name="test", base_url="https://api.example.com/v1")
        )
        sdk = _FlakySDK()
        provider.client = sdk  # type: ignore[assignment]

        first = asyncio.create_task(provider.close())
        await asyncio.wait_for(entered.wait(), timeout=1.0)
        second = asyncio.create_task(provider.close())
        release.set()
        outcomes = await asyncio.gather(first, second, return_exceptions=True)

        assert [type(outcome) for outcome in outcomes] == [RuntimeError, RuntimeError]
        assert [str(outcome) for outcome in outcomes] == [
            "synthetic async close failure",
            "synthetic async close failure",
        ]
        assert close_count == 1
        assert provider.client is sdk

        fail = False
        await provider.close()
        assert close_count == 2
        assert provider.client is None

    def test_sync_close_supports_legacy_fixture_without_client_lock(self) -> None:
        from js.memory.embeddings import LLMEmbedder

        close_count = 0

        class _FakeClient:
            def close(self) -> None:
                nonlocal close_count
                close_count += 1

        embedder = LLMEmbedder.__new__(LLMEmbedder)
        embedder.client = _FakeClient()  # type: ignore[assignment]
        embedder._closed = False

        embedder.close()

        assert close_count == 1
        assert embedder.client is None

    def test_sync_close_failure_is_shared_and_retry_preserves_client(self) -> None:
        from js.memory.embeddings import LLMEmbedder

        entered = threading.Event()
        release = threading.Event()
        fail = True
        close_count = 0

        class _FlakyClient:
            def close(self) -> None:
                nonlocal close_count
                close_count += 1
                entered.set()
                assert release.wait(1.0)
                if fail:
                    raise RuntimeError("synthetic close failure")

        embedder = LLMEmbedder(
            "https://api.example.com/v1",
            "synthetic-key",
        )
        client = _FlakyClient()
        embedder.client = client  # type: ignore[assignment]
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(embedder.close)
            assert entered.wait(1.0)
            second = pool.submit(embedder.close)
            release.set()
            failures = []
            for future in (first, second):
                with pytest.raises(RuntimeError, match="synthetic close failure") as exc:
                    future.result(1.0)
                failures.append(str(exc.value))

        assert failures == ["synthetic close failure", "synthetic close failure"]
        assert embedder.client is client

        fail = False
        embedder.close()
        assert close_count == 2
        assert embedder.client is None

    @pytest.mark.asyncio
    async def test_health_check_enters_through_lazy_pinned_client(self) -> None:
        from js.config import ModelProviderConfig
        from js.models.providers import OpenAICompatibleProvider

        provider = OpenAICompatibleProvider.__new__(OpenAICompatibleProvider)
        provider.config = ModelProviderConfig(
            name="test",
            base_url="https://api.example.com/v1",
        )
        provider._is_local = False
        provider._last_health_check = 0.0
        provider._health_status = False
        provider._health_lock = asyncio.Lock()
        fake_client = MagicMock()
        fake_client.models.list = AsyncMock(return_value=[])
        provider._ensure_client = AsyncMock(return_value=fake_client)

        assert await provider.health_check() is True
        provider._ensure_client.assert_awaited_once()


# ---------------------------------------------------------------------------
# 5. DNS rebinding defense
# ---------------------------------------------------------------------------


class TestDNSRebindingDefense:
    """The connection must use the pinned IP from the first validated resolution."""

    @pytest.mark.asyncio
    async def test_pinned_ip_ignores_subsequent_dns_changes(self) -> None:
        validated_ips = resolve_and_validate(
            "https://rebinding.example/",
            resolver=_mock_resolver({"rebinding.example": ["1.2.3.4"]}),
        )
        assert validated_ips == ["1.2.3.4"]

        mock_backend = AsyncMock()
        mock_stream = MagicMock()
        mock_backend.connect_tcp = AsyncMock(return_value=mock_stream)

        pinned = PinnedIPBackend("1.2.3.4", backend=mock_backend)
        await pinned.connect_tcp("rebinding.example", 80, timeout=5.0)

        mock_backend.connect_tcp.assert_awaited_once_with(
            "1.2.3.4", 80, 5.0, None, None
        )

    @pytest.mark.asyncio
    async def test_provider_pinned_transport_uses_validated_ip(self) -> None:
        from js.config import ModelProviderConfig
        from js.models.providers import OpenAICompatibleProvider

        with (
            patch(
                "js.security.net_guard.resolve_and_validate_provider_endpoint",
                return_value=["93.184.216.34"],
            ),
        ):
            provider = OpenAICompatibleProvider(
                ModelProviderConfig(
                    name="test",
                    base_url="https://api.example.com/v1",
                )
            )
            await provider._ensure_client()
            assert provider._validated_ips == ("93.184.216.34",)
            transport = provider._http_client._transport
            backend = transport._pool._network_backend
            assert backend.pinned_ip == "93.184.216.34"
            await provider.close()


# ---------------------------------------------------------------------------
# 6. Public IPv6 allowed
# ---------------------------------------------------------------------------


class TestPublicIPv6:
    def test_public_ipv6_allowed(self) -> None:
        resolver = _mock_resolver({"v6.example": ["2606:4700:4700::1111"]})
        ips = resolve_and_validate(
            "https://v6.example/",
            resolver=resolver,
        )
        assert "2606:4700:4700::1111" in ips

    def test_ipv4_mapped_ipv6_treated_as_ipv4(self) -> None:
        """::ffff:127.0.0.1 must be treated as loopback."""
        resolver = _mock_resolver({"mapped.example": ["::ffff:127.0.0.1"]})
        with pytest.raises(OutboundURLError, match="loopback"):
            resolve_and_validate(
                "https://mapped.example/",
                allow_loopback=False,
                resolver=resolver,
            )

    def test_domain_cannot_gain_loopback_exemption_from_caller_flag(self) -> None:
        resolver = _mock_resolver({"localhost": ["127.0.0.1"]})
        with pytest.raises(OutboundURLError, match="loopback"):
            resolve_and_validate(
                "https://localhost:1234/v1",
                allow_loopback=True,
                resolver=resolver,
            )

    @pytest.mark.parametrize(
        "host",
        [
            "127.0.0.1.",
            "127.0.0.1..",
            "0:0:0:0:0:0:0:1",
            "::1%lo0",
            "::ffff:127.0.0.1",
        ],
    )
    def test_noncanonical_loopback_text_is_not_literal(self, host: str) -> None:
        from js.security.net_guard import is_canonical_loopback_literal

        assert is_canonical_loopback_literal(host) is False

    def test_ipv6_loopback_allowed(self) -> None:
        ips = resolve_and_validate("http://[::1]:1234/v1", allow_loopback=True)
        assert "::1" in ips


# ---------------------------------------------------------------------------
# 7. Redirects forbidden
# ---------------------------------------------------------------------------


class TestRedirectsForbidden:
    """Provider HTTP clients must have follow_redirects=False."""

    @pytest.mark.asyncio
    async def test_provider_http_client_no_redirects(self) -> None:
        from js.config import ModelProviderConfig
        from js.models.providers import OpenAICompatibleProvider

        with (
            patch(
                "js.security.net_guard.resolve_and_validate_provider_endpoint",
                return_value=["93.184.216.34"],
            ),
        ):
            provider = OpenAICompatibleProvider(
                ModelProviderConfig(
                    name="test",
                    base_url="https://api.example.com/v1",
                )
            )
            await provider._ensure_client()
            http_client = provider._http_client
            assert http_client is not None
            assert http_client.follow_redirects is False
            await provider.close()

    @pytest.mark.asyncio
    async def test_discover_models_client_no_redirects(self) -> None:
        from js.models.provider_manager import ProviderManager

        captured_kwargs: dict[str, Any] = {}

        class _CaptureClient:
            async def __aenter__(self) -> _CaptureClient:
                return self

            async def __aexit__(self, *args: Any) -> None:
                pass

            async def get(self, *args: Any, **kwargs: Any) -> Any:
                mock_resp = MagicMock()
                mock_resp.status_code = 200
                mock_resp.json.return_value = {"data": []}
                mock_resp.raise_for_status = MagicMock()
                return mock_resp

        def capture_client(**kwargs: Any) -> _CaptureClient:
            captured_kwargs.update(kwargs)
            return _CaptureClient()

        with (
            patch(
                "js.security.net_guard.resolve_and_validate_provider_endpoint",
                return_value=["93.184.216.34"],
            ),
            patch("js.security.net_guard.PinnedTransport", return_value=MagicMock()),
            patch("httpx.AsyncClient", side_effect=capture_client),
        ):
            await ProviderManager.discover_models("https://api.example.com/v1")

        assert captured_kwargs.get("follow_redirects") is False

    @pytest.mark.asyncio
    async def test_probe_provider_client_no_redirects(self) -> None:
        from js.models.capability import probe_provider

        captured_kwargs: dict[str, Any] = {}

        class _CaptureClient:
            async def __aenter__(self) -> _CaptureClient:
                return self

            async def __aexit__(self, *args: Any) -> None:
                pass

            async def get(self, *args: Any, **kwargs: Any) -> Any:
                mock_resp = MagicMock()
                mock_resp.status_code = 200
                mock_resp.json.return_value = {"data": [{"id": "m1"}]}
                mock_resp.raise_for_status = MagicMock()
                return mock_resp

        def capture_client(**kwargs: Any) -> _CaptureClient:
            captured_kwargs.update(kwargs)
            return _CaptureClient()

        with (
            patch(
                "js.security.net_guard.resolve_and_validate_provider_endpoint",
                return_value=["93.184.216.34"],
            ),
            patch("js.security.net_guard.PinnedTransport", return_value=MagicMock()),
            patch("httpx.AsyncClient", side_effect=capture_client),
        ):
            await probe_provider("https://api.example.com/v1", "sk-test")

        assert captured_kwargs.get("follow_redirects") is False

    @pytest.mark.asyncio
    @pytest.mark.parametrize("status_code", range(300, 400))
    async def test_probe_provider_rejects_redirect_response_without_second_request(
        self, status_code: int
    ) -> None:
        from js.models.capability import probe_provider

        requests: list[str] = []

        class _RedirectClient:
            async def __aenter__(self) -> _RedirectClient:
                return self

            async def __aexit__(self, *args: Any) -> None:
                return None

            async def get(self, url: str, **_kwargs: Any) -> Any:
                requests.append(url)
                response = MagicMock()
                response.status_code = status_code
                response.is_redirect = True
                response.headers = {"location": "http://169.254.169.254/latest"}
                response.text = '{"data":[{"id":"looks-valid"}]}'
                response.json.return_value = {"data": [{"id": "looks-valid"}]}
                return response

        with (
            patch(
                "js.security.net_guard.resolve_and_validate_provider_endpoint",
                return_value=["93.184.216.34"],
            ),
            patch("js.security.net_guard.PinnedTransport", return_value=MagicMock()),
            patch("httpx.AsyncClient", return_value=_RedirectClient()),
        ):
            result = await probe_provider("https://api.example.com/v1", "sk-test")

        assert result.ok is False
        assert result.status == status_code
        assert result.error == "redirects are not allowed"
        assert requests == ["https://api.example.com/v1/models"]


# ---------------------------------------------------------------------------
# 8. trust_env / verify / follow_redirects on all clients
# ---------------------------------------------------------------------------


class TestClientSecurityAttributes:
    """All HTTP clients must have trust_env=False, verify=True, follow_redirects=False."""

    @pytest.mark.asyncio
    async def test_provider_http_client_attributes(self) -> None:
        from js.config import ModelProviderConfig
        from js.models.providers import OpenAICompatibleProvider

        with (
            patch(
                "js.security.net_guard.resolve_and_validate_provider_endpoint",
                return_value=["93.184.216.34"],
            ),
        ):
            provider = OpenAICompatibleProvider(
                ModelProviderConfig(
                    name="test",
                    base_url="https://api.example.com/v1",
                )
            )
            await provider._ensure_client()
            http_client = provider._http_client
            assert http_client is not None
            assert http_client.follow_redirects is False
            # trust_env must be False
            assert http_client.trust_env is False
            await provider.close()

    @pytest.mark.asyncio
    async def test_discover_models_client_attributes(self) -> None:
        from js.models.provider_manager import ProviderManager

        captured_kwargs: dict[str, Any] = {}

        class _CaptureClient:
            async def __aenter__(self) -> _CaptureClient:
                return self

            async def __aexit__(self, *args: Any) -> None:
                pass

            async def get(self, *args: Any, **kwargs: Any) -> Any:
                mock_resp = MagicMock()
                mock_resp.status_code = 200
                mock_resp.json.return_value = {"data": []}
                mock_resp.raise_for_status = MagicMock()
                return mock_resp

        def capture_client(**kwargs: Any) -> _CaptureClient:
            captured_kwargs.update(kwargs)
            return _CaptureClient()

        with (
            patch(
                "js.security.net_guard.resolve_and_validate_provider_endpoint",
                return_value=["93.184.216.34"],
            ),
            patch("js.security.net_guard.PinnedTransport", return_value=MagicMock()),
            patch("httpx.AsyncClient", side_effect=capture_client),
        ):
            await ProviderManager.discover_models("https://api.example.com/v1")

        assert captured_kwargs.get("trust_env") is False
        assert captured_kwargs.get("follow_redirects") is False

    @pytest.mark.asyncio
    async def test_probe_provider_client_attributes(self) -> None:
        from js.models.capability import probe_provider

        captured_kwargs: dict[str, Any] = {}

        class _CaptureClient:
            async def __aenter__(self) -> _CaptureClient:
                return self

            async def __aexit__(self, *args: Any) -> None:
                pass

            async def get(self, *args: Any, **kwargs: Any) -> Any:
                mock_resp = MagicMock()
                mock_resp.status_code = 200
                mock_resp.json.return_value = {"data": [{"id": "m1"}]}
                mock_resp.raise_for_status = MagicMock()
                return mock_resp

        def capture_client(**kwargs: Any) -> _CaptureClient:
            captured_kwargs.update(kwargs)
            return _CaptureClient()

        with (
            patch(
                "js.security.net_guard.resolve_and_validate_provider_endpoint",
                return_value=["93.184.216.34"],
            ),
            patch("js.security.net_guard.PinnedTransport", return_value=MagicMock()),
            patch("httpx.AsyncClient", side_effect=capture_client),
        ):
            await probe_provider("https://api.example.com/v1", "sk-test")

        assert captured_kwargs.get("trust_env") is False
        assert captured_kwargs.get("follow_redirects") is False


# ---------------------------------------------------------------------------
# 9. Synchronous embedding uses pinned transport
# ---------------------------------------------------------------------------


class TestSyncEmbeddingPin:
    """LLMEmbedder must use a pinned transport for its synchronous httpx.Client."""

    def test_llm_embedder_remote_endpoint_fail_closed_before_dns(self) -> None:
        from js.memory.embeddings import LLMEmbedder

        with (
            patch(
                "js.security.net_guard.resolve_and_validate_provider_endpoint",
                return_value=["93.184.216.34"],
            ) as resolver,
            patch("js.memory.embeddings.httpx.Client") as client_factory,
        ):
            emb = LLMEmbedder(
                base_url="https://api.example.com/v1",
                api_key="sk-test",
            )
            with pytest.raises(PermissionError, match="remote embedding is disabled"):
                emb._ensure_client()
            with pytest.raises(PermissionError, match="remote embedding is disabled"):
                emb.embed("hello")
            resolver.assert_not_called()
            client_factory.assert_not_called()

    def test_llm_embedder_uses_pinned_transport(self) -> None:
        from js.memory.embeddings import LLMEmbedder

        with (
            patch(
                "js.security.net_guard.resolve_and_validate_provider_endpoint",
                return_value=["93.184.216.34"],
            ),
        ):
            emb = LLMEmbedder(
                base_url="http://127.0.0.1:1234/v1",
                api_key="sk-test",
            )
            assert emb.client is None
            client = emb._ensure_client()
            assert isinstance(client._transport, httpx.HTTPTransport)
            assert client._transport._pool._network_backend.pinned_ip == "93.184.216.34"
            emb.close()

    def test_llm_embedder_is_lazy_and_dns_failure_has_no_plain_fallback(self) -> None:
        from js.memory.embeddings import LLMEmbedder

        with (
            patch(
                "js.security.net_guard.resolve_and_validate_provider_endpoint",
                side_effect=OutboundURLError("blocked embedding destination"),
            ) as resolver,
            patch("js.memory.embeddings.httpx.Client") as client_factory,
        ):
            emb = LLMEmbedder(
                base_url="http://127.0.0.1:1234/v1",
                api_key="sk-test",
            )
            resolver.assert_not_called()
            assert emb.client is None
            with pytest.raises(OutboundURLError, match="blocked"):
                emb._ensure_client()
            client_factory.assert_not_called()

    def test_llm_embedder_rejects_remote_http(self) -> None:
        from js.memory.embeddings import LLMEmbedder

        with pytest.raises(OutboundURLError):
            LLMEmbedder(base_url="http://93.184.216.34/v1", api_key="sk-test")

    def test_llm_embedder_no_redirects_no_env(self) -> None:
        from js.memory.embeddings import LLMEmbedder

        with (
            patch(
                "js.security.net_guard.resolve_and_validate_provider_endpoint",
                return_value=["93.184.216.34"],
            ),
        ):
            emb = LLMEmbedder(
                base_url="http://127.0.0.1:1234/v1",
                api_key="sk-test",
            )
            client = emb._ensure_client()
            assert client.follow_redirects is False
            assert client.trust_env is False
            emb.close()

    def test_closed_embedder_cannot_recreate_a_network_client(self) -> None:
        from js.memory.embeddings import LLMEmbedder

        with patch(
            "js.security.net_guard.resolve_and_validate_provider_endpoint",
            return_value=["93.184.216.34"],
        ) as resolver:
            emb = LLMEmbedder(
                base_url="http://127.0.0.1:1234/v1",
                api_key="sk-test",
            )
            emb.close()
            with pytest.raises(RuntimeError, match="closed"):
                emb._ensure_client()
            resolver.assert_not_called()


# ---------------------------------------------------------------------------
# 10. Real async backend type
# ---------------------------------------------------------------------------


class TestRealAsyncBackend:
    """PinnedIPBackend must use a working AnyIOBackend, not the abstract base."""

    def test_pinned_backend_uses_real_backend(self) -> None:
        backend = PinnedIPBackend("1.2.3.4")
        inner = backend._backend
        assert isinstance(inner, httpcore.AsyncNetworkBackend)
        assert type(inner) is not httpcore.AsyncNetworkBackend

    def test_pinned_backend_not_abstract_base(self) -> None:
        backend = PinnedIPBackend("1.2.3.4")
        inner = backend._backend
        assert type(inner) is not httpcore.AsyncNetworkBackend

    def test_pinned_transport_uses_real_backend(self) -> None:
        transport = PinnedTransport("1.2.3.4", verify=False)
        pool = transport._pool
        backend = getattr(pool, "_network_backend", None)
        assert backend is not None
        assert isinstance(backend, PinnedIPBackend)
        inner = backend._backend
        assert isinstance(inner, httpcore.AsyncNetworkBackend)
        assert type(inner) is not httpcore.AsyncNetworkBackend

    @pytest.mark.parametrize("transport_type", [PinnedTransport, PinnedSyncTransport])
    def test_transport_forces_no_environment_ca_even_if_caller_requests_it(
        self, transport_type: type[PinnedTransport] | type[PinnedSyncTransport]
    ) -> None:
        captured: list[dict[str, Any]] = []

        def capture_context(**kwargs: Any) -> ssl.SSLContext:
            captured.append(dict(kwargs))
            return ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

        with patch(
            "httpx._transports.default.create_ssl_context",
            side_effect=capture_context,
        ):
            transport = transport_type("93.184.216.34", trust_env=True, verify=True)
        assert captured == [{"verify": True, "cert": None, "trust_env": False}]
        if isinstance(transport, PinnedTransport):
            asyncio.run(transport.aclose())
        else:
            transport.close()

    @pytest.mark.asyncio
    async def test_async_pin_preserves_sni_host_and_certificate_verification(self) -> None:
        stream = _AsyncTLSStream()
        backend = _AsyncTLSBackend(stream)
        transport = PinnedTransport("93.184.216.34", verify=True)
        transport._pool._network_backend._backend = backend
        async with httpx.AsyncClient(
            transport=transport,
            trust_env=False,
            follow_redirects=False,
        ) as client:
            response = await client.get("https://api.example.com:8443/v1/models")
        assert response.status_code == 200
        assert backend.calls[0][:2] == ("93.184.216.34", 8443)
        assert stream.server_hostname == "api.example.com"
        assert b"Host: api.example.com:8443\r\n" in b"".join(stream.writes)
        assert stream.ssl_context is not None
        assert stream.ssl_context.verify_mode == ssl.CERT_REQUIRED
        assert stream.ssl_context.check_hostname is True

    def test_sync_pin_preserves_sni_host_and_certificate_verification(self) -> None:
        stream = _SyncTLSStream()
        backend = _SyncTLSBackend(stream)
        transport = PinnedSyncTransport("93.184.216.34", verify=True)
        transport._pool._network_backend._backend = backend
        with httpx.Client(
            transport=transport,
            trust_env=False,
            follow_redirects=False,
        ) as client:
            response = client.get("https://api.example.com:8443/v1/models")
        assert response.status_code == 200
        assert backend.calls[0][:2] == ("93.184.216.34", 8443)
        assert stream.server_hostname == "api.example.com"
        assert b"Host: api.example.com:8443\r\n" in b"".join(stream.writes)
        assert stream.ssl_context is not None
        assert stream.ssl_context.verify_mode == ssl.CERT_REQUIRED
        assert stream.ssl_context.check_hostname is True


# ---------------------------------------------------------------------------
# URL canonicalization: no userinfo / query / fragment
# ---------------------------------------------------------------------------


class TestUrlCanonicalization:
    """URLs with userinfo, query, or fragment must be rejected."""

    def test_userinfo_rejected(self) -> None:
        with pytest.raises(OutboundURLError):
            resolve_and_validate_provider_endpoint("https://user:pass@example.com/v1")

    def test_empty_userinfo_rejected(self) -> None:
        with pytest.raises(OutboundURLError):
            resolve_and_validate_provider_endpoint("https://@example.com/v1")

    def test_fragment_rejected(self) -> None:
        with pytest.raises(OutboundURLError):
            resolve_and_validate_provider_endpoint("https://example.com/v1#frag")

    def test_query_rejected(self) -> None:
        with pytest.raises(OutboundURLError):
            resolve_and_validate_provider_endpoint("https://example.com/v1?token=secret")

    @pytest.mark.parametrize(
        "url",
        [
            "https://example.com/v1?",
            "https://example.com/v1#",
            "https://[::1",
            "https://[v1.invalid]/v1",
            "https://example.com：443/v1",
        ],
    )
    def test_empty_delimiters_and_malformed_authority_are_rejected(self, url: str) -> None:
        with pytest.raises(OutboundURLError):
            resolve_and_validate_provider_endpoint(url)

    @pytest.mark.parametrize(
        ("url", "host", "resolved"),
        [
            ("http://127.0.0.2:1234/v1", "127.0.0.2", "127.0.0.2"),
            ("http://[::1]:1234/v1", "::1", "::1"),
        ],
    )
    def test_provider_wrapper_allows_only_canonical_loopback_http(
        self, url: str, host: str, resolved: str
    ) -> None:
        resolver = _mock_resolver({host: [resolved]})
        assert resolve_and_validate_provider_endpoint(url, resolver=resolver) == [resolved]

    @pytest.mark.parametrize(
        "url",
        [
            "http://localhost:1234/v1",
            "http://127.1:1234/v1",
            "http://127.0.0.1.:1234/v1",
            "http://[0:0:0:0:0:0:0:1]:1234/v1",
            "http://[::ffff:127.0.0.1]:1234/v1",
        ],
    )
    def test_provider_wrapper_rejects_noncanonical_http_before_dns(self, url: str) -> None:
        resolver = MagicMock(return_value=["127.0.0.1"])
        with pytest.raises(OutboundURLError):
            resolve_and_validate_provider_endpoint(url, resolver=resolver)
        resolver.assert_not_called()

    def test_generic_guard_preserves_https_query_for_browser_callers(self) -> None:
        resolver = _mock_resolver({"example.com": ["93.184.216.34"]})
        assert resolve_and_validate(
            "https://example.com/search?q=hello",
            resolver=resolver,
        ) == ["93.184.216.34"]


# ---------------------------------------------------------------------------
# allow_private only from server settings
# ---------------------------------------------------------------------------


class TestAllowPrivateFromSettingsOnly:
    """allow_private must come from server settings, not provider payload."""

    def test_router_propagates_only_settings_authority(self) -> None:
        from types import SimpleNamespace

        from js.config import ModelProviderConfig
        from js.models.router import ModelRouter

        config = ModelProviderConfig(
            name="lan",
            base_url="https://10.0.0.2/v1",
        )
        router = ModelRouter.__new__(ModelRouter)
        router.settings = SimpleNamespace(
            providers=[config],
            security=SimpleNamespace(allow_private_model_providers=True),
        )
        router._providers = {}
        router._model_map = {}

        with patch("js.models.router.OpenAICompatibleProvider") as provider_factory:
            router._init_providers()

        provider_factory.assert_called_once_with(config, allow_private=True)
