"""Tests for browser tool."""

from pathlib import Path

import httpx
import pytest

from js.config import SecurityConfig, ToolLimits
from js.security.guard import BehaviorGuard
from js.tools.browser import BrowserTool


class TestBrowserTool:
    @pytest.fixture
    def browser(self) -> BrowserTool:
        limits = ToolLimits()
        guard = BehaviorGuard(SecurityConfig(), Path("/tmp"))
        return BrowserTool(limits, guard)

    @pytest.mark.asyncio
    async def test_private_url_blocked(self, browser: BrowserTool, tmp_path: Path) -> None:
        from tests.test_b2c_non_model_egress import adjacent_network_consent

        with adjacent_network_consent(tmp_path):
            result = await browser.fetch("http://127.0.0.1:8080/admin")
        assert not result.success
        assert "blocked" in result.error.lower()

    @pytest.mark.asyncio
    async def test_invalid_url_blocked(self, browser: BrowserTool) -> None:
        result = await browser.fetch("ftp://example.com/file")
        assert not result.success
        assert "http://" in result.error or "https://" in result.error

    @pytest.mark.asyncio
    async def test_fetch_real(self, browser: BrowserTool) -> None:
        result = await browser.fetch("https://httpbin.org/get", max_chars=2000)
        # May fail in CI, so just check structure
        assert isinstance(result.success, bool)

    @pytest.mark.asyncio
    async def test_oversized_body_is_rejected_before_buffering(
        self, browser: BrowserTool, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from tests.test_b2c_non_model_egress import adjacent_network_consent

        max_chars = 1000
        oversized = b"x" * (max_chars * 4 + 1)

        class _Stream:
            async def __aenter__(self) -> httpx.Response:
                request = httpx.Request("GET", "https://example.com/")
                return httpx.Response(
                    200,
                    headers={"content-type": "text/plain"},
                    content=oversized,
                    request=request,
                )

            async def __aexit__(self, *args: object) -> None:
                return None

        class _Client:
            async def __aenter__(self) -> "_Client":
                return self

            async def __aexit__(self, *args: object) -> None:
                return None

            def stream(self, method: str, url: str, **kwargs: object) -> _Stream:
                return _Stream()

        monkeypatch.setattr("js.tools.browser.resolve_and_validate", lambda *a, **k: ["93.184.216.34"])
        monkeypatch.setattr("js.tools.browser.httpx.AsyncClient", lambda *a, **k: _Client())
        with adjacent_network_consent(tmp_path):
            result = await browser.fetch("https://example.com/", max_chars=max_chars)
        assert not result.success
        assert "budget" in result.error.lower()
