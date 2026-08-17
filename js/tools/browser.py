"""Simple browser/fetch tool for web content retrieval."""

from __future__ import annotations

import time
from typing import Any

import httpx

from js import __version__
from js.config import ToolLimits
from js.security.bounded_http import ResponseBudgetError, read_bounded_response
from js.security.guard import BehaviorGuard
from js.security.net_guard import OutboundURLError, PinnedTransport, resolve_and_validate
from js.tools.registry import ToolParam, ToolResult, ToolSpec


class BrowserTool:
    """Fetch and extract web content."""

    def __init__(self, limits: ToolLimits, guard: BehaviorGuard) -> None:
        self.limits = limits
        self.guard = guard
        self._client: httpx.AsyncClient | None = None

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.limits.browser_timeout),
                follow_redirects=False,  # Prevent redirect-based SSRF bypass
                headers={
                    "User-Agent": f"JS-Agent/{__version__} (Research Bot)",
                },
            )
        return self._client

    def get_specs(self) -> list[ToolSpec]:
        return [
            ToolSpec(
                name="browser_fetch",
                description="Fetch content from a URL. Returns text content up to max chars.",
                parameters=[
                    ToolParam("url", "string", "URL to fetch"),
                    ToolParam("max_chars", "integer", "Max characters to return", required=False),
                ],
                read_only=True,
            ),
        ]

    async def fetch(self, url: str, max_chars: int | None = None) -> ToolResult:
        max_chars = max_chars if max_chars is not None else self.limits.file_read_max_chars

        # Resolve the host and reject any internal/metadata destination.
        # This catches numeric-host (127.1, 2130706433), wildcard-DNS
        # (*.nip.io) and DNS-rebinding bypasses that a literal-only check misses.
        # We CAPTURE the validated IPs and pin the connection to them so the
        # hostname is NOT re-resolved between validation and the actual request.
        from js.security import egress as network_egress

        if network_egress.classify_network_endpoint_url(url if type(url) is str else "") == "invalid":
            return ToolResult(
                success=False,
                error="URL blocked: URL must start with http:// or https://",
            )
        try:
            auth = await network_egress.authorize_network_egress(
                kind=network_egress.NetworkEgressKind.BROWSER_FETCH,
                target_identity="browser_fetch",
                endpoint_url=url if type(url) is str else "",
                method="GET",
                payload={"url_digest": network_egress.digest_jsonable(url if type(url) is str else "")},
                provenance={
                    "schema": network_egress.NETWORK_PROVENANCE_SCHEMA,
                    "kind": "browser_fetch_egress",
                    "source": "browser_fetch",
                    "tool_name": "browser_fetch",
                },
                credential_generation="none",
            )
        except network_egress.EgressConsentError:
            return ToolResult(success=False, error="network egress consent required")
        try:
            network_egress.assert_network_authorization_fresh(auth)
        except network_egress.EgressConsentError:
            return ToolResult(success=False, error="network egress consent required")
        fetch_url = auth.snapshot.endpoint_url

        try:
            validated_ips = resolve_and_validate(
                fetch_url, allow_loopback=False, allow_private=False
            )
        except OutboundURLError as exc:
            return ToolResult(success=False, error=f"URL blocked: {exc}")

        max_bytes = min(max(1, max_chars) * 4, self.limits.file_read_max_chars * 4)
        deadline = time.monotonic() + float(self.limits.browser_timeout)
        try:
            async with (
                httpx.AsyncClient(
                    transport=PinnedTransport(
                        validated_ips[0],
                        verify=True,
                    ),
                    timeout=httpx.Timeout(self.limits.browser_timeout),
                    follow_redirects=False,  # Prevent redirect-based SSRF bypass
                    headers={
                        "User-Agent": f"JS-Agent/{__version__} (Research Bot)",
                    },
                ) as client,
                client.stream("GET", fetch_url) as response,
            ):
                if response.is_redirect:
                    return ToolResult(
                        success=False,
                        error="Redirects are not followed for security",
                    )
                bounded = await read_bounded_response(
                    response,
                    max_bytes=max_bytes,
                    deadline_monotonic=deadline,
                )
                bounded.raise_for_status()
                content = bounded.text
                if len(content) > max_chars:
                    content = content[:max_chars] + "\n... [truncated]"

                return ToolResult(
                    success=True,
                    output=content,
                    metadata={
                        "status_code": bounded.status_code,
                        "content_type": bounded.headers.get("content-type", "unknown"),
                        "url": str(response.url),
                    },
                )
        except ResponseBudgetError as e:
            return ToolResult(success=False, error=f"Response budget exceeded: {e}")
        except httpx.HTTPStatusError as e:
            return ToolResult(success=False, error=f"HTTP error {e.response.status_code}")
        except httpx.RequestError as e:
            return ToolResult(success=False, error=f"Request failed: {e}")
        except Exception as e:
            return ToolResult(success=False, error=f"Fetch error: {e}")

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()

    def register_all(self, registry: Any) -> None:
        specs = self.get_specs()
        registry.register(specs[0], self.fetch)
