"""Outbound URL safety guard — unified SSRF protection.

Every outbound HTTP(S) request initiated on behalf of untrusted input
(``browser_fetch``, WebBridge navigation, model discovery) must pass through
:func:`resolve_and_validate` first.

The guard does NOT trust the URL's literal host.  It resolves the hostname via
``getaddrinfo`` (following CNAME chains and the OS resolver's numeric-host
shortcuts) and then validates *every* resolved address.  This is what closes
the classic bypasses:

* ``127.1`` and ``2130706433`` — not valid ``ipaddress`` literals, but the
  resolver expands them to ``127.0.0.1``.
* ``127.0.0.1.nip.io`` / ``169.254.169.254.nip.io`` — wildcard-DNS domains that
  resolve to the embedded address.
* DNS rebinding — by validating the *resolved* IPs (and letting callers pin to
  them) rather than the hostname.

Cloud metadata endpoints (``169.254.169.254`` and friends) and link-local /
reserved / multicast / unspecified ranges are ALWAYS rejected, regardless of
the ``allow_loopback`` / ``allow_private`` policy flags.
"""

from __future__ import annotations

import ipaddress
import socket
import typing
from collections.abc import Callable
from typing import Protocol
from urllib.parse import urlparse

import httpcore
import httpx

__all__ = [
    "OutboundURLError",
    "resolve_and_validate",
    "resolve_and_validate_provider_endpoint",
    "is_blocked_ip",
    "is_canonical_loopback_literal",
    "PinnedIPBackend",
    "PinnedTransport",
    "PinnedSyncTransport",
    "validate_provider_url",
]

# Hostnames that must never be reachable even when loopback/private is allowed.
# These resolve to link-local (169.254.0.0/16) already, but block by name too
# in case a resolver returns something unexpected.
_BLOCKED_HOSTNAMES = frozenset(
    {
        "metadata.google.internal",
        "metadata",
    }
)

# Cloud metadata service addresses (always blocked).  169.254.169.254 is also
# link-local so it is caught by the range check; listed here for clarity and to
# cover the IPv6 form used by some providers.
_METADATA_ADDRESSES = frozenset(
    {
        "169.254.169.254",
        "fd00:ec2::254",
        "100.100.100.200",  # Alibaba Cloud metadata
    }
)

_PRIVATE_PROVIDER_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "fc00::/7",
    )
)

_ALWAYS_BLOCKED_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in (
        "0.0.0.0/8",
        "100.64.0.0/10",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "2001:db8::/32",
        "fec0::/10",
        "ff00::/8",
    )
)


class OutboundURLError(Exception):
    """Raised when an outbound URL fails the safety policy."""


class _Resolver(Protocol):
    def __call__(self, host: str, port: int | None) -> list[str]:
        """Return the list of IP address strings *host* resolves to."""
        ...


def _default_resolver(host: str, port: int | None) -> list[str]:
    """Resolve *host* to all A/AAAA addresses via the OS resolver."""
    infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    addrs: list[str] = []
    for info in infos:
        sockaddr = info[4]
        addr = str(sockaddr[0])
        if addr not in addrs:
            addrs.append(addr)
    return addrs


def is_canonical_loopback_literal(hostname: str) -> bool:
    """Return True if *hostname* is a canonical literal loopback address.

    Only bare IPv4 in 127.0.0.0/8 and bare IPv6 ``::1`` are recognised.
    ``localhost``, ``0.0.0.0``, ``127.1``, integer/hex encodings, and any
    domain containing ``localhost`` are NOT canonical literals and must go
    through DNS resolution.
    """
    host = hostname.lower()
    if host == "::1":
        return True
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    return (
        isinstance(addr, ipaddress.IPv4Address)
        and addr.is_loopback
        and host == str(addr)
    )


def validate_provider_url(url: str) -> str:
    """Validate a provider base_url and return the normalised form.

    Rejects URLs with userinfo, query, or fragment.  Rejects non-http/https
    schemes.  Returns the URL unchanged if it passes validation.
    """
    if not isinstance(url, str) or not url or len(url) > 4096:
        raise OutboundURLError("provider URL is invalid")
    if "\\" in url or any(ord(char) <= 0x20 or ord(char) == 0x7F for char in url):
        raise OutboundURLError("provider URL contains forbidden characters")
    if "?" in url:
        raise OutboundURLError("URL must not contain a query string")
    if "#" in url:
        raise OutboundURLError("URL must not contain a fragment")
    try:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        username = parsed.username
        password = parsed.password
        hostname = parsed.hostname
        _port = parsed.port
    except ValueError as exc:
        raise OutboundURLError("provider URL host or port is invalid") from exc
    if scheme not in ("http", "https"):
        raise OutboundURLError("URL must start with http:// or https://")
    if username is not None or password is not None:
        raise OutboundURLError("URL must not contain userinfo")
    if not parsed.netloc or not hostname:
        raise OutboundURLError("URL has no host")
    if "%" in hostname:
        raise OutboundURLError("provider URL host must not contain a zone identifier")
    authority = parsed.netloc.rsplit("@", 1)[-1]
    if authority.startswith("["):
        try:
            bracketed = ipaddress.ip_address(hostname)
        except ValueError as exc:
            raise OutboundURLError("provider URL has an invalid IP literal") from exc
        if not isinstance(bracketed, ipaddress.IPv6Address):
            raise OutboundURLError("provider URL has an invalid IP literal")
    if scheme == "http" and not is_canonical_loopback_literal(hostname):
        raise OutboundURLError(
            "HTTP is only allowed for canonical loopback addresses (127.0.0.0/8, ::1)"
        )
    return url


def is_blocked_ip(
    addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
    *,
    allow_loopback: bool,
    allow_private: bool,
) -> str | None:
    """Return a rejection reason for *addr*, or ``None`` if it is permitted.

    Link-local, reserved, multicast, unspecified and known metadata addresses
    are always rejected.  Loopback and private (RFC1918 / ULA) ranges are
    rejected unless explicitly allowed by the policy flags.
    """
    # Normalize IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1) to its IPv4 form so
    # the classification below isn't bypassed via the v6 representation.
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped

    if str(addr) in _METADATA_ADDRESSES:
        return "cloud metadata address is blocked"
    # Loopback is checked before reserved/private because IPv6 ::1 is
    # both is_loopback and is_reserved; the loopback policy must take
    # precedence so canonical ::1 is allowed when allow_loopback is set.
    if addr.is_loopback:
        return None if allow_loopback else "loopback address is blocked"
    if addr.is_link_local:
        return "link-local address is blocked"
    if addr.is_reserved:
        return "reserved address is blocked"
    if addr.is_multicast:
        return "multicast address is blocked"
    if addr.is_unspecified:
        return "unspecified address is blocked"
    if any(addr in network for network in _ALWAYS_BLOCKED_NETWORKS):
        return "non-routable or special-purpose address is blocked"
    if any(addr in network for network in _PRIVATE_PROVIDER_NETWORKS):
        return None if allow_private else "private/internal address is blocked"
    if not addr.is_global:
        return "non-global address is blocked"
    return None


def resolve_and_validate(
    url: str,
    *,
    allow_loopback: bool = False,
    allow_private: bool = False,
    resolver: Callable[[str, int | None], list[str]] | None = None,
) -> list[str]:
    """Validate *url* and return the list of safe resolved IP addresses.

    Raises :class:`OutboundURLError` if the scheme is unsupported, the host is
    missing/blocked, resolution fails, or *any* resolved address violates the
    policy (fail-closed: if one address is internal, the whole URL is rejected,
    which defeats split-horizon DNS tricks).  Provider-only URL shape rules
    such as forbidding query strings live in
    :func:`resolve_and_validate_provider_endpoint`; generic browser/search
    callers intentionally retain their existing query semantics here.

    The returned IP list lets callers pin the connection to a validated address
    to defeat DNS-rebinding between this check and the actual request.
    """
    try:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise OutboundURLError("URL host or port is invalid") from exc
    if scheme not in ("http", "https"):
        raise OutboundURLError("URL must start with http:// or https://")

    if not hostname:
        raise OutboundURLError("URL has no host")

    host_lower = hostname.lower().rstrip(".")
    effective_allow_loopback = allow_loopback and is_canonical_loopback_literal(hostname)

    if host_lower in _BLOCKED_HOSTNAMES:
        raise OutboundURLError("metadata hostname is blocked")

    resolve = resolver or _default_resolver
    try:
        resolved = resolve(hostname, port)
    except OutboundURLError:
        raise
    except Exception as exc:  # noqa: BLE001 — resolution failure is fail-closed
        raise OutboundURLError(f"could not resolve host: {exc}") from exc

    if not resolved:
        raise OutboundURLError("host did not resolve to any address")

    validated: list[str] = []
    for ip_str in resolved:
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError as exc:
            raise OutboundURLError(f"resolver returned invalid address {ip_str!r}") from exc
        reason = is_blocked_ip(
            addr,
            allow_loopback=effective_allow_loopback,
            allow_private=allow_private,
        )
        if reason is not None:
            raise OutboundURLError(f"blocked destination ({reason})")
        validated.append(ip_str)

    return validated


def resolve_and_validate_provider_endpoint(
    url: str,
    *,
    allow_private: bool = False,
    resolver: Callable[[str, int | None], list[str]] | None = None,
) -> list[str]:
    """Apply the stricter model-provider endpoint policy and resolve safely."""
    validate_provider_url(url)
    hostname = urlparse(url).hostname or ""
    literal_loopback = is_canonical_loopback_literal(hostname)
    return resolve_and_validate(
        url,
        allow_loopback=literal_loopback,
        allow_private=allow_private,
        resolver=resolver,
    )


# ── DNS-rebinding defense: pin connections to validated IPs ──

class PinnedIPBackend(httpcore.AsyncNetworkBackend):
    """Network backend that forces TCP connections to a pre-validated IP.

    When :func:`resolve_and_validate` returns a list of safe IPs, this backend
    ensures the *actual* TCP connection uses one of those IPs instead of
    re-resolving the hostname.  This closes the DNS-rebinding window where an
    attacker domain first resolves to a public IP (passing validation) and
    then rebinds to ``127.0.0.1`` or ``169.254.169.254`` before the HTTP
    request is made.

    The original hostname is preserved in the URL, so TLS SNI and the HTTP
    ``Host`` header remain correct — only the underlying TCP destination is
    pinned.
    """

    def __init__(
        self,
        pinned_ip: str,
        backend: httpcore.AsyncNetworkBackend | None = None,
    ) -> None:
        self.pinned_ip = pinned_ip
        self._backend = backend or httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: typing.Iterable[typing.Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        # Ignore the hostname and connect directly to the validated IP.
        # The original hostname is still used for TLS SNI and Host header
        # because the URL passed to httpx retains it.
        return await self._backend.connect_tcp(
            self.pinned_ip, port, timeout, local_address, socket_options
        )

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: typing.Iterable[typing.Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        return await self._backend.connect_unix_socket(path, timeout, socket_options)

    async def sleep(self, seconds: float) -> None:
        return await self._backend.sleep(seconds)


def create_pinned_transport(
    validated_ips: list[str],
    **pool_kwargs: typing.Any,
) -> httpcore.AsyncConnectionPool:
    """Create an :class:`httpcore.AsyncConnectionPool` pinned to *validated_ips*.

    The first IP in the list is used for the connection.  Callers should pass
    the returned pool as ``transport=`` to :class:`httpx.AsyncClient`.
    """
    if not validated_ips:
        raise OutboundURLError("no validated IPs to pin to")
    backend = PinnedIPBackend(validated_ips[0])
    return httpcore.AsyncConnectionPool(network_backend=backend, **pool_kwargs)


class PinnedTransport(httpx.AsyncHTTPTransport):
    """AsyncHTTPTransport that pins TCP connections to a pre-validated IP.

    Inherits from :class:`httpx.AsyncHTTPTransport` so mypy recognises it as a
    valid ``AsyncBaseTransport``.  The parent ``__init__`` is called first to
    create a default pool, then the pool is replaced with one that uses our
    :class:`PinnedIPBackend` so the TCP destination is pinned while the URL's
    original hostname is preserved for TLS SNI and the HTTP ``Host`` header.
    """

    def __init__(
        self,
        pinned_ip: str,
        **kwargs: typing.Any,
    ) -> None:
        # Client(trust_env=False) does not override a custom transport's
        # SSLContext construction, so enforce the no-environment invariant here.
        kwargs["trust_env"] = False
        super().__init__(**kwargs)
        # Replace the pool created by the parent with one that pins to the
        # validated IP.  We do not aclose the old pool here (__init__ is sync);
        # it will be garbage-collected and any idle connections reaped.
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=getattr(self._pool, "_ssl_context", None),
            max_connections=getattr(self._pool, "_max_connections", None),
            max_keepalive_connections=getattr(
                self._pool, "_max_keepalive_connections", None
            ),
            keepalive_expiry=getattr(self._pool, "_keepalive_expiry", None),
            http1=getattr(self._pool, "_http1", True),
            http2=getattr(self._pool, "_http2", False),
            local_address=getattr(self._pool, "_local_address", None),
            retries=getattr(self._pool, "_retries", 0),
            socket_options=getattr(self._pool, "_socket_options", None),
            network_backend=PinnedIPBackend(pinned_ip),
        )


def create_pinned_client(
    validated_ips: list[str],
    **client_kwargs: typing.Any,
) -> httpx.AsyncClient:
    """Create an :class:`httpx.AsyncClient` whose connections are pinned to
    the first validated IP.

    This is a convenience helper for the common case where a caller needs a
    one-off client with pinned transport.  For long-lived clients, use
    :class:`PinnedTransport` directly.
    """
    if not validated_ips:
        raise OutboundURLError("no validated IPs to pin to")
    return httpx.AsyncClient(transport=PinnedTransport(validated_ips[0]), **client_kwargs)


class PinnedSyncTransport(httpx.HTTPTransport):
    """Synchronous HTTPTransport that pins TCP connections to a pre-validated IP.

    Used by synchronous clients (e.g. :class:`js.memory.embeddings.LLMEmbedder`)
    so they share the same DNS-rebinding defense as async clients.
    """

    def __init__(
        self,
        pinned_ip: str,
        **kwargs: typing.Any,
    ) -> None:
        kwargs["trust_env"] = False
        super().__init__(**kwargs)
        self._pinned_ip = pinned_ip
        self._pool = httpcore.ConnectionPool(
            ssl_context=getattr(self._pool, "_ssl_context", None),
            max_connections=getattr(self._pool, "_max_connections", None),
            max_keepalive_connections=getattr(
                self._pool, "_max_keepalive_connections", None
            ),
            keepalive_expiry=getattr(self._pool, "_keepalive_expiry", None),
            http1=getattr(self._pool, "_http1", True),
            http2=getattr(self._pool, "_http2", False),
            local_address=getattr(self._pool, "_local_address", None),
            retries=getattr(self._pool, "_retries", 0),
            socket_options=getattr(self._pool, "_socket_options", None),
            network_backend=_PinnedSyncIPBackend(pinned_ip),
        )


class _PinnedSyncIPBackend(httpcore.NetworkBackend):
    """Synchronous network backend that forces TCP connections to a pinned IP."""

    def __init__(
        self,
        pinned_ip: str,
        backend: httpcore.NetworkBackend | None = None,
    ) -> None:
        self.pinned_ip = pinned_ip
        self._backend = backend or httpcore.SyncBackend()

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: typing.Iterable[typing.Any] | None = None,
    ) -> httpcore.NetworkStream:
        return self._backend.connect_tcp(
            self.pinned_ip, port, timeout, local_address, socket_options
        )

    def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: typing.Iterable[typing.Any] | None = None,
    ) -> httpcore.NetworkStream:
        return self._backend.connect_unix_socket(path, timeout, socket_options)

    def sleep(self, seconds: float) -> None:
        return self._backend.sleep(seconds)
