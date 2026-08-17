"""Lightweight embedding providers for semantic memory search.

No external dependencies — uses deterministic hashing for keyword-based
vectors, with a pluggable interface for future transformer-based models.
"""

from __future__ import annotations

import hashlib
import json
import math
import threading
import time
from abc import ABC, abstractmethod
from collections.abc import Iterator
from concurrent.futures import Future
from contextlib import contextmanager
from dataclasses import dataclass
from typing import cast

import httpx

from js.security.net_guard import PinnedSyncTransport, is_canonical_loopback_literal
from js.utils.log import get_logger

logger = get_logger("js.memory.embeddings")


@dataclass
class EmbedderHealth:
    """Health status of an embedder."""

    provider: str
    active: bool
    failure_count: int = 0
    last_failure: float | None = None
    last_success: float | None = None
    fallback_provider: str | None = None


class Embedder(ABC):
    """Abstract embedding provider."""

    @abstractmethod
    def embed(self, text: str) -> list[float]:
        """Return a dense vector for the given text."""

    def embed_batch(self, texts: list[str]) -> list[list[float]]:
        """Embed multiple texts. Default: sequential embed()."""
        return [self.embed(t) for t in texts]

    def to_json(self, vec: list[float]) -> str:
        return json.dumps(vec)

    def from_json(self, raw: str) -> list[float]:
        return cast("list[float]", json.loads(raw))

    def health(self) -> EmbedderHealth:
        """Return health status. Override in subclasses for richer reporting."""
        return EmbedderHealth(provider=self.__class__.__name__, active=True)


def cosine_similarity(a: list[float], b: list[float]) -> float:
    """Compute cosine similarity between two vectors."""
    if len(a) != len(b):
        raise ValueError(f"Vector dimension mismatch: {len(a)} vs {len(b)}")
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    return dot  # Vectors are assumed normalized


class KeywordEmbedder(Embedder):
    """Deterministic keyword-frequency embedder using hash-based indexing.

    Each word is hashed to a fixed position in the vector, making
    embeddings reproducible without maintaining a vocabulary.
    """

    def __init__(self, dims: int = 256) -> None:
        self.dims = dims

    def embed(self, text: str) -> list[float]:
        vec = [0.0] * self.dims
        for word in text.lower().split():
            h = int(hashlib.md5(word.encode(), usedforsecurity=False).hexdigest(), 16)
            idx = h % self.dims
            vec[idx] += 1.0

        norm = math.sqrt(sum(v * v for v in vec))
        if norm > 0:
            vec = [v / norm for v in vec]
        return vec


class LLMEmbedder(Embedder):
    """Embedding provider using an OpenAI-compatible embeddings API.

    Uses a synchronous httpx client so it can be called from the
    synchronous MemoryStore methods.  Includes retry with exponential
    backoff for transient failures.

    Transport security: the base_url is validated through ``resolve_and_validate``
    and the connection is pinned to the first validated IP via
    :class:`js.security.net_guard.PinnedSyncTransport` to prevent DNS rebinding.
    HTTP is only allowed for canonical loopback addresses; all other URLs must
    use HTTPS.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        model: str = "text-embedding-3-small",
        dims: int | None = None,
        max_retries: int = 3,
        *,
        allow_private: bool = False,
    ) -> None:
        from js.security.net_guard import validate_provider_url

        validate_provider_url(base_url)
        self._base_url = base_url
        self._api_key = api_key
        self._allow_private = allow_private is True
        self._client_lock = threading.Lock()
        self._lifecycle_condition = threading.Condition()
        self._lifecycle_state = "OPEN"
        self._active_operations = 0
        self._close_future: Future[None] | None = None
        self._closed = False
        self.client: httpx.Client | None = None
        self.model = model
        self.dims = dims
        self.max_retries = max_retries
        self._failure_count = 0
        self._last_failure: float | None = None
        self._last_success: float | None = None

    def _require_literal_loopback(self) -> None:
        from urllib.parse import urlparse

        try:
            hostname = (urlparse(self._base_url).hostname or "").lower()
        except ValueError as exc:
            raise PermissionError("remote embedding is disabled") from exc
        if not is_canonical_loopback_literal(hostname):
            raise PermissionError("remote embedding is disabled")

    def _ensure_client(self) -> httpx.Client:
        self._require_literal_loopback()
        with self._client_lock:
            if self._closed:
                raise RuntimeError("embedder is closed")
            existing = self.client
            if existing is not None:
                return existing
            from js.security.net_guard import resolve_and_validate_provider_endpoint

            validated_ips = resolve_and_validate_provider_endpoint(
                self._base_url,
                allow_private=self._allow_private,
            )
            transport = PinnedSyncTransport(
                validated_ips[0],
                verify=True,
                trust_env=False,
            )
            client = httpx.Client(
                base_url=self._base_url,
                headers={"Authorization": f"Bearer {self._api_key}"},
                timeout=httpx.Timeout(30.0, connect=5.0),
                transport=transport,
                trust_env=False,
                follow_redirects=False,
            )
            self.client = client
            return client

    def embed(self, text: str) -> list[float]:
        result = self.embed_batch([text])
        return result[0]

    def _get_lifecycle_condition(self) -> threading.Condition:
        """Return lifecycle state, lazily initialising legacy test fixtures."""
        condition = getattr(self, "_lifecycle_condition", None)
        if condition is None:
            condition = threading.Condition()
            self._lifecycle_condition = condition
            self._lifecycle_state = "CLOSED" if getattr(self, "_closed", False) else "OPEN"
            self._active_operations = 0
            self._close_future = None
        return condition

    @contextmanager
    def _operation_lease(self) -> Iterator[None]:
        """Keep the synchronous HTTP client alive for a complete operation."""
        condition = self._get_lifecycle_condition()
        with condition:
            if getattr(self, "_lifecycle_state", "OPEN") != "OPEN" or getattr(
                self, "_closed", False
            ):
                raise RuntimeError("embedder is closing or closed")
            self._active_operations = getattr(self, "_active_operations", 0) + 1
        try:
            yield
        finally:
            with condition:
                self._active_operations -= 1
                if self._active_operations == 0:
                    condition.notify_all()

    def embed_batch(self, texts: list[str]) -> list[list[float]]:
        self._require_literal_loopback()
        with self._operation_lease():
            return self._embed_batch_with_lease(texts)

    def _embed_batch_with_lease(self, texts: list[str]) -> list[list[float]]:
        last_error: Exception | None = None
        for attempt in range(self.max_retries):
            try:
                response = self._ensure_client().post(
                    "/embeddings",
                    json={"model": self.model, "input": texts},
                )
                response.raise_for_status()
                data = response.json()
                vectors = [item["embedding"] for item in data["data"]]
                if self.dims:
                    vectors = [v[: self.dims] for v in vectors]
                self._failure_count = 0
                self._last_success = time.time()
                return vectors
            except Exception as e:
                last_error = e
                is_retryable = isinstance(e, (httpx.NetworkError, httpx.TimeoutException))
                if hasattr(e, 'response') and hasattr(e.response, 'status_code'):
                    is_retryable = is_retryable or e.response.status_code >= 500 or e.response.status_code == 429
                if not is_retryable or attempt >= self.max_retries - 1:
                    break
                time.sleep(min(2 ** attempt, 10))

        self._failure_count += 1
        self._last_failure = time.time()
        raise RuntimeError(f"Embedding API failed after {self.max_retries} attempts: {last_error}") from last_error

    def close(self) -> None:
        condition = self._get_lifecycle_condition()
        with condition:
            state = getattr(self, "_lifecycle_state", "OPEN")
            if state == "CLOSED":
                return
            future = getattr(self, "_close_future", None)
            if state == "CLOSING" and future is not None and not future.done():
                leader = False
            else:
                future = Future()
                self._close_future = future
                leader = True
            if not leader:
                pass
            else:
                self._lifecycle_state = "CLOSING"
                self._closed = True
                while getattr(self, "_active_operations", 0):
                    condition.wait()
        if not leader:
            future.result()
            return

        lock = getattr(self, "_client_lock", None)
        if lock is None:
            lock = threading.Lock()
            self._client_lock = lock
        with lock:
            client = getattr(self, "client", None)
        try:
            if client is not None:
                client.close()
        except BaseException as exc:
            with condition:
                self._lifecycle_state = "CLOSE_FAILED"
                future.set_exception(exc)
                condition.notify_all()
            raise
        with lock:
            if getattr(self, "client", None) is client:
                self.client = None
        with condition:
            self._lifecycle_state = "CLOSED"
            future.set_result(None)
            condition.notify_all()

    def health(self) -> EmbedderHealth:
        return EmbedderHealth(
            provider=f"LLMEmbedder({self.model})",
            active=True,
            failure_count=self._failure_count,
            last_failure=self._last_failure,
            last_success=self._last_success,
        )


class HybridEmbedder(Embedder):
    """Resilient embedder with circuit-breaker fallback.

    Uses the primary embedder (e.g. LLMEmbedder) under normal conditions.
    If the primary fails ``failure_threshold`` consecutive times, it
    switches to the fallback (e.g. KeywordEmbedder).  After
    ``recovery_timeout`` seconds it probes the primary again with a
    dummy call.  If the probe succeeds, it switches back.

    This guarantees that memory operations never crash because of a
    transient embedding API outage.
    """

    def __init__(
        self,
        primary: Embedder,
        fallback: Embedder | None = None,
        failure_threshold: int = 3,
        recovery_timeout: float = 60.0,
    ) -> None:
        self.primary = primary
        self.fallback = fallback or KeywordEmbedder()
        self.failure_threshold = max(1, failure_threshold)
        self.recovery_timeout = max(0.0, recovery_timeout)
        self._consecutive_failures = 0
        self._last_failure_time: float | None = None
        self._using_fallback = False
        self._lock = threading.Lock()

    def _try_primary(self, texts: list[str]) -> list[list[float]]:
        """Attempt primary embedder, updating circuit state."""
        try:
            result = self.primary.embed_batch(texts)
            with self._lock:
                self._consecutive_failures = 0
                self._last_failure_time = None
                self._using_fallback = False
            return result
        except Exception:
            with self._lock:
                self._consecutive_failures += 1
                self._last_failure_time = time.time()
                if self._consecutive_failures >= self.failure_threshold:
                    self._using_fallback = True
            raise

    def _maybe_recover(self) -> bool:
        """If we are in fallback mode and the recovery timeout has passed,
        try a dummy embed to see if the primary is back.
        """
        with self._lock:
            if not self._using_fallback:
                return False
            if self._last_failure_time is None:
                return False
            elapsed = time.time() - self._last_failure_time
            if elapsed < self.recovery_timeout:
                return False
        return self.force_recover()

    def force_recover(self) -> bool:
        """Immediately probe the primary embedder and switch back if healthy.

        Returns True if recovery succeeded.
        """
        from js.security.egress import embedder_endpoint_is_remote

        if embedder_endpoint_is_remote(self.primary):
            return False
        try:
            self.primary.embed("ping")
            with self._lock:
                self._using_fallback = False
                self._consecutive_failures = 0
                self._last_failure_time = None
            return True
        except Exception:
            with self._lock:
                self._consecutive_failures = self.failure_threshold
                self._last_failure_time = time.time()
            return False

    def embed(self, text: str) -> list[float]:
        return self.embed_batch([text])[0]

    def embed_batch(self, texts: list[str]) -> list[list[float]]:
        with self._lock:
            using_fallback = self._using_fallback
        if using_fallback:
            if self._maybe_recover():
                try:
                    return self._try_primary(texts)
                except Exception:
                    logger.warning('Operation failed', exc_info=True)
            return self.fallback.embed_batch(texts)

        try:
            return self._try_primary(texts)
        except Exception:
            # First or intermittent failure: try fallback immediately so
            # the caller never sees an error.
            return self.fallback.embed_batch(texts)

    def close(self) -> None:
        """Close any underlying resources (e.g. HTTP clients)."""
        if hasattr(self.primary, 'close'):
            try:
                self.primary.close()
            except Exception:
                logger.warning('Operation failed', exc_info=True)
        if hasattr(self.fallback, 'close'):
            try:
                self.fallback.close()
            except Exception:
                logger.warning('Operation failed', exc_info=True)

    def health(self) -> EmbedderHealth:
        primary_health = self.primary.health()
        with self._lock:
            using_fallback = self._using_fallback
            consecutive_failures = self._consecutive_failures
            last_failure = self._last_failure_time
        return EmbedderHealth(
            provider=primary_health.provider,
            active=not using_fallback,
            failure_count=consecutive_failures,
            last_failure=last_failure,
            last_success=primary_health.last_success,
            fallback_provider=self.fallback.health().provider if using_fallback else None,
        )
