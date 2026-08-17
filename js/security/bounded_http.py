"""Streaming HTTP body budget for untrusted search/provider responses."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any

import httpx

MAX_RESPONSE_BYTES = 1_048_576
MAX_JSON_DEPTH = 8
MAX_JSON_STRING = 8_192
MAX_JSON_ITEMS = 256


class ResponseBudgetError(ValueError):
    """Inbound HTTP body exceeded a local resource budget."""


@dataclass(frozen=True)
class BoundedResponse:
    status_code: int
    headers: httpx.Headers
    content: bytes
    elapsed_seconds: float

    def raise_for_status(self) -> None:
        request = httpx.Request("GET", "https://invalid.example/")
        response = httpx.Response(self.status_code, headers=self.headers, request=request)
        response.raise_for_status()

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", errors="replace")

    def json(self) -> Any:
        return loads_bounded_json(self.content)


def loads_bounded_json(payload: bytes) -> Any:
    if len(payload) > MAX_RESPONSE_BYTES:
        raise ResponseBudgetError("json payload exceeds byte budget")
    try:
        parsed = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ResponseBudgetError("json payload is invalid") from exc
    _assert_bounded_json(parsed, depth=0)
    return parsed


def _assert_bounded_json(value: object, *, depth: int) -> None:
    if depth > MAX_JSON_DEPTH:
        raise ResponseBudgetError("json depth exceeds budget")
    if isinstance(value, str):
        if len(value) > MAX_JSON_STRING:
            raise ResponseBudgetError("json string exceeds budget")
        return
    if isinstance(value, list):
        if len(value) > MAX_JSON_ITEMS:
            raise ResponseBudgetError("json array exceeds budget")
        for item in value:
            _assert_bounded_json(item, depth=depth + 1)
        return
    if isinstance(value, dict):
        if len(value) > MAX_JSON_ITEMS:
            raise ResponseBudgetError("json object exceeds budget")
        for key, item in value.items():
            if not isinstance(key, str) or len(key) > MAX_JSON_STRING:
                raise ResponseBudgetError("json key exceeds budget")
            _assert_bounded_json(item, depth=depth + 1)
        return
    if isinstance(value, bool) or value is None or isinstance(value, int | float):
        return
    raise ResponseBudgetError("json type is not allowed")


async def read_bounded_response(
    response: httpx.Response,
    *,
    max_bytes: int = MAX_RESPONSE_BYTES,
    deadline_monotonic: float,
) -> BoundedResponse:
    started = time.monotonic()
    content_length = response.headers.get("content-length")
    if content_length is not None:
        try:
            declared = int(content_length)
        except ValueError as exc:
            raise ResponseBudgetError("content-length is invalid") from exc
        if declared < 0 or declared > max_bytes:
            raise ResponseBudgetError("content-length exceeds byte budget")
    chunks: list[bytes] = []
    total = 0
    async for chunk in response.aiter_bytes():
        if time.monotonic() > deadline_monotonic:
            raise ResponseBudgetError("response exceeded absolute deadline")
        if not chunk:
            continue
        total += len(chunk)
        if total > max_bytes:
            raise ResponseBudgetError("response exceeded byte budget")
        chunks.append(chunk)
    return BoundedResponse(
        status_code=response.status_code,
        headers=response.headers,
        content=b"".join(chunks),
        elapsed_seconds=max(0.0, time.monotonic() - started),
    )
