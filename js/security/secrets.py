"""Secret detection, redaction, and encrypted storage."""

from __future__ import annotations

import base64
import hashlib
import hmac
import importlib
import json
import os
import re
import stat
import threading
from array import array
from collections import deque
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, ClassVar
from urllib.parse import quote, quote_plus

from cryptography.fernet import Fernet, InvalidToken

from js.utils.db import db_connection


class ProviderSecretScrubError(RuntimeError):
    """Closed, secret-free failure raised by exact Provider response scrubbing."""

    def __init__(self) -> None:
        # All valid secrets are at least eight UTF-8 bytes. A three-byte error
        # marker cannot itself contain an arbitrary configured secret.
        super().__init__("[S]")

    def __repr__(self) -> str:
        return "[S]"


class _ExactByteMatcher:
    """Bounded Aho-Corasick matcher for private exact-value byte patterns."""

    def __init__(self, patterns: Iterable[bytes]) -> None:
        self._next: list[dict[int, int]] = [{}]
        self._failure: list[int] = [0]
        self._outputs: list[list[int]] = [[]]
        self._depth: list[int] = [0]
        self._max_pattern_length = 0
        for pattern in patterns:
            self._max_pattern_length = max(self._max_pattern_length, len(pattern))
            state = 0
            for byte in pattern:
                child = self._next[state].get(byte)
                if child is None:
                    child = len(self._next)
                    self._next[state][byte] = child
                    self._next.append({})
                    self._failure.append(0)
                    self._outputs.append([])
                    self._depth.append(self._depth[state] + 1)
                state = child
            self._outputs[state].append(len(pattern))

        pending: deque[int] = deque()
        for child in self._next[0].values():
            pending.append(child)
        while pending:
            state = pending.popleft()
            for byte, child in self._next[state].items():
                pending.append(child)
                failure = self._failure[state]
                while failure and byte not in self._next[failure]:
                    failure = self._failure[failure]
                self._failure[child] = self._next[failure].get(byte, 0)
                inherited = self._outputs[self._failure[child]]
                if inherited:
                    self._outputs[child].extend(inherited)

    def _advance(self, state: int, byte: int) -> int:
        while state and byte not in self._next[state]:
            state = self._failure[state]
        return self._next[state].get(byte, 0)

    def iter_intervals(
        self,
        scan: bytes,
        *,
        origin_starts: array[int] | None = None,
        origin_ends: array[int] | None = None,
    ) -> Iterator[tuple[int, int]]:
        """Yield matched source spans without retaining Python interval objects."""
        if (origin_starts is None) != (origin_ends is None):
            raise ProviderSecretScrubError
        if origin_starts is not None and (
            len(origin_starts) != len(scan) or len(origin_ends or ()) != len(scan)
        ):
            raise ProviderSecretScrubError
        state = 0
        for index, byte in enumerate(scan):
            state = self._advance(state, byte)
            for length in self._outputs[state]:
                canonical_start = index + 1 - length
                if origin_starts is None:
                    yield canonical_start, index + 1
                else:
                    assert origin_ends is not None
                    yield origin_starts[canonical_start], origin_ends[index]

    def replace(
        self,
        data: bytes,
        marker: bytes,
        *,
        match_data: bytes | None = None,
    ) -> tuple[bytes, bool]:
        """Return leftmost-longest replacement with bounded interval state."""
        scan = data if match_data is None else match_data
        if len(scan) != len(data):
            raise ProviderSecretScrubError
        intervals: dict[int, int] = {}
        output = bytearray()
        cursor = 0
        state = 0
        matched_any = False
        for index, byte in enumerate(scan):
            state = self._advance(state, byte)
            for length in self._outputs[state]:
                start = index + 1 - length
                if start >= cursor:
                    intervals[start] = max(intervals.get(start, 0), index + 1)
            safe_through = index + 1 - self._max_pattern_length
            while cursor <= safe_through:
                end = intervals.get(cursor)
                if end is None:
                    output.append(data[cursor])
                    cursor += 1
                    continue
                output.extend(marker)
                matched_any = True
                cursor = end
                intervals = {
                    start: interval_end
                    for start, interval_end in intervals.items()
                    if start >= cursor
                }
        while cursor < len(data):
            end = intervals.get(cursor)
            if end is None:
                output.append(data[cursor])
                cursor += 1
                continue
            output.extend(marker)
            matched_any = True
            cursor = end
        return bytes(output), matched_any

    def contains(self, data: bytes) -> bool:
        state = 0
        for byte in data:
            state = self._advance(state, byte)
            if self._outputs[state]:
                return True
        return False

    def has_longer_prefix(self, data: bytes) -> bool:
        """Return whether ``data`` is an exact trie prefix with descendants."""
        state = 0
        for byte in data:
            child = self._next[state].get(byte)
            if child is None:
                return False
            state = child
        return bool(self._next[state])

    def pending_suffix_length(self, data: bytes) -> int:
        state = 0
        for byte in data:
            state = self._advance(state, byte)
        return self._depth[state]

    def deferred_suffix_length(self, data: bytes) -> int:
        """Return a suffix that can still grow into a longer exact match."""
        state = 0
        for byte in data:
            state = self._advance(state, byte)
        if state == 0 or not self._next[state]:
            return 0
        return self._depth[state]

    def terminal_match_length(self, data: bytes) -> int:
        """Return the longest complete pattern ending at the final byte."""
        state = 0
        for byte in data:
            state = self._advance(state, byte)
        return max(self._outputs[state], default=0)


class ProviderSecretScrubber:
    """Redact one attempt's exact Provider secret forms without persistence.

    The object deliberately exposes neither its source secrets nor derived
    patterns. It never calls :class:`SecretManager`, writes detection state, or
    logs matching data.
    """

    marker = "[S]"
    _MARKER_BYTES = marker.encode("ascii")
    _MAX_SECRETS = 64
    _MAX_FORMS_PER_SECRET = 12
    _MIN_SECRET_BYTES = 8
    _MAX_SECRET_BYTES = 512
    _MAX_DEPTH = 16
    _MAX_NODES = 4096
    _MAX_STRING_BYTES = 1024 * 1024
    _MAX_AGGREGATE_STRING_BYTES = 16 * 1024 * 1024
    _MIN_MATCH_CANDIDATE_BUDGET = 4096
    _MATCH_CANDIDATES_PER_INPUT_BYTE = 4

    def __init__(self, secrets: Iterable[str]) -> None:
        values = list(secrets)
        if len(values) > self._MAX_SECRETS:
            raise ProviderSecretScrubError
        exact_patterns: dict[bytes, None] = {}
        url_patterns: dict[bytes, None] = {}
        quote_plus_patterns: dict[bytes, None] = {}
        json_patterns: dict[bytes, None] = {}
        max_source_span = 1
        for secret in values:
            if type(secret) is not str:
                raise ProviderSecretScrubError
            if not secret:
                continue
            try:
                raw = secret.encode("utf-8")
            except UnicodeEncodeError:
                raise ProviderSecretScrubError from None
            if not self._MIN_SECRET_BYTES <= len(raw) <= self._MAX_SECRET_BYTES:
                raise ProviderSecretScrubError
            exact_forms, percent_forms, json_forms = self._derive_forms(secret, raw)
            if len({*exact_forms, *percent_forms, *json_forms}) > (
                self._MAX_FORMS_PER_SECRET
            ):
                raise ProviderSecretScrubError
            for form in exact_forms:
                encoded_form = form.encode("utf-8")
                exact_patterns[encoded_form] = None
                max_source_span = max(max_source_span, len(encoded_form))
            for form in percent_forms:
                encoded_form = form.encode("utf-8")
                max_source_span = max(max_source_span, len(encoded_form))
            # URL encodings may legally percent-encode even an otherwise
            # unreserved byte.  Match a decoded source view instead of
            # enumerating the exponential set of literal/escaped mixtures.
            url_patterns[raw] = None
            quote_plus_patterns[raw] = None
            max_source_span = max(max_source_span, len(raw) * 3)
            for form in json_forms:
                encoded_form = form.encode("utf-8")
                canonical, _, _ = self._canonicalize_json_view(encoded_form)
                json_patterns[canonical] = None
                max_source_span = max(
                    max_source_span,
                    len(encoded_form) + encoded_form.count(b"/"),
                )
        if any(
            self._MARKER_BYTES in pattern
            for pattern in (
                *exact_patterns,
                *url_patterns,
                *quote_plus_patterns,
                *json_patterns,
            )
        ):
            # Arbitrary secrets that contain the fixed marker cannot be safely
            # transformed causally: a future replacement could reconnect an
            # already-published prefix and suffix into the secret. Reject the
            # provider configuration before any response or network I/O.
            raise ProviderSecretScrubError
        self._has_patterns = bool(
            exact_patterns or url_patterns or quote_plus_patterns or json_patterns
        )
        self._exact_matcher = _ExactByteMatcher(exact_patterns)
        self._url_matcher = _ExactByteMatcher(url_patterns)
        self._quote_plus_matcher = _ExactByteMatcher(quote_plus_patterns)
        self._json_matcher = _ExactByteMatcher(json_patterns)
        self._max_pattern_length = max(
            self._exact_matcher._max_pattern_length,
            self._url_matcher._max_pattern_length,
            self._quote_plus_matcher._max_pattern_length,
            self._json_matcher._max_pattern_length,
        )
        self._max_source_span = max_source_span

    def __repr__(self) -> str:
        return "<S>"

    @staticmethod
    def _percent_lower(value: str) -> str:
        return re.sub(
            r"%[0-9A-Fa-f]{2}",
            lambda match: match.group(0).lower(),
            value,
        )

    @staticmethod
    def _canonicalize_percent_bytes(data: bytes) -> bytes:
        """Canonicalize only valid complete or partial URL percent escapes."""
        canonical = bytearray(data)
        index = 0
        while index < len(canonical):
            if canonical[index] == ord("%"):
                start = index + 1
                available = min(2, len(canonical) - start)
                digits = canonical[start : start + available]
                if available and all(
                    ord("0") <= value <= ord("9")
                    or ord("A") <= value <= ord("F")
                    or ord("a") <= value <= ord("f")
                    for value in digits
                ):
                    for position in range(start, start + available):
                        value = canonical[position]
                        if ord("a") <= value <= ord("f"):
                            canonical[position] = value - 32
                    index = start + available
                    continue
            index += 1
        return bytes(canonical)

    @staticmethod
    def _canonicalize_url_view(
        data: bytes,
        *,
        plus_as_space: bool,
    ) -> tuple[bytes, array[int], array[int]]:
        """Decode valid percent triplets while retaining exact source spans.

        In the quote-plus view only a literal ``+`` becomes a space.  A
        percent-encoded ``%2B`` remains a plus, which avoids conflating a
        secret containing ``+`` with one containing a space.
        """
        scan = bytearray()
        starts = array("I")
        ends = array("I")
        index = 0
        while index < len(data):
            if index + 2 < len(data) and data[index] == ord("%"):
                pair = data[index + 1 : index + 3]
                if all(
                    ord("0") <= value <= ord("9")
                    or ord("A") <= value <= ord("F")
                    or ord("a") <= value <= ord("f")
                    for value in pair
                ):
                    scan.append(int(pair.decode("ascii"), 16))
                    starts.append(index)
                    ends.append(index + 3)
                    index += 3
                    continue
            value = data[index]
            if plus_as_space and value == ord("+"):
                value = ord(" ")
            scan.append(value)
            starts.append(index)
            ends.append(index + 1)
            index += 1
        return bytes(scan), starts, ends

    @staticmethod
    def _has_incomplete_percent_suffix(data: bytes) -> bool:
        """Return whether a later chunk can complete a trailing ``%HH`` token."""
        if data.endswith(b"%"):
            return True
        if len(data) < 2 or data[-2] != ord("%"):
            return False
        value = data[-1]
        return (
            ord("0") <= value <= ord("9")
            or ord("A") <= value <= ord("F")
            or ord("a") <= value <= ord("f")
        )

    @staticmethod
    def _has_incomplete_json_escape_suffix(data: bytes) -> bool:
        """Return whether a later chunk can complete a JSON escape token.

        The streaming fast path may otherwise publish a shorter exact secret
        that is also the prefix of a longer secret's JSON ``\\uHHHH`` form.
        Keep an odd escaping backslash, lowercase ``u``, and up to three valid
        hex nibbles pending until the token is complete or the stream ends.
        """
        if data.endswith(b"\\"):
            return True
        for digit_count in range(4):
            u_index = len(data) - digit_count - 1
            if u_index <= 0 or data[u_index] != ord("u"):
                continue
            digits = data[u_index + 1 :]
            if len(digits) != digit_count or not all(
                ord("0") <= value <= ord("9")
                or ord("A") <= value <= ord("F")
                or ord("a") <= value <= ord("f")
                for value in digits
            ):
                continue
            slash_start = u_index
            while slash_start > 0 and data[slash_start - 1] == ord("\\"):
                slash_start -= 1
            if (u_index - slash_start) % 2 == 1:
                return True
        return False

    @staticmethod
    def _canonicalize_json_view(
        data: bytes,
    ) -> tuple[bytes, array[int], array[int]]:
        """Build a JSON-equivalent scan plus exact source-span mapping.

        Only an odd final backslash may escape a solidus or introduce the
        lowercase ``u`` JSON unicode escape. Even backslash runs represent
        literal backslashes and remain byte-exact.
        """
        scan = bytearray()
        starts = array("I")
        ends = array("I")

        def append(byte: int, start: int, end: int) -> None:
            scan.append(byte)
            starts.append(start)
            ends.append(end)

        index = 0
        while index < len(data):
            if data[index] != ord("\\"):
                append(data[index], index, index + 1)
                index += 1
                continue
            run_start = index
            while index < len(data) and data[index] == ord("\\"):
                index += 1
            run_length = index - run_start
            following = data[index] if index < len(data) else None
            if following == ord("/") and run_length % 2 == 1:
                for position in range(run_start, index - 1):
                    append(ord("\\"), position, position + 1)
                append(ord("/"), index - 1, index + 1)
                index += 1
                continue
            unicode_end = index + 5
            if (
                following == ord("u")
                and run_length % 2 == 1
                and unicode_end <= len(data)
                and all(
                    ord("0") <= value <= ord("9")
                    or ord("A") <= value <= ord("F")
                    or ord("a") <= value <= ord("f")
                    for value in data[index + 1 : unicode_end]
                )
            ):
                for position in range(run_start, index):
                    append(ord("\\"), position, position + 1)
                append(ord("u"), index, index + 1)
                for position in range(index + 1, unicode_end):
                    value = data[position]
                    if ord("a") <= value <= ord("f"):
                        value -= 32
                    append(value, position, position + 1)
                index = unicode_end
                continue
            for position in range(run_start, index):
                append(ord("\\"), position, position + 1)
        return bytes(scan), starts, ends

    @classmethod
    def _derive_forms(
        cls, secret: str, raw: bytes
    ) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
        quoted = quote(secret, safe="")
        plus = quote_plus(secret, safe="")
        json_inner = json.dumps(secret, ensure_ascii=True)[1:-1]
        # JSON permits each solidus to be escaped independently. Rather than
        # enumerate 2^N variants, matching canonicalizes `\/` to `/` only in
        # the JSON matcher while retaining all other bytes exactly.
        json_canonical = json_inner
        standard = base64.b64encode(raw).decode("ascii")
        urlsafe = base64.urlsafe_b64encode(raw).decode("ascii")
        fully_percent_encoded = "".join(f"%{byte:02X}" for byte in raw)
        exact_candidates = (
            secret,
            standard,
            standard.rstrip("="),
            urlsafe,
            urlsafe.rstrip("="),
            raw.hex(),
            raw.hex().upper(),
        )
        percent_candidates = (quoted, plus, fully_percent_encoded)
        json_candidates = (json_canonical,)
        return (
            tuple(dict.fromkeys(candidate for candidate in exact_candidates if candidate)),
            tuple(dict.fromkeys(candidate for candidate in percent_candidates if candidate)),
            tuple(dict.fromkeys(candidate for candidate in json_candidates if candidate)),
        )

    def _redact_bytes(self, data: bytes) -> bytes:
        if not self._has_patterns:
            return data
        intervals = self._collect_intervals(data)
        redacted, cursor, matched = self._replace_mature(
            data,
            intervals,
            mature_limit=len(data),
        )
        if cursor != len(data):
            raise ProviderSecretScrubError
        if not matched:
            return data
        # A fixed marker can be part of an otherwise valid arbitrary secret.
        # Never publish a replacement-boundary reconstruction.
        if any(self._collect_intervals(redacted)):
            raise ProviderSecretScrubError
        return redacted

    def _collect_intervals(self, data: bytes) -> array[int]:
        best_end = array("I", [0]) * (len(data) + 1)
        budget = max(
            self._MIN_MATCH_CANDIDATE_BUDGET,
            len(data) * self._MATCH_CANDIDATES_PER_INPUT_BYTE,
        )
        candidates = 0

        def collect(intervals: Iterator[tuple[int, int]]) -> None:
            nonlocal candidates
            for start, end in intervals:
                candidates += 1
                if candidates > budget or not (0 <= start < end <= len(data)):
                    raise ProviderSecretScrubError
                if end > best_end[start]:
                    best_end[start] = end

        collect(self._exact_matcher.iter_intervals(data))
        url_scan, url_starts, url_ends = self._canonicalize_url_view(
            data,
            plus_as_space=False,
        )
        collect(
            self._url_matcher.iter_intervals(
                url_scan,
                origin_starts=url_starts,
                origin_ends=url_ends,
            )
        )
        plus_scan, plus_starts, plus_ends = self._canonicalize_url_view(
            data,
            plus_as_space=True,
        )
        collect(
            self._quote_plus_matcher.iter_intervals(
                plus_scan,
                origin_starts=plus_starts,
                origin_ends=plus_ends,
            )
        )
        json_scan, json_starts, json_ends = self._canonicalize_json_view(data)
        collect(
            self._json_matcher.iter_intervals(
                json_scan,
                origin_starts=json_starts,
                origin_ends=json_ends,
            )
        )
        return best_end

    def _replace_mature(
        self,
        data: bytes,
        intervals: array[int],
        *,
        mature_limit: int,
    ) -> tuple[bytes, int, bool]:
        output = bytearray()
        cursor = 0
        matched = False
        while cursor < mature_limit:
            end = intervals[cursor]
            if end > cursor:
                output.extend(self._MARKER_BYTES)
                cursor = end
                matched = True
            else:
                output.append(data[cursor])
                cursor += 1
        return bytes(output), cursor, matched

    @staticmethod
    def _utf8_mature_limit(data: bytes, limit: int) -> int:
        safe = min(limit, len(data))
        while safe > 0 and safe < len(data) and data[safe] & 0xC0 == 0x80:
            safe -= 1
        return safe

    def _redact_stream_prefix(self, data: bytes, *, final: bool) -> tuple[bytes, bytes]:
        if not self._has_patterns:
            return data, b""
        intervals = self._collect_intervals(data)
        limit = (
            len(data)
            if final
            else max(0, len(data) - self._max_source_span + 1)
        )
        if (
            not final
            and intervals[0] == len(data)
            and not self._has_incomplete_percent_suffix(data)
            and not self._has_incomplete_json_escape_suffix(data)
        ):
            url_scan, _, _ = self._canonicalize_url_view(
                data,
                plus_as_space=False,
            )
            plus_scan, _, _ = self._canonicalize_url_view(
                data,
                plus_as_space=True,
            )
            json_scan, _, _ = self._canonicalize_json_view(data)
            can_extend = (
                self._exact_matcher.has_longer_prefix(data)
                or self._url_matcher.has_longer_prefix(url_scan)
                or self._quote_plus_matcher.has_longer_prefix(plus_scan)
                or self._json_matcher.has_longer_prefix(json_scan)
            )
            if not can_extend:
                limit = len(data)
        limit = self._utf8_mature_limit(data, limit)
        emitted, cursor, _ = self._replace_mature(
            data,
            intervals,
            mature_limit=limit,
        )
        if any(self._collect_intervals(emitted)):
            raise ProviderSecretScrubError
        return emitted, data[cursor:]

    def _advance_output_guard(self, history: bytes, emitted: bytes) -> bytes:
        """Reject a secret reconstructed across sanitized stream returns."""
        combined = history + emitted
        if any(self._collect_intervals(combined)):
            raise ProviderSecretScrubError
        retain = max(0, self._max_source_span - 1)
        return combined[-retain:] if retain else b""

    @classmethod
    def _encode_text(cls, text: str) -> bytes:
        if type(text) is not str:
            raise ProviderSecretScrubError
        try:
            encoded = text.encode("utf-8")
        except UnicodeEncodeError:
            raise ProviderSecretScrubError from None
        if len(encoded) > cls._MAX_STRING_BYTES:
            raise ProviderSecretScrubError
        return encoded

    def redact_text(self, text: str) -> str:
        encoded = self._encode_text(text)
        try:
            return self._redact_bytes(encoded).decode("utf-8")
        except UnicodeDecodeError:
            raise ProviderSecretScrubError from None

    def redact_value(self, value: object) -> object:
        active: set[int] = set()
        counters = {"nodes": 0, "bytes": 0}

        def visit(current: object, depth: int) -> object:
            if depth > self._MAX_DEPTH:
                raise ProviderSecretScrubError
            counters["nodes"] += 1
            if counters["nodes"] > self._MAX_NODES:
                raise ProviderSecretScrubError
            if type(current) is str:
                encoded = self._encode_text(current)
                counters["bytes"] += len(encoded)
                if counters["bytes"] > self._MAX_AGGREGATE_STRING_BYTES:
                    raise ProviderSecretScrubError
                return self._redact_bytes(encoded).decode("utf-8")
            if current is None or type(current) in {bool, int, float}:
                return current
            if type(current) in {dict, list, tuple}:
                identity = id(current)
                if identity in active:
                    raise ProviderSecretScrubError
                active.add(identity)
                try:
                    if type(current) is dict:
                        rebuilt: dict[str, object] = {}
                        for key, item in current.items():
                            if type(key) is not str:
                                raise ProviderSecretScrubError
                            safe_key = visit(key, depth + 1)
                            if not isinstance(safe_key, str) or safe_key in rebuilt:
                                raise ProviderSecretScrubError
                            rebuilt[safe_key] = visit(item, depth + 1)
                        return rebuilt
                    if type(current) is list:
                        return [visit(item, depth + 1) for item in current]
                    if type(current) is tuple:
                        return tuple(visit(item, depth + 1) for item in current)
                    raise ProviderSecretScrubError
                finally:
                    active.remove(identity)
            raise ProviderSecretScrubError

        return visit(value, 0)

    def open_stream(self) -> ProviderSecretStream:
        return ProviderSecretStream(self)


class ProviderSecretStream:
    """Incremental exact-value stream with cross-chunk prefix retention."""

    def __init__(self, scrubber: ProviderSecretScrubber) -> None:
        self._scrubber = scrubber
        self._pending = b""
        self._published_guard_tail = b""
        self._total_bytes = 0
        self._closed = False

    def __repr__(self) -> str:
        return "<S>"

    def feed(self, chunk: str) -> str:
        if self._closed:
            raise ProviderSecretScrubError
        try:
            encoded = self._scrubber._encode_text(chunk)
            self._total_bytes += len(encoded)
            if self._total_bytes > self._scrubber._MAX_AGGREGATE_STRING_BYTES:
                raise ProviderSecretScrubError
            combined = self._pending + encoded
            emitted, pending = self._scrubber._redact_stream_prefix(
                combined,
                final=False,
            )
            published_guard_tail = self._scrubber._advance_output_guard(
                self._published_guard_tail,
                emitted,
            )
            decoded = emitted.decode("utf-8")
            self._pending = pending
            self._published_guard_tail = published_guard_tail
            return decoded
        except (ProviderSecretScrubError, UnicodeDecodeError):
            self.discard()
            raise ProviderSecretScrubError from None

    def flush(self) -> str:
        if self._closed:
            return ""
        pending = self._pending
        try:
            emitted, remainder = self._scrubber._redact_stream_prefix(
                pending,
                final=True,
            )
            if remainder:
                raise ProviderSecretScrubError
            published_guard_tail = self._scrubber._advance_output_guard(
                self._published_guard_tail,
                emitted,
            )
            decoded = emitted.decode("utf-8")
            self._pending = b""
            self._published_guard_tail = published_guard_tail
            self._closed = True
            return decoded
        except (ProviderSecretScrubError, UnicodeDecodeError):
            self.discard()
            raise ProviderSecretScrubError from None

    def discard(self) -> None:
        self._pending = b""
        self._published_guard_tail = b""
        self._closed = True


class SecretManager:
    """Manages secret detection, redaction, and encrypted storage."""

    # Patterns for common secrets
    PATTERNS = {
        "openai_key": re.compile(r"sk-[a-zA-Z0-9]{20,60}"),
        "anthropic_key": re.compile(r"sk-ant-[a-zA-Z0-9_-]{20,100}"),
        "generic_api_key": re.compile(
            r"[a-zA-Z0-9_-]*[aA][pP][iI][_-]?[kK][eE][yY]\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{16,})['\"]?"
        ),
        "aws_key": re.compile(r"AKIA[0-9A-Z]{16}"),
        "github_token": re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}"),
        "jwt": re.compile(r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*"),
        "password": re.compile(
            r"[pP][aA][sS][sS][wW][oO][rR][dD]\s*[:=]\s*['\"]?([^'\"\s]{8,})['\"]?"
        ),
        "token": re.compile(r"[tT][oO][kK][eE][nN]\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{16,})['\"]?"),
    }

    _init_lock = threading.RLock()
    _KDF_HEADER = b"JSS1"
    _KDF_ITERATIONS = 600_000
    _LEGACY_KDF_ITERATIONS = 100_000
    _KDF_JOURNAL_NAME = ".secret_kdf_migrate.journal"
    # Test-only one-shot fault injection. Production never sets this.
    _migration_fault_point: ClassVar[str | None] = None

    def __init__(
        self,
        state_dir: Path,
        master_key: str | None = None,
        *,
        require_encryption: bool = True,
    ) -> None:
        self.state_dir = state_dir
        self.db_path = state_dir / "secrets.db"
        self._require_encryption = bool(require_encryption)
        self._init_db()
        self._fernet, self._key_material = self._init_fernet(master_key)
        self._redaction_cache: set[str] = set()

    def _init_db(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.state_dir, 0o700)
        with db_connection(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS secrets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    value_encrypted BLOB NOT NULL,
                    category TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS detected_leaks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source TEXT,
                    secret_hash TEXT,
                    secret_type TEXT,
                    redacted_preview TEXT,
                    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()

    def _init_fernet(self, master_key: str | None) -> tuple[Fernet, bytes]:
        key_path = self.state_dir / ".secret_key"
        salt_path = self.state_dir / ".secret_salt"
        if master_key:
            with self._init_lock, self._secret_material_lock():
                recovered = self._recover_kdf_migration(master_key=master_key, salt_path=salt_path)
                if recovered is not None:
                    return recovered
                encoded_salt = self._load_or_create_kdf_salt(salt_path)
            if len(encoded_salt) == 16:
                salt = encoded_salt
                iterations = self._LEGACY_KDF_ITERATIONS
                legacy = True
            elif len(encoded_salt) == 24 and encoded_salt.startswith(self._KDF_HEADER):
                iterations = int.from_bytes(encoded_salt[4:8], "big")
                if iterations < self._LEGACY_KDF_ITERATIONS:
                    raise ValueError("secret KDF iteration count is below the supported minimum")
                salt = encoded_salt[8:]
                legacy = iterations < self._KDF_ITERATIONS
            else:
                raise ValueError("invalid secret KDF salt metadata")
            key = hashlib.pbkdf2_hmac(
                "sha256",
                master_key.encode(),
                salt,
                iterations,
                dklen=32,
            )
            fernet_key = base64.urlsafe_b64encode(key)
            fernet = Fernet(fernet_key)
            if legacy:
                fernet, key = self._migrate_legacy_kdf(
                    master_key=master_key,
                    salt_path=salt_path,
                    old_fernet=fernet,
                    old_encoded=encoded_salt,
                )
            return fernet, key

        with self._init_lock, self._secret_material_lock():
            if key_path.exists() or key_path.is_symlink():
                key = self._read_private_file(key_path)
                return Fernet(key), key

            key = Fernet.generate_key()
            fd = os.open(str(key_path), os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
            try:
                os.fchmod(fd, 0o600)
                with os.fdopen(fd, "wb") as handle:
                    fd = -1
                    handle.write(key)
                    handle.flush()
                    os.fsync(handle.fileno())
            finally:
                if fd >= 0:
                    os.close(fd)
            self._fsync_state_directory()
            return Fernet(key), key

    def derive_mac_key(self, purpose: str) -> bytes:
        """Derive a purpose-scoped MAC key from the master secret material.

        The derived key never exposes the Fernet master key itself, and each
        purpose label produces an independent key domain so MAC keys cannot be
        confused across subsystems.  The key is stable across restarts for the
        same installation, which is required for verifying persisted chains.
        """
        if not purpose.strip():
            raise ValueError("MAC key purpose must not be empty")
        return hmac.new(
            self._key_material,
            f"js-secret-manager-mac-v1:{purpose}".encode(),
            hashlib.sha256,
        ).digest()

    def _load_or_create_kdf_salt(self, path: Path) -> bytes:
        if path.exists() or path.is_symlink():
            return self._read_private_file(path)
        salt = os.urandom(16)
        encoded = self._KDF_HEADER + self._KDF_ITERATIONS.to_bytes(4, "big") + salt
        fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as handle:
                fd = -1
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
        finally:
            if fd >= 0:
                os.close(fd)
        self._fsync_state_directory()
        return encoded

    @contextmanager
    def _secret_material_lock(self) -> Iterator[None]:
        lock_path = self.state_dir / ".secret_material.lock"
        flags = os.O_CREAT | os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        lock_fd = os.open(lock_path, flags, 0o600)
        try:
            metadata = os.fstat(lock_fd)
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError(f"secret material lock must be a regular file: {lock_path}")
            os.fchmod(lock_fd, 0o600)
            self._acquire_file_lock(lock_fd)
            try:
                yield
            finally:
                self._release_file_lock(lock_fd)
        finally:
            os.close(lock_fd)

    @staticmethod
    def _acquire_file_lock(lock_fd: int) -> None:
        if os.name == "nt":
            msvcrt: Any = importlib.import_module("msvcrt")
            if os.fstat(lock_fd).st_size == 0:
                os.write(lock_fd, b"\0")
            os.lseek(lock_fd, 0, os.SEEK_SET)
            msvcrt.locking(lock_fd, msvcrt.LK_LOCK, 1)
            return
        fcntl: Any = importlib.import_module("fcntl")
        fcntl.flock(lock_fd, fcntl.LOCK_EX)

    @staticmethod
    def _release_file_lock(lock_fd: int) -> None:
        if os.name == "nt":
            msvcrt: Any = importlib.import_module("msvcrt")
            os.lseek(lock_fd, 0, os.SEEK_SET)
            msvcrt.locking(lock_fd, msvcrt.LK_UNLCK, 1)
            return
        fcntl: Any = importlib.import_module("fcntl")
        fcntl.flock(lock_fd, fcntl.LOCK_UN)

    def _fsync_state_directory(self) -> None:
        directory_fd = os.open(self.state_dir, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

    @staticmethod
    def _read_private_file(path: Path) -> bytes:
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(path, flags)
        except OSError as exc:
            raise ValueError(f"secret key material must be a regular file: {path}") from exc
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError(f"secret key material must be a regular file: {path}")
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "rb") as handle:
                fd = -1
                return handle.read()
        finally:
            if fd >= 0:
                os.close(fd)

    def store(self, name: str, value: str, category: str = "general") -> None:
        """Store a secret securely."""
        encrypted = self._fernet.encrypt(value.encode())
        with db_connection(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO secrets (name, value_encrypted, category)
                VALUES (?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    value_encrypted=excluded.value_encrypted,
                    category=excluded.category,
                    updated_at=CURRENT_TIMESTAMP
                """,
                (name, encrypted, category),
            )
            conn.commit()

    def retrieve(self, name: str) -> str | None:
        """Retrieve a secret by name."""
        with db_connection(self.db_path) as conn:
            row = conn.execute(
                "SELECT value_encrypted FROM secrets WHERE name = ?", (name,)
            ).fetchone()
        if row:
            return self._fernet.decrypt(row[0]).decode()
        return None

    def delete(self, name: str) -> bool:
        """Delete one stored secret and report whether it existed."""
        with db_connection(self.db_path) as conn:
            cursor = conn.execute("DELETE FROM secrets WHERE name = ?", (name,))
            conn.commit()
            return cursor.rowcount > 0

    _BLOB_PREFIX: bytes = b"ENC:v1:"  # Version tag for encrypted blobs

    def encrypt_blob(self, data: bytes) -> bytes:
        """Encrypt arbitrary binary data with the Fernet key.

        Prepends a version tag so that ``decrypt_blob`` can distinguish
        encrypted payloads from pre-upgrade plaintext data.
        """
        return self._BLOB_PREFIX + self._fernet.encrypt(data)

    def decrypt_blob(self, data: bytes) -> bytes:
        """Decrypt data previously encrypted with ``encrypt_blob``.

        Legacy plaintext blobs are rejected by default. Callers that must
        accept pre-encryption data must construct the manager with
        ``require_encryption=False``.
        """
        if not data.startswith(self._BLOB_PREFIX):
            if self._require_encryption:
                raise ValueError("legacy plaintext blob rejected; encryption required")
            return data  # Explicit opt-out for migration tooling
        return self._fernet.decrypt(data[len(self._BLOB_PREFIX) :])

    def _kdf_journal_path(self) -> Path:
        return self.state_dir / self._KDF_JOURNAL_NAME

    @classmethod
    def _maybe_migration_fault(cls, point: str) -> None:
        """Raise once when tests inject a crash at ``point``."""
        if cls._migration_fault_point == point:
            cls._migration_fault_point = None
            raise RuntimeError(f"injected kdf migration fault: {point}")

    @classmethod
    def _fernet_from_encoded_salt(
        cls, master_key: str, encoded: bytes
    ) -> tuple[Fernet, bytes, bytes]:
        """Derive Fernet + raw key material from a salt file blob.

        Returns ``(fernet, key_material, salt_bytes)``.
        """
        if len(encoded) == 16:
            salt = encoded
            iterations = cls._LEGACY_KDF_ITERATIONS
        elif len(encoded) == 24 and encoded.startswith(cls._KDF_HEADER):
            iterations = int.from_bytes(encoded[4:8], "big")
            if iterations < cls._LEGACY_KDF_ITERATIONS:
                raise ValueError("secret KDF iteration count is below the supported minimum")
            salt = encoded[8:]
        else:
            raise ValueError("invalid secret KDF salt metadata")
        key = hashlib.pbkdf2_hmac(
            "sha256",
            master_key.encode(),
            salt,
            iterations,
            dklen=32,
        )
        return Fernet(base64.urlsafe_b64encode(key)), key, salt

    def _write_kdf_journal(
        self,
        *,
        old_encoded: bytes,
        new_encoded: bytes,
        phase: str,
    ) -> None:
        payload = {
            "version": 1,
            "phase": phase,
            "old_salt": base64.b64encode(old_encoded).decode("ascii"),
            "new_salt": base64.b64encode(new_encoded).decode("ascii"),
        }
        raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        journal_path = self._kdf_journal_path()
        tmp_path = journal_path.with_name(
            f".{journal_path.name}.tmp-{os.getpid()}-{os.urandom(4).hex()}"
        )
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(str(tmp_path), os.O_CREAT | os.O_WRONLY | os.O_EXCL | nofollow, 0o600)
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, raw)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp_path, journal_path)
        self._fsync_state_directory()

    def _read_kdf_journal(self) -> dict[str, Any] | None:
        journal_path = self._kdf_journal_path()
        if not (journal_path.exists() or journal_path.is_symlink()):
            return None
        raw = self._read_private_file(journal_path)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("corrupt secret KDF migration journal") from exc
        if not isinstance(payload, dict) or int(payload.get("version", 0)) != 1:
            raise ValueError("unsupported secret KDF migration journal")
        for field in ("phase", "old_salt", "new_salt"):
            if field not in payload or not isinstance(payload[field], str):
                raise ValueError("invalid secret KDF migration journal")
        return payload

    def _clear_kdf_journal(self) -> None:
        journal_path = self._kdf_journal_path()
        try:
            journal_path.unlink(missing_ok=True)
        except OSError:
            pass
        self._fsync_state_directory()

    def _publish_kdf_salt(self, salt_path: Path, encoded: bytes) -> None:
        tmp_path = salt_path.with_name(
            f".{salt_path.name}.migrate-{os.getpid()}-{os.urandom(4).hex()}"
        )
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(str(tmp_path), os.O_CREAT | os.O_WRONLY | os.O_EXCL | nofollow, 0o600)
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, encoded)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp_path, salt_path)
        self._fsync_state_directory()

    def _secrets_decryptable(self, fernet: Fernet) -> bool:
        with db_connection(self.db_path) as conn:
            rows = conn.execute("SELECT value_encrypted FROM secrets").fetchall()
        if not rows:
            return True
        for (blob,) in rows:
            try:
                fernet.decrypt(blob)
            except InvalidToken:
                return False
        return True

    def _recover_kdf_migration(
        self,
        *,
        master_key: str,
        salt_path: Path,
    ) -> tuple[Fernet, bytes] | None:
        """Replay an interrupted KDF migration journal (dual-key window).

        Crash after re-encrypt but before salt publish leaves old salt on disk
        and new ciphertext in SQLite; the journal carries the new salt so
        restart can finish the swap. Crash after salt publish leaves the
        journal for cleanup. In all recoverable states plaintext remains
        readable.
        """
        journal = self._read_kdf_journal()
        if journal is None:
            return None

        old_encoded = base64.b64decode(journal["old_salt"])
        new_encoded = base64.b64decode(journal["new_salt"])
        old_fernet, _old_key, _ = self._fernet_from_encoded_salt(master_key, old_encoded)
        new_fernet, new_key, _ = self._fernet_from_encoded_salt(master_key, new_encoded)

        published = (
            self._read_private_file(salt_path)
            if (salt_path.exists() or salt_path.is_symlink())
            else None
        )

        if published == new_encoded:
            if not self._secrets_decryptable(new_fernet):
                raise ValueError("KDF migration journal/salt mismatch after salt publish")
            self._clear_kdf_journal()
            return new_fernet, new_key

        if published is not None and published != old_encoded:
            raise ValueError("KDF migration journal does not match published salt")

        if self._secrets_decryptable(new_fernet):
            self._write_kdf_journal(
                old_encoded=old_encoded,
                new_encoded=new_encoded,
                phase="reencrypted",
            )
            self._publish_kdf_salt(salt_path, new_encoded)
            self._maybe_migration_fault("after_salt_publish")
            self._clear_kdf_journal()
            return new_fernet, new_key

        if self._secrets_decryptable(old_fernet):
            # Intent only — ciphertext still under the old key; drop journal so
            # legacy migration can run again cleanly.
            self._clear_kdf_journal()
            return None

        raise ValueError("KDF migration journal is not recoverable")

    def _migrate_legacy_kdf(
        self,
        *,
        master_key: str,
        salt_path: Path,
        old_fernet: Fernet,
        old_encoded: bytes,
    ) -> tuple[Fernet, bytes]:
        """Upgrade a 100K (or otherwise below-target) salt to JSS1/600K and re-encrypt.

        Crash-safe via a replayable migration journal:

        1. Write intent journal (old + new salt metadata).
        2. Re-encrypt ciphertext under the new key while the published salt
           remains the old one (dual-key window).
        3. Atomically publish the new salt.
        4. Clear the journal.

        A crash at any step leaves secrets decryptable after restart by
        replaying the journal or continuing under the old salt.
        """
        with self._init_lock, self._secret_material_lock():
            recovered = self._recover_kdf_migration(master_key=master_key, salt_path=salt_path)
            if recovered is not None:
                return recovered

            current = (
                self._read_private_file(salt_path)
                if (salt_path.exists() or salt_path.is_symlink())
                else old_encoded
            )
            if (
                len(current) == 24
                and current.startswith(self._KDF_HEADER)
                and int.from_bytes(current[4:8], "big") >= self._KDF_ITERATIONS
            ):
                fernet, key, _ = self._fernet_from_encoded_salt(master_key, current)
                return fernet, key

            rows: list[tuple[str, bytes, str | None]] = []
            with db_connection(self.db_path) as conn:
                for name, value_encrypted, category in conn.execute(
                    "SELECT name, value_encrypted, category FROM secrets"
                ):
                    plaintext = old_fernet.decrypt(value_encrypted)
                    rows.append((name, plaintext, category))

            new_salt = os.urandom(16)
            new_encoded = self._KDF_HEADER + self._KDF_ITERATIONS.to_bytes(4, "big") + new_salt
            new_fernet, new_key, _ = self._fernet_from_encoded_salt(master_key, new_encoded)
            journal_old = current if len(current) in {16, 24} else old_encoded

            # 1) Durable intent: both salts known before any ciphertext change.
            self._write_kdf_journal(
                old_encoded=journal_old,
                new_encoded=new_encoded,
                phase="intent",
            )
            self._maybe_migration_fault("after_journal")

            # 2) Encrypt-then-salt-swap: re-encrypt under dual-key window.
            updates = [
                (new_fernet.encrypt(plaintext), category, name)
                for name, plaintext, category in rows
            ]
            with db_connection(self.db_path) as conn:
                for encrypted, category, name in updates:
                    conn.execute(
                        """
                        UPDATE secrets
                        SET value_encrypted = ?, category = COALESCE(?, category),
                            updated_at = CURRENT_TIMESTAMP
                        WHERE name = ?
                        """,
                        (encrypted, category, name),
                    )
                self._maybe_migration_fault("after_ciphertext_update")
                self._maybe_migration_fault("before_commit")
                conn.commit()

            self._write_kdf_journal(
                old_encoded=journal_old,
                new_encoded=new_encoded,
                phase="reencrypted",
            )

            # 3) Publish new salt only after ciphertext is durable.
            self._maybe_migration_fault("before_salt_publish")
            self._publish_kdf_salt(salt_path, new_encoded)
            self._maybe_migration_fault("after_salt_publish")

            # 4) Drop journal — migration complete.
            self._clear_kdf_journal()
            return new_fernet, new_key

    def detect_and_redact(self, text: str, source: str = "unknown") -> str:
        """Detect secrets in text and replace with [REDACTED]."""
        result = text
        for secret_type, pattern in self.PATTERNS.items():
            for match in pattern.finditer(text):
                secret_value = match.group(0)
                secret_hash = hashlib.sha256(secret_value.encode()).hexdigest()[:16]

                if secret_hash not in self._redaction_cache:
                    self._redaction_cache.add(secret_hash)
                    # Limit cache size to prevent unbounded growth
                    if len(self._redaction_cache) > 10_000:
                        self._redaction_cache.clear()
                    self._log_detection(source, secret_hash, secret_type, secret_value)

                result = result.replace(secret_value, f"[REDACTED:{secret_type}]")
        return result

    def _log_detection(self, source: str, secret_hash: str, secret_type: str, value: str) -> None:
        # Never store partial secret values — only the type and hash.
        preview = f"[{secret_type}]"
        with db_connection(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO detected_leaks (source, secret_hash, secret_type, redacted_preview)
                VALUES (?, ?, ?, ?)
                """,
                (source, secret_hash, secret_type, preview),
            )
            conn.commit()

    def get_stats(self) -> dict[str, int]:
        """Return statistics about stored secrets and detections."""
        with db_connection(self.db_path) as conn:
            secret_count = conn.execute("SELECT COUNT(*) FROM secrets").fetchone()[0]
            leak_count = conn.execute("SELECT COUNT(*) FROM detected_leaks").fetchone()[0]
        return {"stored_secrets": secret_count, "detected_leaks": leak_count}


def redact_known_secrets(text: str) -> str:
    """Redact built-in secret shapes without requiring a stateful manager."""
    redacted = text
    for secret_type, pattern in SecretManager.PATTERNS.items():
        redacted = pattern.sub(f"[REDACTED:{secret_type}]", redacted)
    return redacted


class StreamingSecretRedactor:
    """Incrementally redact secrets without leaking cross-chunk matches.

    Normal text is emitted immediately. Only suffixes that can still become a
    supported secret are retained, keeping first-token latency unchanged for
    ordinary output while preventing provider chunk boundaries from bypassing
    :class:`SecretManager` patterns.
    """

    _MAX_PENDING = 4096
    _LITERAL_CANDIDATES: tuple[tuple[str, str], ...] = (
        ("sk-ant-", r"[A-Za-z0-9_-]"),
        ("sk-", r"[A-Za-z0-9_-]"),
        ("AKIA", r"[0-9A-Z]"),
        ("ghp_", r"[A-Za-z0-9_]"),
        ("gho_", r"[A-Za-z0-9_]"),
        ("ghu_", r"[A-Za-z0-9_]"),
        ("ghs_", r"[A-Za-z0-9_]"),
        ("ghr_", r"[A-Za-z0-9_]"),
        ("eyJ", r"[A-Za-z0-9_.-]"),
    )
    _LABEL_PREFIXES = ("api_key", "api-key", "apikey", "password", "token")
    _LABEL_CANDIDATE = re.compile(
        r"(?i)(?:[A-Za-z0-9_-]*api[_-]?key|password|token)"
        r"\s*[:=]\s*['\"]?[^\s'\"]*$"
    )
    _CONTINUATION_PATTERNS = {
        "openai_key": re.compile(r"[A-Za-z0-9]"),
        "anthropic_key": re.compile(r"[A-Za-z0-9_-]"),
        "generic_api_key": re.compile(r"[A-Za-z0-9_-]"),
        "aws_key": re.compile(r"[0-9A-Z]"),
        "github_token": re.compile(r"[A-Za-z0-9_]"),
        "jwt": re.compile(r"[A-Za-z0-9_.-]"),
        "password": re.compile(r"[^\s'\"]"),
        "token": re.compile(r"[A-Za-z0-9_-]"),
        "possible_secret": re.compile(r"[^\s'\"]"),
    }

    def __init__(self, manager: Any, source: str) -> None:
        self._manager = manager
        self._source = source
        self._pending = ""
        self._suppress_type: str | None = None

    def feed(self, text: str) -> str:
        if not text:
            return ""
        self._pending += text
        return self._drain(final=False)

    def flush(self) -> str:
        return self._drain(final=True)

    def discard(self) -> None:
        self._pending = ""
        self._suppress_type = None

    def _drain(self, *, final: bool) -> str:
        emitted: list[str] = []
        while self._pending:
            if self._suppress_type is not None:
                boundary = self._suppression_boundary(self._pending, self._suppress_type)
                if boundary is None:
                    self._pending = ""
                    break
                self._pending = self._pending[boundary:]
                self._suppress_type = None
                continue

            first_match = self._first_match(self._pending)
            if first_match is not None:
                secret_type, match = first_match
                if match.start() > 0:
                    emitted.append(
                        self._manager.detect_and_redact(
                            self._pending[: match.start()], self._source
                        )
                    )
                matched = self._pending[match.start() : match.end()]
                marker = self._manager.detect_and_redact(matched, self._source)
                if marker == matched:
                    marker = f"[REDACTED:{secret_type}]"
                emitted.append(marker)

                end = match.end()
                continuation = self._CONTINUATION_PATTERNS[secret_type]
                while end < len(self._pending) and continuation.fullmatch(self._pending[end]):
                    end += 1
                reached_open_end = end == len(self._pending)
                self._pending = self._pending[end:]
                if reached_open_end:
                    self._suppress_type = secret_type
                continue

            custom_redacted = self._manager.detect_and_redact(self._pending, self._source)
            if custom_redacted != self._pending:
                emitted.append(custom_redacted)
                self._pending = ""
                break

            if final:
                emitted.append(self._pending)
                self._pending = ""
                break

            candidate_start = self._potential_secret_start(self._pending)
            if candidate_start is None:
                emitted.append(self._pending)
                self._pending = ""
                break
            if candidate_start > 0:
                emitted.append(self._pending[:candidate_start])
                self._pending = self._pending[candidate_start:]
            if len(self._pending) > self._MAX_PENDING:
                emitted.append("[REDACTED:possible_secret]")
                self._pending = ""
                self._suppress_type = "possible_secret"
            break
        if final:
            self._pending = ""
            self._suppress_type = None
        return "".join(emitted)

    def _first_match(self, text: str) -> tuple[str, re.Match[str]] | None:
        patterns = getattr(self._manager, "PATTERNS", SecretManager.PATTERNS)
        matches: list[tuple[str, re.Match[str]]] = []
        for secret_type, pattern in patterns.items():
            match = pattern.search(text)
            if match is not None:
                matches.append((str(secret_type), match))
        if not matches:
            return None
        return min(matches, key=lambda item: (item[1].start(), -item[1].end()))

    @classmethod
    def _potential_secret_start(cls, text: str) -> int | None:
        starts: list[int] = []
        for prefix, continuation_pattern in cls._LITERAL_CANDIDATES:
            candidate = re.search(
                re.escape(prefix) + continuation_pattern + r"*$",
                text,
            )
            if candidate is not None:
                starts.append(candidate.start())
            for length in range(1, len(prefix)):
                if text.endswith(prefix[:length]):
                    starts.append(len(text) - length)

        label_match = cls._LABEL_CANDIDATE.search(text)
        if label_match is not None:
            starts.append(label_match.start())
        lower = text.lower()
        for prefix in cls._LABEL_PREFIXES:
            for length in range(1, len(prefix) + 1):
                if lower.endswith(prefix[:length]):
                    starts.append(len(text) - length)
        return min(starts) if starts else None

    @classmethod
    def _suppression_boundary(cls, text: str, secret_type: str) -> int | None:
        continuation = cls._CONTINUATION_PATTERNS[secret_type]
        for index, char in enumerate(text):
            if continuation.fullmatch(char) is None:
                return index
        return None
