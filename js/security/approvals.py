"""Tiered approval system: manual, auto-approve, auto-deny, cron-deny.

Inspired by Hermes:
- Manual: interactive prompt for dangerous operations
- Gateway: async queue for WebSocket sessions
- Cron mode: deny all dangerous ops in scheduled jobs
"""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import stat
import threading
import time
import uuid
from collections import OrderedDict
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, NoReturn, cast

from js.security.secrets import redact_known_secrets
from js.utils.log import get_logger
from js.utils.metrics import get_metrics

logger = get_logger("js.approvals")


def _secure_str_eq(left: str | None, right: str | None) -> bool:
    """Constant-time equality for optional UTF-8 identity strings."""
    a = (left or "").encode("utf-8")
    b = (right or "").encode("utf-8")
    if len(a) != len(b):
        # Still touch both digests so length mismatch is not a pure short-circuit oracle.
        hmac.compare_digest(hashlib.sha256(a).digest(), hashlib.sha256(b).digest())
        return False
    return hmac.compare_digest(a, b)


DEFAULT_APPROVAL_TIMEOUT = 300.0  # 5 minutes
APPROVAL_ARGUMENTS_HASH_SCHEME = "stable_payload_hash:v1"
MODEL_EGRESS_KIND = "model_egress"
_MODEL_EGRESS_REQUEST_RE = re.compile(r"^meg:[0-9a-f]{32}$")

# Approval inputs cross an authority boundary, so bound their in-memory and
# serialized cost before hashing, callback projection, or durable persistence.
_SNAPSHOT_MAX_UTF8_BYTES = 256 * 1024
_SNAPSHOT_MAX_DEPTH = 32
_SNAPSHOT_MAX_NODES = 8192
_SNAPSHOT_MAX_STRING_UTF8_BYTES = 64 * 1024
_SNAPSHOT_MAX_KEY_UTF8_BYTES = 512


class ApprovalMode(StrEnum):
    MANUAL = "manual"
    AUTO_APPROVE = "auto_approve"
    AUTO_DENY = "auto_deny"
    CRON_DENY = "cron_deny"


class ApprovalDecisionType(StrEnum):
    PENDING = "pending"
    APPROVE = "approve"
    EDIT = "edit"
    REJECT = "reject"
    RESPOND = "respond"


@dataclass(frozen=True)
class ApprovalDecision:
    action: ApprovalDecisionType
    request_id: str = ""
    edited_arguments: dict[str, Any] | None = None
    response: str = ""
    reason: str = ""

    @property
    def approved(self) -> bool:
        return self.action in {ApprovalDecisionType.APPROVE, ApprovalDecisionType.EDIT}


@dataclass(frozen=True, slots=True)
class ApprovalClaimProof:
    """Immutable typed proof of an exactly-once approval claim.

    Returned by :meth:`ApprovalQueue.consume_approved_binding`.  All fields
    are frozen closed-set identities and hashes.  Only
    ``claimed_now is True`` authorises execution.
    """

    action: ApprovalDecisionType
    request_id: str
    arguments_hash: str
    binding_hash: str
    journal_record_hash: str
    journal_seq: int
    claimed_now: bool

    @property
    def approved(self) -> bool:
        return self.action in {ApprovalDecisionType.APPROVE, ApprovalDecisionType.EDIT}

    @property
    def decision(self) -> ApprovalDecision:
        """Return a fresh compatibility projection, never authority state."""

        return ApprovalDecision(self.action, request_id=self.request_id)


@dataclass
class ApprovalRequest:
    id: str
    tool_name: str
    arguments: dict[str, Any]
    timestamp: float
    context: str  # "cli", "web", "cron", "subagent"
    timeout_seconds: float = field(default=DEFAULT_APPROVAL_TIMEOUT)
    session_id: str | None = None
    run_id: str | None = None
    owner_key_hash: str | None = None
    approval_mode: ApprovalMode = ApprovalMode.MANUAL
    resolved: bool = False
    approved: bool = False
    decision: ApprovalDecision | None = None

    def is_expired(self) -> bool:
        return time.time() - self.timestamp > self.timeout_seconds


ApprovalCallback = Callable[[ApprovalRequest], bool | ApprovalDecision]


@dataclass(frozen=True)
class _CallbackRegistration:
    callback: ApprovalCallback
    owner_key_hash: str | None = None
    run_id: str | None = None
    tool_name: str | None = None
    arguments_hash: str | None = None


@dataclass(frozen=True)
class _ResolvedDecisionRecord:
    decision: ApprovalDecision
    owner_key_hash: str | None
    session_id: str
    run_id: str
    tool_name: str
    arguments_hash: str
    arguments_hash_scheme: str
    requested_at: float
    expires_at: float
    approval_mode: ApprovalMode


class ApprovalEchoAuthority:
    """Typed, sealed authority for atomic approval claims in EchoLedger.

    Created by ``EchoSafetyService``, passed to ``ApprovalQueue`` via
    ``set_echo_authority()`` (set-once).  Once sealed, cannot be replaced.
    All four methods (``claim_once``, ``lookup_claim``,
    ``lookup_resolution``, ``record_event``) operate on the same Echo
    journal partition.
    """

    __slots__ = ("_service", "_product_id", "_sealed")

    def __init__(self, service: Any, *, product_id: str) -> None:
        self._service = service
        self._product_id = product_id
        self._sealed = False

    def seal(self) -> None:
        self._sealed = True

    def claim_once(
        self,
        *,
        tenant_id: str,
        session_id: str,
        run_id: str,
        request_id: str,
        tool_name: str,
        arguments_hash: str,
        approval_mode: str,
        expires_at: float,
        requested_at: float,
        arguments_hash_scheme: str = APPROVAL_ARGUMENTS_HASH_SCHEME,
    ) -> Any:
        """Atomically claim one approval binding in the Echo journal."""
        return self._service.claim_approval_binding_once(
            tenant_id=tenant_id,
            product_id=self._product_id,
            session_id=session_id,
            run_id=run_id,
            request_id=request_id,
            tool_name=tool_name,
            arguments_hash=arguments_hash,
            approval_mode=approval_mode,
            expires_at=expires_at,
            requested_at=requested_at,
            arguments_hash_scheme=arguments_hash_scheme,
        )

    def lookup_claim(
        self,
        *,
        tenant_id: str,
        session_id: str,
        request_id: str,
    ) -> Any | None:
        """Query whether a claim exists in the Echo journal."""
        return self._service.lookup_approval_claim(
            tenant_id=tenant_id,
            product_id=self._product_id,
            session_id=session_id,
            request_id=request_id,
        )

    def lookup_resolution(
        self,
        *,
        tenant_id: str,
        session_id: str,
        request_id: str,
    ) -> Any | None:
        """Query the unique authoritative terminal for one request."""
        return self._service.lookup_approval_resolution(
            tenant_id=tenant_id,
            product_id=self._product_id,
            session_id=session_id,
            request_id=request_id,
        )

    def record_event(
        self,
        *,
        tenant_id: str,
        session_id: str,
        run_id: str,
        event_type: str,
        request_id: str,
        tool_name: str,
        arguments_hash: str,
        extra: dict[str, Any] | None = None,
    ) -> None:
        """Record a non-claim approval event (e.g. finalize)."""
        self._service.record_approval_event(
            tenant_id=tenant_id,
            product_id=self._product_id,
            session_id=session_id,
            run_id=run_id,
            event_type=event_type,
            request_id=request_id,
            tool_name=tool_name,
            arguments_hash=arguments_hash,
            extra=extra,
        )


class ApprovalQueue:
    """Async approval queue with session-scoped callbacks."""

    def __init__(
        self,
        default_mode: ApprovalMode = ApprovalMode.MANUAL,
        input_stream: Callable[[str], str] | None = None,
        default_timeout: float = DEFAULT_APPROVAL_TIMEOUT,
        ledger_path: Path | None = None,
    ) -> None:
        self._default_mode = default_mode
        self._input_stream = input_stream or input
        self._default_timeout = default_timeout
        self._pending: dict[str, ApprovalRequest] = {}
        self._callbacks: dict[str, _CallbackRegistration] = {}
        self._lock = threading.RLock()
        self._counter = 0
        self._history: dict[str, int] = {"total": 0, "approved": 0, "denied": 0}
        self._ledger_path = ledger_path
        if ledger_path is not None and ledger_path.is_symlink():
            raise ValueError("approval ledger must not be a symlink")
        self._ledger_seq = 0
        self._ledger_prev_hash = "0" * 64
        self._ledger_mac_key = self._derive_ledger_mac_key()
        self._resolved_decisions: OrderedDict[str, _ResolvedDecisionRecord] = OrderedDict()
        self._delivered_decisions: set[str] = set()
        # Authoritative EchoLedger sink for approval lifecycle events.  The
        # local JSONL file is only a derived mirror; the EchoLedger scope
        # partition journal is the system of record.
        self._echo_event_sink: Callable[[dict[str, Any]], None] | None = None
        # Typed, sealed Echo authority for atomic approval claims.
        self._echo_authority: ApprovalEchoAuthority | None = None
        self._echo_authority_sealed = False
        self._load_ledger_sequence()

    def set_echo_event_sink(self, sink: Callable[[dict[str, Any]], None] | None) -> None:
        """Install the authoritative EchoLedger sink for lifecycle events.

        Once installed, every approval lifecycle event is recorded into the
        EchoLedger scope partition journal (atomically ordered with the Echo
        run it belongs to).  Sink failures propagate: the approval flow fails
        closed rather than proceeding on the derived JSONL mirror alone.

        After ``set_echo_authority`` seals the queue, this method raises
        ``RuntimeError`` to prevent replacing the authority-bound sink.
        """
        if self._echo_authority_sealed:
            raise RuntimeError("echo authority is sealed; sink cannot be replaced")
        self._echo_event_sink = sink

    def set_echo_authority(self, authority: ApprovalEchoAuthority) -> None:
        """Install the typed, sealed Echo authority for atomic claims.

        Set-once: a second call raises ``RuntimeError``.  Once installed,
        ``consume_approved_binding`` uses the authority's atomic
        ``claim_once`` instead of trusting the local mirror.
        """
        if self._echo_authority_sealed:
            raise RuntimeError("echo authority is already sealed")
        self._echo_authority = authority
        self._echo_authority_sealed = True
        authority.seal()
        # Also wire the sink for non-claim events (approve, finalize, etc.)
        if self._echo_event_sink is None:
            self._echo_event_sink = lambda event: authority.record_event(
                tenant_id=str(event.get("owner_key_hash") or "local"),
                session_id=str(event.get("session_id") or ""),
                run_id=str(event.get("run_id") or ""),
                event_type=str(event["event_type"]),
                request_id=str(event.get("request_id") or ""),
                tool_name=str(event.get("tool_name") or ""),
                arguments_hash=str(event.get("arguments_hash") or ""),
                extra={
                    k: v
                    for k, v in event.items()
                    if k not in _SINK_CORE_FIELDS and k != "timestamp"
                },
            )

    def _derive_ledger_mac_key(self) -> bytes:
        """Derive a per-installation MAC key from a secret file.

        Never hardcode the MAC key in source: an attacker with source access
        could forge ledger entries.  The key is derived from a random secret
        stored alongside the ledger (mode 0600) so each installation signs
        with a different key.

        When a persistent ledger is configured, any failure is fatal: falling
        back to an ephemeral in-memory key would split the MAC domain between
        processes and silently invalidate the chain, so we fail closed.

        Key material is opened via ``dir_fd`` + ``O_NOFOLLOW`` + ``fstat``,
        created with a random ``O_EXCL`` temp file, and published with
        ``link`` so concurrent first-init cannot observe a partial key.
        """
        if self._ledger_path is None:
            # No ledger -> ephemeral random key for this process.
            return os.urandom(32)

        parent = self._ledger_path.parent
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        key_name = ".approval_ledger_mac_key"
        secret_path = parent / key_name
        if secret_path.is_symlink():
            raise ValueError("approval ledger mac key must not be a symlink")

        nofollow = getattr(os, "O_NOFOLLOW", 0)
        dir_flags = (
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | nofollow
        )
        use_dir_fd = (
            hasattr(os, "O_DIRECTORY")
            and os.open in getattr(os, "supports_dir_fd", set())
            and os.stat in getattr(os, "supports_dir_fd", set())
        )

        def _validate_and_read(fd: int) -> bytes:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError("approval ledger mac key must be a regular file")
            # Existing keys must already be 0600. Never chmod-then-accept a key
            # that may have been world/group-readable (possible leak).
            mode = stat.S_IMODE(metadata.st_mode)
            if mode != 0o600:
                raise PermissionError(
                    f"approval ledger mac key permissions too open: {oct(mode)}; expected 0o600"
                )
            key = os.read(fd, 33)
            if len(key) != 32:
                raise ValueError("approval ledger mac key file is invalid: expected exact 32 bytes")
            return key

        def _create_key(dir_fd: int | None) -> None:
            key = os.urandom(32)
            tmp_name = f".{key_name}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
            open_kwargs: dict[str, Any] = {}
            if dir_fd is not None:
                open_kwargs["dir_fd"] = dir_fd
            fd = os.open(
                tmp_name if dir_fd is not None else str(parent / tmp_name),
                os.O_CREAT | os.O_WRONLY | os.O_EXCL | nofollow,
                0o600,
                **open_kwargs,
            )
            try:
                os.fchmod(fd, 0o600)
                os.write(fd, key)
                os.fsync(fd)
            finally:
                os.close(fd)
            try:
                if dir_fd is not None and os.link in getattr(os, "supports_dir_fd", set()):
                    os.link(tmp_name, key_name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
                else:
                    os.link(str(parent / tmp_name), str(secret_path))
            except FileExistsError:
                # Another process won the race; fall through and use its key.
                pass
            finally:
                try:
                    if dir_fd is not None and os.unlink in getattr(os, "supports_dir_fd", set()):
                        os.unlink(tmp_name, dir_fd=dir_fd)
                    else:
                        (parent / tmp_name).unlink(missing_ok=True)
                except FileNotFoundError:
                    pass
            if dir_fd is not None:
                os.fsync(dir_fd)
            else:
                sync_fd = os.open(str(parent), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                try:
                    os.fsync(sync_fd)
                finally:
                    os.close(sync_fd)

        dir_fd = -1
        try:
            if use_dir_fd:
                dir_fd = os.open(str(parent), dir_flags)
                dir_meta = os.fstat(dir_fd)
                if not stat.S_ISDIR(dir_meta.st_mode):
                    raise ValueError("approval ledger mac key parent must be a directory")
                try:
                    fd = os.open(key_name, os.O_RDONLY | nofollow, dir_fd=dir_fd)
                except FileNotFoundError:
                    _create_key(dir_fd)
                    fd = os.open(key_name, os.O_RDONLY | nofollow, dir_fd=dir_fd)
                try:
                    key = _validate_and_read(fd)
                finally:
                    os.close(fd)
            else:
                parent_fd = os.open(str(parent), dir_flags)
                try:
                    parent_meta = os.fstat(parent_fd)
                    if not stat.S_ISDIR(parent_meta.st_mode):
                        raise ValueError("approval ledger mac key parent must be a directory")
                finally:
                    os.close(parent_fd)
                try:
                    fd = os.open(str(secret_path), os.O_RDONLY | nofollow)
                except FileNotFoundError:
                    _create_key(None)
                    fd = os.open(str(secret_path), os.O_RDONLY | nofollow)
                except OSError as exc:
                    raise ValueError("approval ledger mac key must be a regular file") from exc
                try:
                    key = _validate_and_read(fd)
                finally:
                    os.close(fd)
        except PermissionError:
            # Unwritable ledger directory must fail closed as OSError so callers
            # never fall back to an ephemeral MAC key.
            raise
        except OSError as exc:
            if isinstance(exc, FileNotFoundError):
                raise
            raise ValueError("approval ledger mac key must be a regular file") from exc
        finally:
            if dir_fd >= 0:
                os.close(dir_fd)

        return key

    @property
    def default_mode(self) -> ApprovalMode:
        return self._default_mode

    @default_mode.setter
    def default_mode(self, value: ApprovalMode) -> None:
        """Immutable after init — reject runtime changes for safety."""
        prev = getattr(self, "_default_mode", None)
        if prev is not None and prev != value:
            logger.error(
                "Rejected attempt to change approval default_mode from %s to %s",
                prev,
                value,
            )
            raise RuntimeError(
                f"Cannot change approval mode from {prev} to {value} at runtime. "
                "Create a new ApprovalQueue with the desired mode."
            )
        self._default_mode = value

    def _next_id(self) -> str:
        return f"approval_{uuid.uuid4().hex}"

    def _load_ledger_sequence(self) -> None:
        if self._ledger_path is None or not self._ledger_path.exists():
            return
        max_sequence = -1
        prev_hash = "0" * 64
        try:
            with self._ledger_path.open("r", encoding="utf-8") as handle:
                for raw_line in handle:
                    if not raw_line.strip():
                        continue
                    try:
                        row = json.loads(raw_line)
                        sequence = int(row["seq"])
                    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                        if max_sequence < 0:
                            logger.error(
                                "Echo approval ledger first record is corrupt; failing closed"
                            )
                            raise ValueError("approval ledger first record is corrupt") from None
                        logger.warning("Ignoring invalid Echo approval ledger tail")
                        break
                    # Verify hash chain and MAC
                    expected_prev = row.get("prev_hash", "")
                    if expected_prev != prev_hash:
                        logger.error("Echo approval ledger hash chain broken at seq %d", sequence)
                        raise ValueError(f"approval ledger hash chain broken at seq {sequence}")
                    record_hash = row.get("record_hash", "")
                    mac = row.get("mac", "")
                    canonical = json.dumps(
                        {k: v for k, v in row.items() if k not in ("record_hash", "mac")},
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                        default=str,
                    ).encode("utf-8")
                    expected_hash = "sha256:" + hashlib.sha256(canonical).hexdigest()
                    if record_hash != expected_hash:
                        logger.error(
                            "Echo approval ledger record_hash mismatch at seq %d", sequence
                        )
                        raise ValueError(f"approval ledger record_hash mismatch at seq {sequence}")
                    expected_mac = hmac.new(
                        self._ledger_mac_key, canonical, hashlib.sha256
                    ).hexdigest()
                    if not hmac.compare_digest(str(mac), expected_mac):
                        logger.error("Echo approval ledger MAC mismatch at seq %d", sequence)
                        raise ValueError(f"approval ledger MAC mismatch at seq {sequence}")
                    max_sequence = max(max_sequence, sequence)
                    prev_hash = record_hash.removeprefix("sha256:")
        except OSError:
            logger.warning("Could not read Echo approval ledger", exc_info=True)
            raise
        self._ledger_seq = max_sequence + 1
        self._ledger_prev_hash = prev_hash

    def _store_resolved_decision(
        self,
        decision: ApprovalDecision,
        request: ApprovalRequest,
        *,
        final_arguments_hash: str | None = None,
    ) -> None:
        # For EDIT decisions the binding hash must reference the *edited*
        # final arguments, not the original request arguments.  The caller
        # may pass ``final_arguments_hash`` to override; otherwise we fall
        # back to the original request arguments hash.
        args_hash = final_arguments_hash
        if args_hash is None:
            if decision.action is ApprovalDecisionType.EDIT and isinstance(
                decision.edited_arguments, dict
            ):
                args_hash = self._argument_hash(decision.edited_arguments)
            else:
                args_hash = self._argument_hash(request.arguments)
        stored_decision = self._clone_decision(decision)
        self._resolved_decisions[decision.request_id] = _ResolvedDecisionRecord(
            decision=stored_decision,
            owner_key_hash=request.owner_key_hash,
            session_id=request.session_id or "",
            run_id=request.run_id or "",
            tool_name=request.tool_name,
            arguments_hash=args_hash,
            arguments_hash_scheme=APPROVAL_ARGUMENTS_HASH_SCHEME,
            requested_at=request.timestamp,
            expires_at=request.timestamp + request.timeout_seconds,
            approval_mode=request.approval_mode,
        )
        self._delivered_decisions.discard(decision.request_id)
        self._resolved_decisions.move_to_end(decision.request_id)
        while len(self._resolved_decisions) > 1024:
            evicted_request_id, _evicted = self._resolved_decisions.popitem(last=False)
            self._delivered_decisions.discard(evicted_request_id)

    def _record_outcome(self, approved: bool) -> None:
        with self._lock:
            self._history["total"] += 1
            if approved:
                self._history["approved"] += 1
            else:
                self._history["denied"] += 1

    @staticmethod
    def _argument_hash(arguments: dict[str, Any]) -> str:
        from js.echo.primitives import stable_payload_hash

        return stable_payload_hash(arguments)

    @classmethod
    def arguments_hash(cls, arguments: dict[str, Any]) -> str:
        """Return the exact safe hash used by approval binding snapshots."""

        return cls._argument_hash(cls.snapshot_arguments(arguments))

    @classmethod
    def snapshot_arguments(cls, value: Any) -> dict[str, Any]:
        """Return a bounded exact-JSON deep snapshot with fixed safe errors."""

        nodes = 0
        aggregate_utf8_bytes = 0

        def limit() -> NoReturn:
            raise ValueError("approval snapshot exceeds limits")

        def unsafe() -> NoReturn:
            raise ValueError("approval snapshot is not JSON-safe")

        def bounded_utf8(text: str, maximum: int) -> None:
            nonlocal aggregate_utf8_bytes
            # Every Unicode code point needs at least one UTF-8 byte, so this
            # cheap character bound avoids encoding attacker-sized strings
            # merely to decide that they exceed the byte limit.
            if len(text) > maximum:
                limit()
            try:
                byte_length = len(text.encode("utf-8"))
            except UnicodeEncodeError:
                unsafe()
            if byte_length > maximum:
                limit()
            aggregate_utf8_bytes += byte_length
            if aggregate_utf8_bytes > _SNAPSHOT_MAX_UTF8_BYTES:
                limit()

        def visit(item: Any, depth: int) -> Any:
            nonlocal nodes
            if depth > _SNAPSHOT_MAX_DEPTH:
                limit()
            nodes += 1
            if nodes > _SNAPSHOT_MAX_NODES:
                limit()
            if type(item) is dict:
                result: dict[str, Any] = {}
                for key, child in item.items():
                    if type(key) is not str:
                        unsafe()
                    bounded_utf8(key, _SNAPSHOT_MAX_KEY_UTF8_BYTES)
                    result[key] = visit(child, depth + 1)
                return result
            if type(item) is list:
                return [visit(child, depth + 1) for child in item]
            if item is None or type(item) in {bool, int}:
                if type(item) is int:
                    # Decimal digits <= ceil(bit_length * log10(2)) + sign.
                    # Reject one chunk that could itself exceed the document
                    # budget without materializing its decimal representation.
                    digit_upper_bound = (item.bit_length() * 30103 + 99_999) // 100_000
                    if digit_upper_bound + int(item < 0) > _SNAPSHOT_MAX_UTF8_BYTES:
                        limit()
                return item
            if type(item) is float:
                if not math.isfinite(item):
                    unsafe()
                return item
            if type(item) is str:
                bounded_utf8(item, _SNAPSHOT_MAX_STRING_UTF8_BYTES)
                return item
            unsafe()

        if type(value) is not dict:
            unsafe()
        snapshot = cast("dict[str, Any]", visit(value, 0))
        encoder = json.JSONEncoder(
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        encoded_size = 0
        try:
            for chunk in encoder.iterencode(snapshot):
                encoded_size += len(chunk.encode("utf-8"))
                if encoded_size > _SNAPSHOT_MAX_UTF8_BYTES:
                    limit()
        except ValueError as exc:
            if str(exc) == "approval snapshot exceeds limits":
                raise
            unsafe()
        except (TypeError, OverflowError, UnicodeEncodeError):
            unsafe()
        return snapshot

    _json_safe_deep_snapshot = snapshot_arguments

    @classmethod
    def _clone_decision(cls, decision: ApprovalDecision) -> ApprovalDecision:
        edited = (
            cls.snapshot_arguments(decision.edited_arguments)
            if decision.action is ApprovalDecisionType.EDIT
            and decision.edited_arguments is not None
            else None
        )
        return ApprovalDecision(
            decision.action,
            request_id=str(decision.request_id),
            edited_arguments=edited,
            response=decision.response if type(decision.response) is str else "",
            reason=decision.reason if type(decision.reason) is str else "",
        )

    @classmethod
    def _clone_request(cls, request: ApprovalRequest) -> ApprovalRequest:
        decision = cls._clone_decision(request.decision) if request.decision else None
        return ApprovalRequest(
            id=request.id,
            tool_name=request.tool_name,
            arguments=cls.snapshot_arguments(request.arguments),
            timestamp=request.timestamp,
            context=request.context,
            timeout_seconds=request.timeout_seconds,
            session_id=request.session_id,
            run_id=request.run_id,
            owner_key_hash=request.owner_key_hash,
            approval_mode=request.approval_mode,
            resolved=request.resolved,
            approved=request.approved,
            decision=decision,
        )

    def _commit_pending_decision(
        self,
        request: ApprovalRequest,
        decision: ApprovalDecision,
        *,
        event_type: str,
        ledger_kwargs: dict[str, Any] | None = None,
    ) -> tuple[bool, ApprovalDecision]:
        """Commit the sole terminal decision for a published manual request.

        The request is marked resolved before calling the authoritative sink,
        which closes both cross-thread races and same-thread sink re-entry.
        Any uncertain authoritative failure permanently retires the id.
        """

        with self._lock:
            current = self._pending.get(request.id)
            if current is not request or request.resolved:
                winning = request.decision
                if winning is not None:
                    return False, self._clone_decision(winning)
                return False, ApprovalDecision(
                    ApprovalDecisionType.PENDING,
                    request_id=request.id,
                )

            stored = self._clone_decision(decision)
            request.resolved = True
            request.approved = stored.approved
            request.decision = stored
            kwargs = dict(ledger_kwargs or {})
            try:
                self._append_ledger(event_type, request, **kwargs)
                self._store_resolved_decision(
                    stored,
                    request,
                    final_arguments_hash=cast(
                        "str | None",
                        kwargs.get("final_arguments_hash"),
                    ),
                )
                self._pending.pop(request.id, None)
            except Exception:
                request.approved = False
                request.decision = None
                self._resolved_decisions.pop(request.id, None)
                self._delivered_decisions.discard(request.id)
                if self._echo_event_sink is not None and self._echo_authority is None:
                    # A legacy sink-only queue has no claim authority, so a
                    # definite before-write failure may remain retryable while
                    # execution stays fail-closed.  Typed Echo authority errors
                    # are outcome-uncertain and permanently retire the id.
                    request.resolved = False
                else:
                    self._pending.pop(request.id, None)
                raise
            return True, self._clone_decision(stored)

    @classmethod
    def _redact_ledger_value(cls, value: Any) -> Any:
        """Recursively scrub client-controlled ledger fields before persistence."""
        try:
            if isinstance(value, str):
                return redact_known_secrets(value)
            if isinstance(value, dict):
                return {str(key): cls._redact_ledger_value(item) for key, item in value.items()}
            if isinstance(value, (list, tuple)):
                return [cls._redact_ledger_value(item) for item in value]
            if value is None or isinstance(value, (bool, int, float)):
                return value
            return redact_known_secrets(str(value))
        except Exception:
            return "[SUPPRESSED:ledger_redaction_failed]"

    def _append_ledger(
        self,
        event_type: str,
        req: ApprovalRequest,
        *,
        final_arguments_hash: str | None = None,
        original_arguments_hash: str | None = None,
        **extra: Any,
    ) -> None:
        reason = extra.pop("reason", "")
        if reason:
            safe_reason = reason if type(reason) is str else "invalid_reason"
            extra["reason_hash"] = self._argument_hash({"reason": safe_reason})
        event = {
            "event_type": event_type,
            "request_id": req.id,
            "tool_name": req.tool_name,
            "context": req.context,
            "session_id": req.session_id or "",
            "run_id": req.run_id or "",
            "owner_key_hash": req.owner_key_hash or "",
            "arguments_hash": final_arguments_hash or self._argument_hash(req.arguments),
            "arguments_hash_scheme": APPROVAL_ARGUMENTS_HASH_SCHEME,
            "timestamp": req.timestamp,
            "requested_at": req.timestamp,
            "expires_at": req.timestamp + req.timeout_seconds,
            "approval_mode": req.approval_mode.value,
            **extra,
        }
        if original_arguments_hash is not None:
            event["original_arguments_hash"] = original_arguments_hash
        event = self._redact_ledger_value(event)
        # The EchoLedger scope partition journal is the authoritative record.
        # Call it before the derived mirror so a sink failure cannot leave a
        # locally claimable approval that the authoritative journal never saw.
        authority_persisted = False
        if self._echo_event_sink is not None:
            self._echo_event_sink(dict(event))
            authority_persisted = self._echo_authority is not None
        if self._ledger_path is not None:
            try:
                with self._lock:
                    self._append_ledger_mirror(event)
            except Exception:
                if not authority_persisted:
                    raise
                # The local JSONL is a derived cache once an Echo authority is
                # installed.  Never expose exception type, text, or path.
                logger.warning("Approval mirror append failed after authoritative success")

    def _append_ledger_mirror(self, event: dict[str, Any]) -> None:
        """Append to the derived local JSONL mirror (not the system of record)."""
        assert self._ledger_path is not None
        self._ledger_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(
            self._ledger_path,
            os.O_APPEND | os.O_CREAT | os.O_WRONLY,
            0o600,
        )
        try:
            os.fchmod(fd, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX)
            # Re-read the tail under the exclusive file lock so concurrent
            # ApprovalQueue instances (or processes) cannot write with a
            # stale prev_hash/seq and break the hash chain.
            seq, prev_hash = self._read_ledger_tail_locked()
            record = {
                "seq": seq,
                **event,
                "prev_hash": prev_hash,
            }
            canonical = json.dumps(
                record,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                default=str,
            ).encode("utf-8")
            record_hash = "sha256:" + hashlib.sha256(canonical).hexdigest()
            mac = hmac.new(self._ledger_mac_key, canonical, hashlib.sha256).hexdigest()
            record["record_hash"] = record_hash
            record["mac"] = mac
            payload = (
                json.dumps(
                    record,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    default=str,
                )
                + "\n"
            )
            os.write(fd, payload.encode("utf-8"))
            os.fsync(fd)
            fcntl.flock(fd, fcntl.LOCK_UN)
            self._ledger_seq = seq + 1
            self._ledger_prev_hash = record_hash.removeprefix("sha256:")
        finally:
            os.close(fd)

    def _read_ledger_tail_locked(self) -> tuple[int, str]:
        """Read the last valid record's (seq, prev_hash_for_next) under the file lock.

        Returns ``(0, "0"*64)`` when the ledger is empty or does not exist.
        Validates the hash chain of the full file on first read so a corrupt
        tail cannot silently propagate.
        """
        if self._ledger_path is None or not self._ledger_path.exists():
            return 0, "0" * 64
        prev_hash = "0" * 64
        max_seq = -1
        with self._ledger_path.open("r", encoding="utf-8") as handle:
            for raw_line in handle:
                if not raw_line.strip():
                    continue
                try:
                    row = json.loads(raw_line)
                    seq = int(row["seq"])
                except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                    if max_seq < 0:
                        raise ValueError("approval ledger first record is corrupt") from None
                    break
                expected_prev = row.get("prev_hash", "")
                if expected_prev != prev_hash:
                    raise ValueError(f"approval ledger hash chain broken at seq {seq}")
                record_hash = row.get("record_hash", "")
                canonical = json.dumps(
                    {k: v for k, v in row.items() if k not in ("record_hash", "mac")},
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    default=str,
                ).encode("utf-8")
                expected_hash = "sha256:" + hashlib.sha256(canonical).hexdigest()
                if record_hash != expected_hash:
                    raise ValueError(f"approval ledger record_hash mismatch at seq {seq}")
                expected_mac = hmac.new(self._ledger_mac_key, canonical, hashlib.sha256).hexdigest()
                if not hmac.compare_digest(str(row.get("mac", "")), expected_mac):
                    raise ValueError(f"approval ledger MAC mismatch at seq {seq}")
                max_seq = max(max_seq, seq)
                prev_hash = record_hash.removeprefix("sha256:")
        return (max_seq + 1) if max_seq >= 0 else 0, prev_hash

    def _verified_ledger_rows(self) -> list[dict[str, Any]]:
        """Read the complete approval mirror with exact chain/MAC validation."""

        if self._ledger_path is None or not self._ledger_path.exists():
            return []
        rows: list[dict[str, Any]] = []
        prev_hash = "0" * 64
        expected_seq = 0
        with self._ledger_path.open("r", encoding="utf-8") as handle:
            for raw_line in handle:
                if not raw_line.strip():
                    continue
                try:
                    row = json.loads(raw_line)
                except json.JSONDecodeError as exc:
                    raise ValueError("approval ledger contains invalid JSON") from exc
                if type(row) is not dict or int(row.get("seq", -1)) != expected_seq:
                    raise ValueError("approval ledger sequence is invalid")
                if row.get("prev_hash") != prev_hash:
                    raise ValueError("approval ledger hash chain is invalid")
                canonical = json.dumps(
                    {key: value for key, value in row.items() if key not in ("record_hash", "mac")},
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    default=str,
                ).encode("utf-8")
                record_hash = "sha256:" + hashlib.sha256(canonical).hexdigest()
                if row.get("record_hash") != record_hash:
                    raise ValueError("approval ledger record hash is invalid")
                expected_mac = hmac.new(self._ledger_mac_key, canonical, hashlib.sha256).hexdigest()
                if not hmac.compare_digest(str(row.get("mac", "")), expected_mac):
                    raise ValueError("approval ledger MAC is invalid")
                rows.append(cast("dict[str, Any]", row))
                expected_seq += 1
                prev_hash = record_hash.removeprefix("sha256:")
        return rows

    def _emit_metrics(
        self,
        tool_name: str,
        mode: ApprovalMode,
        approved: bool,
    ) -> None:
        try:
            get_metrics().approval_requests_total.labels(
                tool_name=tool_name,
                mode=mode.value,
                outcome="approved" if approved else "denied",
            ).inc()
        except Exception:
            logger.warning("Failed to emit approval metrics", exc_info=True)

    def _audit_log(
        self,
        req: ApprovalRequest,
        outcome: str,
        reason: str = "",
    ) -> None:
        elapsed = time.time() - req.timestamp
        reason_hash = self._argument_hash({"reason": reason}) if reason else ""
        logger.info(
            "AUDIT approval_id=%s tool=%s context=%s mode=%s outcome=%s elapsed=%.2fs %s",
            req.id,
            req.tool_name,
            req.context,
            self.default_mode.value,
            outcome,
            elapsed,
            f"reason_hash={reason_hash}" if reason_hash else "",
        )

    def _cleanup_stale(self) -> int:
        """Remove expired pending requests. Returns count removed."""
        removed = 0
        with self._lock:
            stale_ids = [
                req_id
                for req_id, req in self._pending.items()
                if not req.resolved and req.is_expired()
            ]
            for req_id in stale_ids:
                req = self._pending.pop(req_id)
                req.resolved = True
                req.approved = False
                req.decision = ApprovalDecision(
                    ApprovalDecisionType.REJECT,
                    request_id=req.id,
                    reason="timeout",
                )
                self._store_resolved_decision(req.decision, req)
                self._record_outcome(False)
                self._append_ledger("approval_expired", req, reason="timeout")
                self._audit_log(req, "expired", "timeout")
                self._emit_metrics(req.tool_name, self.default_mode, False)
                removed += 1
        if removed:
            logger.warning("Cleaned up %d stale approval requests", removed)
        return removed

    def set_callback(
        self,
        session_id: str,
        callback: ApprovalCallback,
        *,
        owner_key_hash: str | None = None,
        run_id: str | None = None,
        tool_name: str | None = None,
        arguments: dict[str, Any] | None = None,
    ) -> None:
        """Set a session callback bound to one exact Echo effect."""
        if not session_id:
            raise ValueError("approval callback session_id must not be empty")
        if not owner_key_hash or not run_id or not tool_name or arguments is None:
            raise ValueError("approval callback requires a complete Echo effect binding")
        arguments_snapshot = self.snapshot_arguments(arguments)
        with self._lock:
            self._callbacks[session_id] = _CallbackRegistration(
                callback=callback,
                owner_key_hash=owner_key_hash,
                run_id=run_id,
                tool_name=tool_name,
                arguments_hash=self._argument_hash(arguments_snapshot),
            )

    def remove_callback(self, session_id: str) -> None:
        """Remove a session callback."""
        with self._lock:
            self._callbacks.pop(session_id, None)

    def revoke_for_session(
        self,
        *,
        owner_key_hash: str,
        session_id: str,
        reason: str = "session_revoked",
    ) -> tuple[str, ...]:
        """Reject pending approvals bound to one verified owner/session.

        AppShell mode changes call this beside capability-lease revocation so
        a decision queued in the departing mode cannot be approved after the
        browser reconnects to a different runtime.
        """
        if not owner_key_hash or not session_id:
            raise ValueError("approval revocation requires owner_key_hash and session_id")
        revoked: list[ApprovalRequest] = []
        with self._lock:
            for request_id, request in tuple(self._pending.items()):
                if request.resolved or request.session_id != session_id:
                    continue
                if not _secure_str_eq(request.owner_key_hash, owner_key_hash):
                    continue
                decision = ApprovalDecision(
                    ApprovalDecisionType.REJECT,
                    request_id=request.id,
                    reason=reason,
                )
                request.resolved = True
                request.approved = False
                request.decision = decision
                self._pending.pop(request_id, None)
                self._store_resolved_decision(decision, request)
                revoked.append(request)

            registration = self._callbacks.get(session_id)
            if registration is not None and _secure_str_eq(
                registration.owner_key_hash,
                owner_key_hash,
            ):
                self._callbacks.pop(session_id, None)

        for request in revoked:
            self._record_outcome(False)
            self._emit_metrics(request.tool_name, self.default_mode, False)
            self._append_ledger("approval_rejected", request, reason=reason)
            self._audit_log(request, "denied", reason)
        return tuple(request.id for request in revoked)

    def request(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        context: str = "cli",
        mode: ApprovalMode | None = None,
        session_id: str | None = None,
        timeout_seconds: float | None = None,
    ) -> bool:
        """Request approval for a dangerous operation. Returns True if approved."""
        decision = self.request_decision(
            tool_name=tool_name,
            arguments=arguments,
            context=context,
            mode=mode,
            session_id=session_id,
            timeout_seconds=timeout_seconds,
            queue_if_unhandled=False,
        )
        return decision.approved

    def request_decision(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        context: str = "cli",
        mode: ApprovalMode | None = None,
        session_id: str | None = None,
        timeout_seconds: float | None = None,
        *,
        run_id: str | None = None,
        owner_key_hash: str | None = None,
        queue_if_unhandled: bool = False,
        request_id: str | None = None,
    ) -> ApprovalDecision:
        """Request an Echo approval decision for a dangerous operation."""
        # Periodic cleanup of stale requests
        self._cleanup_stale()

        resolved_mode = mode or self.default_mode
        if tool_name == MODEL_EGRESS_KIND:
            if mode in {
                ApprovalMode.AUTO_APPROVE,
                ApprovalMode.AUTO_DENY,
                ApprovalMode.CRON_DENY,
            }:
                denied = ApprovalRequest(
                    id=self._next_id(),
                    tool_name=tool_name,
                    arguments=self.snapshot_arguments(arguments),
                    timestamp=time.time(),
                    context=context,
                    timeout_seconds=timeout_seconds or self._default_timeout,
                    session_id=session_id,
                    run_id=run_id,
                    owner_key_hash=owner_key_hash,
                    approval_mode=ApprovalMode.MANUAL,
                )
                self._append_ledger("approval_requested", denied)
                self._append_ledger(
                    "approval_rejected",
                    denied,
                    reason="model_egress_manual_only",
                )
                self._audit_log(denied, "denied", "model_egress_manual_only")
                return ApprovalDecision(
                    ApprovalDecisionType.REJECT,
                    request_id=denied.id,
                    reason="model_egress_manual_only",
                )
            resolved_mode = ApprovalMode.MANUAL

        # JSON-safe bounded deep snapshot: rejects custom objects, NaN, Inf,
        # and isolates the queue from caller mutations.
        arguments = self.snapshot_arguments(arguments)

        stable_request_id = ""
        if tool_name == MODEL_EGRESS_KIND and request_id is not None:
            if type(request_id) is not str or not _MODEL_EGRESS_REQUEST_RE.fullmatch(request_id):
                denied = ApprovalRequest(
                    id=self._next_id(),
                    tool_name=tool_name,
                    arguments=arguments,
                    timestamp=time.time(),
                    context=context,
                    timeout_seconds=timeout_seconds or self._default_timeout,
                    session_id=session_id,
                    run_id=run_id,
                    owner_key_hash=owner_key_hash,
                    approval_mode=ApprovalMode.MANUAL,
                )
                self._append_ledger("approval_requested", denied)
                self._append_ledger(
                    "approval_rejected",
                    denied,
                    reason="model_egress_request_identity",
                )
                self._audit_log(denied, "denied", "model_egress_request_identity")
                return ApprovalDecision(
                    ApprovalDecisionType.REJECT,
                    request_id=denied.id,
                    reason="model_egress_request_identity",
                )
            stable_request_id = request_id
            with self._lock:
                existing_pending = self._pending.get(stable_request_id)
            if existing_pending is not None:
                return ApprovalDecision(
                    ApprovalDecisionType.PENDING,
                    request_id=stable_request_id,
                )
            existing_resolved = self._resolved_decisions.get(stable_request_id)
            if existing_resolved is None:
                existing_resolved = self._durable_resolved_record(stable_request_id)
            if existing_resolved is not None:
                return self._clone_decision(existing_resolved.decision)

        if resolved_mode == ApprovalMode.AUTO_APPROVE:
            auto_req = ApprovalRequest(
                id=self._next_id(),
                tool_name=tool_name,
                arguments=arguments,
                timestamp=time.time(),
                context=context,
                timeout_seconds=timeout_seconds or self._default_timeout,
                session_id=session_id,
                run_id=run_id,
                owner_key_hash=owner_key_hash,
                approval_mode=resolved_mode,
            )
            # AUTO_APPROVE must still honor an existing session callback binding
            # so a cross-owner / cross-run request cannot skip the Echo gate.
            if session_id:
                with self._lock:
                    registration = self._callbacks.get(session_id)
                if registration is not None:
                    binding_mismatch = any(
                        (
                            registration.owner_key_hash is not None
                            and not _secure_str_eq(
                                registration.owner_key_hash, auto_req.owner_key_hash
                            ),
                            registration.run_id is not None
                            and not _secure_str_eq(registration.run_id, auto_req.run_id),
                            registration.tool_name is not None
                            and registration.tool_name != auto_req.tool_name,
                            registration.arguments_hash is not None
                            and registration.arguments_hash
                            != self._argument_hash(auto_req.arguments),
                        )
                    )
                    if binding_mismatch:
                        logger.warning(
                            "Auto-approve denied %s due to session binding mismatch",
                            tool_name,
                        )
                        self._record_outcome(False)
                        self._emit_metrics(tool_name, resolved_mode, False)
                        self._append_ledger("approval_requested", auto_req)
                        self._append_ledger(
                            "approval_rejected",
                            auto_req,
                            reason="auto_approve_binding_mismatch",
                        )
                        self._audit_log(auto_req, "denied", "auto_approve_binding_mismatch")
                        return ApprovalDecision(
                            ApprovalDecisionType.REJECT,
                            request_id=auto_req.id,
                            reason="auto_approve_binding_mismatch",
                        )
            logger.info("Auto-approved %s (auto_approve mode)", tool_name)
            self._record_outcome(True)
            self._emit_metrics(tool_name, resolved_mode, True)
            self._append_ledger("approval_requested", auto_req)
            self._append_ledger("approval_approved", auto_req, reason="auto_approve")
            auto_decision = ApprovalDecision(
                ApprovalDecisionType.APPROVE,
                request_id=auto_req.id,
                reason="auto_approve",
            )
            auto_req.resolved = True
            auto_req.approved = True
            auto_req.decision = self._clone_decision(auto_decision)
            self._store_resolved_decision(auto_decision, auto_req)
            self._audit_log(auto_req, "approved", "auto_approve")
            return self._clone_decision(auto_decision)

        if resolved_mode == ApprovalMode.AUTO_DENY:
            logger.warning("Auto-denied %s (auto_deny mode)", tool_name)
            self._record_outcome(False)
            self._emit_metrics(tool_name, resolved_mode, False)
            auto_req = ApprovalRequest(
                id=self._next_id(),
                tool_name=tool_name,
                arguments=arguments,
                timestamp=time.time(),
                context=context,
                timeout_seconds=timeout_seconds or self._default_timeout,
                session_id=session_id,
                run_id=run_id,
                owner_key_hash=owner_key_hash,
                approval_mode=resolved_mode,
            )
            self._append_ledger("approval_requested", auto_req)
            self._append_ledger("approval_rejected", auto_req, reason="auto_deny")
            self._audit_log(auto_req, "denied", "auto_deny")
            return ApprovalDecision(
                ApprovalDecisionType.REJECT,
                request_id=auto_req.id,
                reason="auto_deny",
            )

        if resolved_mode == ApprovalMode.CRON_DENY and context == "cron":
            logger.warning("Auto-denied %s (cron_deny mode)", tool_name)
            self._record_outcome(False)
            self._emit_metrics(tool_name, resolved_mode, False)
            auto_req = ApprovalRequest(
                id=self._next_id(),
                tool_name=tool_name,
                arguments=arguments,
                timestamp=time.time(),
                context=context,
                timeout_seconds=timeout_seconds or self._default_timeout,
                session_id=session_id,
                run_id=run_id,
                owner_key_hash=owner_key_hash,
                approval_mode=resolved_mode,
            )
            self._append_ledger("approval_requested", auto_req)
            self._append_ledger("approval_rejected", auto_req, reason="cron_deny")
            self._audit_log(auto_req, "denied", "cron_deny")
            return ApprovalDecision(
                ApprovalDecisionType.REJECT,
                request_id=auto_req.id,
                reason="cron_deny",
            )

        # MANUAL mode: check for callback or block
        req = ApprovalRequest(
            id=stable_request_id or self._next_id(),
            tool_name=tool_name,
            arguments=arguments,
            timestamp=time.time(),
            context=context,
            timeout_seconds=timeout_seconds or self._default_timeout,
            session_id=session_id,
            run_id=run_id,
            owner_key_hash=owner_key_hash,
            approval_mode=resolved_mode,
        )

        # Publish into the pending decision surface only after the
        # authoritative requested event succeeds.  A failed or uncertain
        # requested append therefore cannot leave an approvable request id.
        self._append_ledger("approval_requested", req)
        with self._lock:
            self._pending[req.id] = req

        # Try session callback first (lookup under lock to avoid TOCTOU)
        callback: ApprovalCallback | None = None
        callback_binding_mismatch = False
        if session_id:
            with self._lock:
                registration = self._callbacks.get(session_id)
            if registration is not None:
                callback_binding_mismatch = any(
                    (
                        (
                            registration.owner_key_hash is not None
                            and not _secure_str_eq(registration.owner_key_hash, req.owner_key_hash)
                        ),
                        (registration.run_id is not None and registration.run_id != req.run_id),
                        (
                            registration.tool_name is not None
                            and registration.tool_name != req.tool_name
                        ),
                        (
                            registration.arguments_hash is not None
                            and registration.arguments_hash != self._argument_hash(req.arguments)
                        ),
                    ),
                )
                if not callback_binding_mismatch:
                    callback = registration.callback

        if callback:
            try:
                callback_result = callback(self._clone_request(req))
                if type(callback_result) is ApprovalDecision:
                    if type(callback_result.action) is not ApprovalDecisionType:
                        raise ValueError("approval callback action is invalid")
                    if callback_result.action is ApprovalDecisionType.PENDING:
                        raise ValueError("approval callback cannot resolve to pending")
                    edited = None
                    if callback_result.action is ApprovalDecisionType.EDIT:
                        if req.tool_name == MODEL_EGRESS_KIND:
                            raise PermissionError("model_egress allows only APPROVE or REJECT")
                        if callback_result.edited_arguments is None:
                            raise ValueError("approval edit requires arguments")
                        edited = self.snapshot_arguments(callback_result.edited_arguments)
                    if (
                        callback_result.action is ApprovalDecisionType.RESPOND
                        and req.tool_name == MODEL_EGRESS_KIND
                    ):
                        raise PermissionError("model_egress allows only APPROVE or REJECT")
                    if (
                        callback_result.action is ApprovalDecisionType.RESPOND
                        and (
                            type(callback_result.response) is not str
                            or not callback_result.response
                        )
                    ):
                        raise ValueError("approval respond requires response")
                    # Always rebuild and normalize, even when the callback id
                    # happens to match.  The callback object is never stored.
                    decision = ApprovalDecision(
                        callback_result.action,
                        request_id=req.id,
                        edited_arguments=edited,
                        response=(
                            callback_result.response
                            if type(callback_result.response) is str
                            else ""
                        ),
                        reason=(
                            callback_result.reason
                            if type(callback_result.reason) is str
                            else ""
                        ),
                    )
                elif type(callback_result) is bool:
                    decision = ApprovalDecision(
                        ApprovalDecisionType.APPROVE
                        if callback_result
                        else ApprovalDecisionType.REJECT,
                        request_id=req.id,
                        reason="callback",
                    )
                else:
                    raise ValueError("approval callback result is invalid")
            except Exception:
                # A callback is untrusted extension code.  Log a fixed code
                # only: even a custom exception class name may carry secrets.
                logger.error("Approval callback failed")
            else:
                approved = decision.approved
                event_type = {
                    ApprovalDecisionType.APPROVE: "approval_approved",
                    ApprovalDecisionType.EDIT: "approval_edited",
                    ApprovalDecisionType.REJECT: "approval_rejected",
                    ApprovalDecisionType.RESPOND: "approval_responded",
                }[decision.action]
                ledger_kwargs: dict[str, Any] = {"reason": decision.reason}
                if (
                    decision.action is ApprovalDecisionType.EDIT
                    and decision.edited_arguments is not None
                ):
                    ledger_kwargs["final_arguments_hash"] = self._argument_hash(
                        decision.edited_arguments
                    )
                    ledger_kwargs["original_arguments_hash"] = self._argument_hash(
                        req.arguments
                    )
                committed, result = self._commit_pending_decision(
                    req,
                    decision,
                    event_type=event_type,
                    ledger_kwargs=ledger_kwargs,
                )
                if not committed:
                    return result
                self._record_outcome(approved)
                self._emit_metrics(tool_name, resolved_mode, approved)
                self._audit_log(req, "approved" if approved else "denied", "callback")
                return result

        # model_egress never uses the CLI raw-argument prompt.
        if tool_name == MODEL_EGRESS_KIND and context == "cli":
            context = "headless"

        # CLI fallback: synchronous prompt
        if context == "cli":
            approved = self._cli_prompt(req)
            decision = ApprovalDecision(
                ApprovalDecisionType.APPROVE if approved else ApprovalDecisionType.REJECT,
                request_id=req.id,
                reason="cli_prompt",
            )
            committed, result = self._commit_pending_decision(
                req,
                decision,
                event_type=("approval_approved" if approved else "approval_rejected"),
                ledger_kwargs={"reason": "cli_prompt"},
            )
            if not committed:
                return result
            self._record_outcome(approved)
            self._emit_metrics(tool_name, resolved_mode, approved)
            self._audit_log(req, "approved" if approved else "denied", "cli_prompt")
            return result

        if queue_if_unhandled:
            logger.info(
                "Queued approval request %s for %s (context=%s)",
                req.id,
                tool_name,
                context,
            )
            return ApprovalDecision(
                ApprovalDecisionType.PENDING,
                request_id=req.id,
                reason=("callback_binding_mismatch" if callback_binding_mismatch else ""),
            )

        # Unknown context (not cli, not cron, not web): deny for safety.
        # This closes the "or 'cli'" fallback gap — when _run_context is
        # not properly set, operations are denied instead of silently
        # treated as interactive.
        logger.warning(
            "No approval handler for %s (context=%s), defaulting to deny",
            tool_name,
            context,
        )
        decision = ApprovalDecision(
            ApprovalDecisionType.REJECT,
            request_id=req.id,
            reason="no_handler",
        )
        committed, result = self._commit_pending_decision(
            req,
            decision,
            event_type="approval_rejected",
            ledger_kwargs={"reason": "no_handler"},
        )
        if not committed:
            return result
        self._record_outcome(False)
        self._emit_metrics(tool_name, resolved_mode, False)
        self._audit_log(req, "denied", "no_handler")
        return result

    def _cli_prompt(self, req: ApprovalRequest) -> bool:
        """Synchronous CLI prompt for approval."""
        try:
            args_str = ", ".join(f"{k}={v!r}" for k, v in req.arguments.items())
            prompt_text = f"\n[Approval] {req.tool_name}({args_str})\nApprove? [y/N]: "
            response = self._input_stream(prompt_text).strip().lower()
            return response in ("y", "yes")
        except (EOFError, KeyboardInterrupt):
            return False

    def resolve(self, request_id: str, approved: bool) -> bool:
        """Resolve a pending approval request (e.g., from Web UI)."""
        decision = self.decide(
            request_id,
            ApprovalDecisionType.APPROVE if approved else ApprovalDecisionType.REJECT,
            reason="resolved",
        )
        return decision.action != ApprovalDecisionType.PENDING

    def decide(
        self,
        request_id: str,
        action: ApprovalDecisionType,
        *,
        edited_arguments: dict[str, Any] | None = None,
        response: str = "",
        reason: str = "",
        owner_key_hash: str | None = None,
    ) -> ApprovalDecision:
        """Resolve a pending Echo approval with approve/edit/reject/respond."""
        if type(action) is not ApprovalDecisionType:
            raise ValueError("approval action is invalid")
        if action == ApprovalDecisionType.PENDING:
            raise ValueError("pending is not a resolution action")
        with self._lock:
            pending_tool = ""
            existing = self._pending.get(request_id)
            if existing is not None:
                pending_tool = existing.tool_name
        if pending_tool == MODEL_EGRESS_KIND and action in {
            ApprovalDecisionType.EDIT,
            ApprovalDecisionType.RESPOND,
        }:
            raise PermissionError("model_egress allows only APPROVE or REJECT")
        with self._lock:
            req = self._pending.get(request_id)
            if req and not req.resolved:
                # 校验 owner：跨 owner decide 返回 PENDING
                if owner_key_hash is not None and not _secure_str_eq(
                    req.owner_key_hash, owner_key_hash
                ):
                    return ApprovalDecision(ApprovalDecisionType.PENDING, request_id=request_id)
                # Reject resolution of expired requests
                if req.is_expired():
                    logger.warning("Attempted to resolve expired approval request %s", request_id)
                    decision = ApprovalDecision(
                        ApprovalDecisionType.REJECT,
                        request_id=req.id,
                        reason="late_resolution",
                    )
                    committed, result = self._commit_pending_decision(
                        req,
                        decision,
                        event_type="approval_expired",
                        ledger_kwargs={"reason": "late_resolution"},
                    )
                    if not committed:
                        return result
                    self._record_outcome(False)
                    self._audit_log(req, "expired", "late_resolution")
                    self._emit_metrics(req.tool_name, self.default_mode, False)
                    return result
                approved = action in {
                    ApprovalDecisionType.APPROVE,
                    ApprovalDecisionType.EDIT,
                }
                if action == ApprovalDecisionType.EDIT and not isinstance(edited_arguments, dict):
                    raise ValueError("edited_arguments are required for edit approval")
                if action == ApprovalDecisionType.RESPOND and not response:
                    raise ValueError("response is required for respond approval")
                frozen_edited = (
                    self.snapshot_arguments(edited_arguments)
                    if action is ApprovalDecisionType.EDIT
                    else None
                )
                decision = ApprovalDecision(
                    action,
                    request_id=request_id,
                    edited_arguments=frozen_edited,
                    response=response,
                    reason=reason,
                )
                event_type = {
                    ApprovalDecisionType.APPROVE: "approval_approved",
                    ApprovalDecisionType.EDIT: "approval_edited",
                    ApprovalDecisionType.REJECT: "approval_rejected",
                    ApprovalDecisionType.RESPOND: "approval_responded",
                }[action]
                # For EDIT, the authoritative event arguments_hash must be
                # the *final* edited hash (Contract C).  The original hash is
                # attached for audit but raw args are never recorded.
                ledger_kwargs: dict[str, Any] = {"reason": reason}
                if action is ApprovalDecisionType.EDIT and frozen_edited is not None:
                    final_hash = self._argument_hash(frozen_edited)
                    original_hash = self._argument_hash(req.arguments)
                    ledger_kwargs["final_arguments_hash"] = final_hash
                    ledger_kwargs["original_arguments_hash"] = original_hash
                committed, result = self._commit_pending_decision(
                    req,
                    decision,
                    event_type=event_type,
                    ledger_kwargs=ledger_kwargs,
                )
                if not committed:
                    return result
                self._record_outcome(approved)
                self._emit_metrics(req.tool_name, self.default_mode, approved)
                self._audit_log(req, "approved" if approved else "denied", "resolved")
                return result
        return ApprovalDecision(ApprovalDecisionType.PENDING, request_id=request_id)

    def get_pending(
        self,
        *,
        owner_key_hash: str | None = None,
    ) -> list[ApprovalRequest]:
        """Get all unresolved approval requests."""
        self._cleanup_stale()
        with self._lock:
            return [
                self._clone_request(request)
                for request in self._pending.values()
                if not request.resolved
                and (
                    owner_key_hash is None or _secure_str_eq(request.owner_key_hash, owner_key_hash)
                )
            ]

    def get_pending_request(
        self,
        request_id: str,
        *,
        owner_key_hash: str | None = None,
    ) -> ApprovalRequest | None:
        self._cleanup_stale()
        with self._lock:
            request = self._pending.get(request_id)
            if request is None or request.resolved:
                return None
            if owner_key_hash is not None and not _secure_str_eq(
                request.owner_key_hash, owner_key_hash
            ):
                return None
            return self._clone_request(request)

    def pending_arguments_hash(
        self,
        request_id: str,
        *,
        owner_key_hash: str,
    ) -> str:
        """Return the canonical argument hash for one exact pending request.

        This is a read-only projection accessor.  It never returns arguments
        and refuses a request that is no longer pending or belongs to another
        owner.
        """
        request = self.get_pending_request(
            request_id,
            owner_key_hash=owner_key_hash,
        )
        if request is None:
            raise KeyError("pending approval request is unavailable")
        return self._argument_hash(request.arguments)

    @contextmanager
    def _approval_claim_transaction(self) -> Iterator[None]:
        """Serialize approval preflight/claim across queue instances and processes."""

        if self._ledger_path is None:
            yield
            return
        lock_path = self._ledger_path.with_suffix(self._ledger_path.suffix + ".claim.lock")
        lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            os.fchmod(lock_fd, 0o600)
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)

    def _durable_resolved_record(self, request_id: str) -> _ResolvedDecisionRecord | None:
        record: _ResolvedDecisionRecord | None = None
        resolution_count = 0
        invalid = False
        resolution_events = {
            "approval_approved",
            "approval_edited",
            "approval_rejected",
            "approval_responded",
            "approval_expired",
            "approval_cancelled",
        }
        for row in self._verified_ledger_rows():
            if row.get("request_id") != request_id:
                continue
            event_type = str(row.get("event_type", ""))
            if event_type in resolution_events:
                resolution_count += 1
                if resolution_count > 1:
                    invalid = True
                    record = None
                    continue
            if event_type == "approval_approved":
                try:
                    approval_mode = ApprovalMode(str(row["approval_mode"]))
                    requested_at = float(row["requested_at"])
                    expires_at = float(row["expires_at"])
                    owner_key_hash = str(row["owner_key_hash"])
                    session_id = str(row["session_id"])
                    run_id = str(row["run_id"])
                    tool_name = str(row["tool_name"])
                    arguments_hash = str(row["arguments_hash"])
                    arguments_hash_scheme = str(row["arguments_hash_scheme"])
                except (KeyError, TypeError, ValueError):
                    invalid = True
                    record = None
                    continue
                if arguments_hash_scheme != APPROVAL_ARGUMENTS_HASH_SCHEME:
                    invalid = True
                    record = None
                    continue
                record = _ResolvedDecisionRecord(
                    decision=ApprovalDecision(
                        ApprovalDecisionType.APPROVE,
                        request_id=request_id,
                    ),
                    owner_key_hash=owner_key_hash,
                    session_id=session_id,
                    run_id=run_id,
                    tool_name=tool_name,
                    arguments_hash=arguments_hash,
                    arguments_hash_scheme=arguments_hash_scheme,
                    requested_at=requested_at,
                    expires_at=expires_at,
                    approval_mode=approval_mode,
                )
            elif event_type == "approval_edited":
                # approval_edited carries the *final* edited arguments_hash
                # (Contract C/D).  Restore as a valid EDIT record.
                try:
                    approval_mode = ApprovalMode(str(row["approval_mode"]))
                    requested_at = float(row["requested_at"])
                    expires_at = float(row["expires_at"])
                    owner_key_hash = str(row["owner_key_hash"])
                    session_id = str(row["session_id"])
                    run_id = str(row["run_id"])
                    tool_name = str(row["tool_name"])
                    arguments_hash = str(row["arguments_hash"])
                    arguments_hash_scheme = str(row["arguments_hash_scheme"])
                except (KeyError, TypeError, ValueError):
                    invalid = True
                    record = None
                    continue
                if arguments_hash_scheme != APPROVAL_ARGUMENTS_HASH_SCHEME:
                    invalid = True
                    record = None
                    continue
                record = _ResolvedDecisionRecord(
                    decision=ApprovalDecision(
                        ApprovalDecisionType.EDIT,
                        request_id=request_id,
                    ),
                    owner_key_hash=owner_key_hash,
                    session_id=session_id,
                    run_id=run_id,
                    tool_name=tool_name,
                    arguments_hash=arguments_hash,
                    arguments_hash_scheme=arguments_hash_scheme,
                    requested_at=requested_at,
                    expires_at=expires_at,
                    approval_mode=approval_mode,
                )
            elif event_type in {
                "approval_rejected",
                "approval_responded",
                "approval_expired",
                "approval_cancelled",
                "approval_execution_claimed",
            }:
                record = None
                if event_type == "approval_execution_claimed":
                    invalid = True
        if invalid:
            record = None
        # If mirror has no claim but Echo authority is available, check Echo
        # for a durable claim.  This detects mirror truncation.
        if (
            record is not None
            and self._echo_authority is not None
        ):
            echo_claim = self._echo_authority.lookup_claim(
                tenant_id=record.owner_key_hash or "",
                session_id=record.session_id,
                request_id=request_id,
            )
            if echo_claim is not None:
                # Echo has a claim that mirror is missing -> rebuild consumed
                return None
        return record

    def _record_from_authority_resolution(
        self,
        resolution: Any,
    ) -> _ResolvedDecisionRecord | None:
        try:
            action_name = str(resolution.action)
            if action_name == "approval_approved":
                action = ApprovalDecisionType.APPROVE
            elif action_name == "approval_edited":
                action = ApprovalDecisionType.EDIT
            else:
                return None
            return _ResolvedDecisionRecord(
                decision=ApprovalDecision(
                    action,
                    request_id=str(resolution.request_id),
                ),
                owner_key_hash=str(resolution.owner_key_hash),
                session_id=str(resolution.session_id),
                run_id=str(resolution.run_id),
                tool_name=str(resolution.tool_name),
                arguments_hash=str(resolution.arguments_hash),
                arguments_hash_scheme=str(resolution.arguments_hash_scheme),
                requested_at=float(resolution.requested_at),
                expires_at=float(resolution.expires_at),
                approval_mode=ApprovalMode(str(resolution.approval_mode)),
            )
        except (AttributeError, TypeError, ValueError):
            return None

    def _resolved_record_for_claim(
        self,
        request_id: str,
        *,
        owner_key_hash: str | None = None,
        session_id: str | None = None,
    ) -> _ResolvedDecisionRecord | None:
        if self._echo_authority is not None:
            memory = self._resolved_decisions.get(request_id)
            if memory is not None:
                return memory
            if not owner_key_hash or not session_id:
                return None
            resolution = self._echo_authority.lookup_resolution(
                tenant_id=owner_key_hash,
                session_id=session_id,
                request_id=request_id,
            )
            if resolution is None:
                return None
            return self._record_from_authority_resolution(resolution)
        if self._ledger_path is not None:
            return self._durable_resolved_record(request_id)
        return self._resolved_decisions.get(request_id)

    @staticmethod
    def _validate_approved_record(
        record: _ResolvedDecisionRecord | None,
        *,
        owner_key_hash: str,
        session_id: str,
        run_id: str,
        tool_name: str,
        arguments_hash: str,
        require_manual: bool,
    ) -> _ResolvedDecisionRecord:
        matches = record is not None and all(
            (
                (
                    record.decision.action is ApprovalDecisionType.APPROVE
                    if record.tool_name == MODEL_EGRESS_KIND
                    else record.decision.action
                    in {
                        ApprovalDecisionType.APPROVE,
                        ApprovalDecisionType.EDIT,
                    }
                ),
                _secure_str_eq(record.owner_key_hash, owner_key_hash),
                _secure_str_eq(record.session_id, session_id),
                _secure_str_eq(record.run_id, run_id),
                record.tool_name == tool_name,
                _secure_str_eq(record.arguments_hash, arguments_hash),
                record.arguments_hash_scheme == APPROVAL_ARGUMENTS_HASH_SCHEME,
                not require_manual or record.approval_mode is ApprovalMode.MANUAL,
                time.time() <= record.expires_at,
            )
        )
        if not matches or record is None:
            raise PermissionError("approved binding is unavailable or does not match")
        return record

    def validate_approved_binding(
        self,
        request_id: str,
        *,
        owner_key_hash: str,
        session_id: str,
        run_id: str,
        tool_name: str,
        arguments_hash: str,
        require_manual: bool,
    ) -> ApprovalDecision:
        """Read-only preflight for one exact resolved approval snapshot."""

        with self._lock, self._approval_claim_transaction():
            record = self._validate_approved_record(
                self._resolved_record_for_claim(
                    request_id,
                    owner_key_hash=owner_key_hash,
                    session_id=session_id,
                ),
                owner_key_hash=owner_key_hash,
                session_id=session_id,
                run_id=run_id,
                tool_name=tool_name,
                arguments_hash=arguments_hash,
                require_manual=require_manual,
            )
            return self._clone_decision(record.decision)

    def consume_approved_binding(
        self,
        request_id: str,
        *,
        owner_key_hash: str,
        session_id: str,
        run_id: str,
        tool_name: str,
        arguments_hash: str,
        require_manual: bool,
    ) -> ApprovalClaimProof:
        """Durably claim one exact manual approval at most once.

        When an :class:`ApprovalEchoAuthority` is installed, the claim is
        performed atomically in the Echo journal's cross-process lock
        (``claim_once``).  The local mirror is updated only as a cache;
        mirror failure is non-fatal.  Only ``claimed_now=True`` authorises
        execution; ``claimed_now=False`` (already claimed) raises
        ``PermissionError``.

        Without an Echo authority (legacy/test mode), falls back to the
        mirror-based claim with cross-process file lock.

        Returns an :class:`ApprovalClaimProof` carrying the immutable
        claim receipt and the resolved approval decision.
        """

        with self._lock, self._approval_claim_transaction():
            record = self._validate_approved_record(
                self._resolved_record_for_claim(
                    request_id,
                    owner_key_hash=owner_key_hash,
                    session_id=session_id,
                ),
                owner_key_hash=owner_key_hash,
                session_id=session_id,
                run_id=run_id,
                tool_name=tool_name,
                arguments_hash=arguments_hash,
                require_manual=require_manual,
            )

            # --- Echo authority path (production) ---
            if self._echo_authority is not None:
                receipt = self._echo_authority.claim_once(
                    tenant_id=record.owner_key_hash or "",
                    session_id=record.session_id,
                    run_id=record.run_id,
                    request_id=request_id,
                    tool_name=record.tool_name,
                    arguments_hash=record.arguments_hash,
                    approval_mode=record.approval_mode.value,
                    expires_at=record.expires_at,
                    requested_at=record.requested_at,
                    arguments_hash_scheme=record.arguments_hash_scheme,
                )
                if not receipt.claimed_now:
                    raise PermissionError(
                        "approval binding already claimed; re-approval required"
                    )
                # Mirror is cache-only:
                event = self._redact_ledger_value(
                    {
                        "event_type": "approval_execution_claimed",
                        "request_id": request_id,
                        "tool_name": record.tool_name,
                        "context": "runtime",
                        "session_id": record.session_id,
                        "run_id": record.run_id,
                        "owner_key_hash": record.owner_key_hash or "",
                        "arguments_hash": record.arguments_hash,
                        "arguments_hash_scheme": record.arguments_hash_scheme,
                        "timestamp": time.time(),
                        "requested_at": record.requested_at,
                        "expires_at": record.expires_at,
                        "approval_mode": record.approval_mode.value,
                        "binding_hash": receipt.binding_hash,
                        "journal_record_hash": receipt.journal_record_hash,
                    }
                )
                if self._ledger_path is not None:
                    try:
                        self._append_ledger_mirror(cast("dict[str, Any]", event))
                    except Exception:
                        pass  # mirror failure is non-fatal; Echo is authoritative
                self._resolved_decisions.pop(request_id, None)
                self._delivered_decisions.discard(request_id)
                return ApprovalClaimProof(
                    action=record.decision.action,
                    request_id=request_id,
                    arguments_hash=record.arguments_hash,
                    binding_hash=receipt.binding_hash,
                    journal_record_hash=receipt.journal_record_hash,
                    journal_seq=receipt.journal_seq,
                    claimed_now=True,
                )

            # --- Fail-closed: sink exists but no authority ---
            if self._echo_event_sink is not None:
                raise PermissionError(
                    "approval claim authority is unavailable; cannot claim"
                    " with sink-only configuration"
                )

            # --- Legacy mirror-only path (isolated test/no-sink mode) ---
            event = self._redact_ledger_value(
                {
                    "event_type": "approval_execution_claimed",
                    "request_id": request_id,
                    "tool_name": record.tool_name,
                    "context": "runtime",
                    "session_id": record.session_id,
                    "run_id": record.run_id,
                    "owner_key_hash": record.owner_key_hash or "",
                    "arguments_hash": record.arguments_hash,
                    "arguments_hash_scheme": record.arguments_hash_scheme,
                    "timestamp": time.time(),
                    "requested_at": record.requested_at,
                    "expires_at": record.expires_at,
                    "approval_mode": record.approval_mode.value,
                }
            )
            if self._ledger_path is not None:
                self._append_ledger_mirror(cast("dict[str, Any]", event))
            self._resolved_decisions.pop(request_id, None)
            self._delivered_decisions.discard(request_id)
            return ApprovalClaimProof(
                action=record.decision.action,
                request_id=request_id,
                arguments_hash=record.arguments_hash,
                binding_hash="",
                journal_record_hash="",
                journal_seq=-1,
                claimed_now=True,
            )

    def take_decision(
        self,
        request_id: str,
        *,
        owner_key_hash: str | None = None,
    ) -> ApprovalDecision | None:
        """Read one externally resolved decision without consuming it.

        Delivery is once-only, but an approved resolved record remains until
        :meth:`consume_approved_binding` performs the authoritative CAS.
        """
        with self._lock:
            record = self._resolved_decisions.get(request_id)
            if record is None:
                return None
            if owner_key_hash is not None and not _secure_str_eq(
                record.owner_key_hash, owner_key_hash
            ):
                return None
            if request_id in self._delivered_decisions:
                return None
            self._delivered_decisions.add(request_id)
            decision = self._clone_decision(record.decision)
            if not decision.approved:
                self._resolved_decisions.pop(request_id, None)
                self._delivered_decisions.discard(request_id)
            return decision

    def get_stats(self) -> dict[str, Any]:
        with self._lock:
            pending_count = sum(1 for r in self._pending.values() if not r.resolved)
            return {
                "total_requests": self._history["total"],
                "resolved": self._history["approved"] + self._history["denied"],
                "approved": self._history["approved"],
                "denied": self._history["denied"],
                "pending": pending_count,
            }


# Fields consumed by the sink itself; everything else is forwarded as extra
# payload for the authoritative EchoLedger approval record.
_SINK_CORE_FIELDS = frozenset(
    {
        "event_type",
        "request_id",
        "tool_name",
        "session_id",
        "run_id",
        "owner_key_hash",
        "arguments_hash",
    }
)


def wire_echo_approval_sink(
    service: Any,
    *,
    product_id: str,
) -> Callable[[dict[str, Any]], None]:
    """Bind an ApprovalQueue to the authoritative EchoLedger.

    The returned sink records every approval lifecycle event into the Echo
    scope partition journal (``EchoSafetyService.record_approval_event``), so
    approval state is atomically ordered with the Echo run it belongs to.
    The queue's local JSONL file remains only a derived mirror.
    """

    def _sink(event: dict[str, Any]) -> None:
        service.record_approval_event(
            tenant_id=str(event.get("owner_key_hash") or "local"),
            product_id=product_id,
            session_id=str(event.get("session_id") or ""),
            run_id=str(event.get("run_id") or ""),
            event_type=str(event["event_type"]),
            request_id=str(event.get("request_id") or ""),
            tool_name=str(event.get("tool_name") or ""),
            arguments_hash=str(event.get("arguments_hash") or ""),
            extra={
                key: value
                for key, value in event.items()
                if key not in _SINK_CORE_FIELDS and key != "timestamp"
            },
        )

    return _sink


def wire_echo_approval_authority(
    service: Any,
    *,
    product_id: str,
) -> ApprovalEchoAuthority:
    """Create a typed, sealed ``ApprovalEchoAuthority`` for an ApprovalQueue.

    The authority provides atomic ``claim_once``, ``lookup_claim``, and
    ``lookup_resolution`` operations backed by the Echo journal.
    """

    return ApprovalEchoAuthority(service, product_id=product_id)
