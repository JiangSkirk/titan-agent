"""B2: dangerous-tool and connector-write approval exactly-once via Echo CAS.

These tests enforce the core contract:

1. JSAgent installs sealed Echo authority (auto-wires sink); claim fails
   closed when authoritative sink exists but authority is missing.
   After seal, ``set_echo_event_sink`` must also be rejected.
2. Approval resolve, Echo CAS, tool lease/effect/handler and connector use
   the same ``stable_payload_hash(final_arguments)``.  Callback decision is
   normalized to the real ``request_id``; subsequent mutation has no effect.
   All arguments are JSON-safe bounded deep snapshots before entering the
   queue; callbacks receive independent clones.
3. ``consume`` returns an immutable typed claim proof with frozen closed-set
   fields (no nested mutable ApprovalDecision); only ``claimed_now=True``
   succeeds.
4. Dangerous tools claim exactly once after EDIT safety re-check and before
   any lease/audit/begin effect/handler.  CAS loser has zero side effects
   (no lease issue/verify/consume, no audit/event, no begin_tool_effect,
   no handler call).
5. ``approval_execution_claimed`` is produced only by Echo CAS (which
   verifies a prior ``approval_approved``/``approval_edited`` prerequisite
   inside the same flock semantic_check), not ``record_event``.
   ``record_approval_event`` rejects reserved ``approval_execution_claimed``
   and forbids ``extra`` from overriding core fields; ``extra`` is
   allowlisted to a closed set.
   A new ``approval_execution_bound`` links the claim receipt hash to the
   execution effect id.
6. Connector write anchors the fresh claim receipt hash into the dispatch
   capability; CAS loser does not anchor, consume lease, or dispatch.
   Read path does not require a proof.
7. Ledger/log/exception contains only closed-set identity and hashes.

Additional contracts:
A. Arguments are JSON-safe bounded deep snapshots; no custom objects/NaN/Inf.
B. ``_argument_hash`` uses ``stable_payload_hash``; old hash cannot authorize.
C. ``approval_edited`` authoritative event ``arguments_hash`` is the final
   edited hash; raw args not recorded.
D. Durable recovery restores exact EDIT final hash; ``approval_edited`` is
   not treated as invalid.
E. ``take_decision`` does not destructively pop before CAS; execution main
   chain retains request_id and record until fresh claim succeeds.
F. ``ApprovalClaimProof`` stores a defensive decision snapshot.
G. AUTO_APPROVE also persists resolved snapshot and Echo approval_approved
   prerequisite before CAS.
"""

from __future__ import annotations

import concurrent.futures
import copy
import dataclasses
import fcntl
import hashlib
import json
import multiprocessing
import os
import stat
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import js.security.approvals as approvals_module
from js.config import EchoLedgerConfig
from js.echo.ledger.journal import FileEchoLedger
from js.echo.ledger.service import EchoSafetyService, _scope_partition_slugs
from js.echo.primitives import stable_payload_hash
from js.security.approvals import (
    ApprovalClaimProof,
    ApprovalDecision,
    ApprovalDecisionType,
    ApprovalEchoAuthority,
    ApprovalMode,
    ApprovalQueue,
    wire_echo_approval_authority,
    wire_echo_approval_sink,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _echo_queue(
    tmp_path: Path,
    *,
    product_id: str = "js-agent",
) -> tuple[ApprovalQueue, EchoSafetyService, ApprovalEchoAuthority]:
    """Create an ApprovalQueue wired to a real EchoSafetyService authority.

    Only calls ``set_echo_authority`` which auto-wires the sink and seals.
    """
    service = EchoSafetyService(state_dir=tmp_path / "echo")
    authority = wire_echo_approval_authority(service, product_id=product_id)
    queue = ApprovalQueue(
        default_mode=ApprovalMode.MANUAL,
        ledger_path=tmp_path / "approvals.jsonl",
    )
    queue.set_echo_authority(authority)
    return queue, service, authority


def _resolve_manual(
    queue: ApprovalQueue,
    *,
    tool_name: str = "dangerous_tool",
    arguments: dict[str, Any] | None = None,
    owner: str = "owner-a",
    session: str = "session-a",
    run: str = "run-a",
    action: ApprovalDecisionType = ApprovalDecisionType.APPROVE,
    edited_arguments: dict[str, Any] | None = None,
    reason: str = "",
) -> tuple[str, str]:
    args = arguments or {"path": "test.txt"}
    pending = queue.request_decision(
        tool_name,
        args,
        context="web",
        session_id=session,
        run_id=run,
        owner_key_hash=owner,
        queue_if_unhandled=True,
    )
    decide_kwargs: dict[str, Any] = {"owner_key_hash": owner, "reason": reason}
    if action is ApprovalDecisionType.EDIT:
        decide_kwargs["edited_arguments"] = edited_arguments or {"path": "edited.txt"}
    queue.decide(pending.request_id, action, **decide_kwargs)
    final_args = edited_arguments if action is ApprovalDecisionType.EDIT else args
    return pending.request_id, queue.arguments_hash(final_args)


def _journal_records(service: EchoSafetyService, *, owner: str = "owner-a"):
    from js.echo.ledger.journal import FileEchoLedger

    journal_path = service.journal_path_for_scope(
        owner, product_id="js-agent", session_id="session-a"
    )
    return FileEchoLedger(
        journal_path,
        mac_key=service.journal_key_for_scope(
            owner, product_id="js-agent", session_id="session-a"
        ),
    ).records


_MIRROR_BEFORE_WRITE_ERROR = "RAW_PRIVATE_MIRROR_PATH"
_AUTHORITATIVE_TERMINALS = frozenset({"approval_approved", "approval_edited"})


def _install_mirror_before_write_failure(
    queue: ApprovalQueue,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Raise before any derived terminal row is written to the JSONL mirror."""

    original_mirror = queue._append_ledger_mirror  # noqa: SLF001

    def raise_before_terminal(event: dict[str, Any]) -> None:
        if str(event.get("event_type", "")) in _AUTHORITATIVE_TERMINALS:
            raise OSError(_MIRROR_BEFORE_WRITE_ERROR)
        original_mirror(event)

    monkeypatch.setattr(queue, "_append_ledger_mirror", raise_before_terminal)


def _logical_journal_records(service: EchoSafetyService, *, owner: str = "owner-a"):
    from js.echo.ledger.journal import FileEchoLedger

    journal_path = service.journal_path_for_scope(
        owner, product_id="js-agent", session_id="session-a"
    )
    return FileEchoLedger(
        journal_path,
        mac_key=service.journal_key_for_scope(
            owner, product_id="js-agent", session_id="session-a"
        ),
    ).verified_logical_records()


def _approval_rows(service: EchoSafetyService, request_id: str) -> list[Any]:
    return [
        record
        for record in _logical_journal_records(service)
        if record.record_type == "approval"
        and isinstance(record.payload, dict)
        and record.payload.get("request_id") == request_id
    ]


def _echo_terminals(service: EchoSafetyService, request_id: str) -> list[Any]:
    return [
        record
        for record in _approval_rows(service, request_id)
        if record.payload.get("event_type") in _AUTHORITATIVE_TERMINALS
    ]


def _echo_claims(service: EchoSafetyService, request_id: str) -> list[Any]:
    return [
        record
        for record in _approval_rows(service, request_id)
        if record.payload.get("event_type") == "approval_execution_claimed"
    ]


def _consume_kwargs(
    request_id: str,
    arguments_hash: str,
    **overrides: Any,
) -> dict[str, Any]:
    payload = {
        "owner_key_hash": "owner-a",
        "session_id": "session-a",
        "run_id": "run-a",
        "tool_name": "dangerous_tool",
        "arguments_hash": arguments_hash,
        "require_manual": True,
    }
    payload.update(overrides)
    return payload


def _assert_no_leaked_mirror_error(tmp_path: Path) -> None:
    persisted = "".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in tmp_path.rglob("*")
        if path.is_file()
    )
    assert _MIRROR_BEFORE_WRITE_ERROR not in persisted


def _assert_mirror_has_no_terminal(ledger_path: Path) -> None:
    if not ledger_path.is_file():
        return
    text = ledger_path.read_text(encoding="utf-8")
    assert "approval_approved" not in text
    assert "approval_edited" not in text


def _ledger_root(service: EchoSafetyService) -> Path:
    return service.journal_path.parent


def _echo_tree_snapshot(root: Path) -> dict[str, str]:
    snapshot: dict[str, str] = {}
    if not root.exists():
        return snapshot
    for path in sorted(root.rglob("*"), key=lambda item: str(item.relative_to(root))):
        relative = str(path.relative_to(root))
        if path.is_symlink():
            snapshot[relative] = f"symlink:{path.readlink()}"
        elif path.is_dir():
            snapshot[relative] = "dir"
        elif path.is_file():
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            snapshot[relative] = f"file:{digest}"
    return snapshot


def _partition_session_set(ledger_root: Path) -> tuple[str, ...]:
    partitions = ledger_root / "partitions"
    try:
        found = [
            str(path.relative_to(partitions))
            for path in partitions.glob("*/*/*")
            if path.is_dir() and not path.is_symlink()
        ]
    except FileNotFoundError:
        return ()
    return tuple(sorted(found))


def _session_file_inodes(session_root: Path) -> dict[str, tuple[int, int]]:
    mapping: dict[str, tuple[int, int]] = {}
    for path in session_root.rglob("*"):
        if path.is_file() and not path.is_symlink():
            metadata = path.stat()
            mapping[str(path.relative_to(session_root))] = (
                metadata.st_dev,
                metadata.st_ino,
            )
    return mapping


def _record_synthetic_terminal(
    service: EchoSafetyService,
    *,
    owner: str,
    session: str,
    request_id: str,
    run: str = "run-a",
) -> str:
    args_hash = ApprovalQueue.arguments_hash({"path": "safe"})
    now = time.time()
    extra = {
        "context": "web",
        "requested_at": now,
        "expires_at": now + 300,
        "approval_mode": "manual",
        "arguments_hash_scheme": "stable_payload_hash:v1",
    }
    for event_type in ("approval_requested", "approval_approved"):
        service.record_approval_event(
            tenant_id=owner,
            product_id="js-agent",
            session_id=session,
            run_id=run,
            event_type=event_type,
            request_id=request_id,
            tool_name="dangerous_tool",
            arguments_hash=args_hash,
            extra=extra,
        )
    return args_hash


def _partition_dirs(
    service: EchoSafetyService,
    *,
    owner: str,
    session: str,
) -> tuple[Path, Path, Path, Path]:
    product_slug, owner_slug, session_slug = _scope_partition_slugs(
        tenant_id=owner,
        product_id="js-agent",
        session_id=session,
    )
    partitions = _ledger_root(service) / "partitions"
    product_dir = partitions / product_slug
    owner_dir = product_dir / owner_slug
    session_dir = owner_dir / session_slug
    return partitions, product_dir, owner_dir, session_dir


def _fresh_service(state_dir: Path) -> EchoSafetyService:
    return EchoSafetyService(state_dir=state_dir)


def _hold_exclusive_lock_until_released(
    path: str,
    ready: Any,
    release: Any,
) -> None:
    fd = os.open(path, os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        ready.set()
        release.wait(10)
    finally:
        os.close(fd)


def _chmod_writer_ancestors_private(
    partitions: Path,
    product_dir: Path,
    owner_dir: Path,
) -> None:
    """Force ancestor 0700 so today's path-mode checker can reach FileEchoLedger."""

    os.chmod(partitions, 0o700)
    os.chmod(product_dir, 0o700)
    os.chmod(owner_dir, 0o700)


# ---------------------------------------------------------------------------
# Contract 3: consume returns typed claim proof with frozen closed-set fields
# ---------------------------------------------------------------------------


def test_consume_returns_typed_claim_proof(tmp_path: Path) -> None:
    """consume must return an immutable typed proof with frozen closed-set fields."""
    queue, _service, _authority = _echo_queue(tmp_path)
    request_id, args_hash = _resolve_manual(queue)

    proof = queue.consume_approved_binding(
        request_id,
        owner_key_hash="owner-a",
        session_id="session-a",
        run_id="run-a",
        tool_name="dangerous_tool",
        arguments_hash=args_hash,
        require_manual=True,
    )
    assert proof.request_id == request_id
    assert proof.arguments_hash == args_hash
    assert proof.binding_hash
    assert proof.journal_record_hash
    assert proof.journal_record_hash.startswith("sha256:")
    assert isinstance(proof.journal_seq, int)
    assert proof.claimed_now is True
    assert proof.action is ApprovalDecisionType.APPROVE
    assert {field.name for field in dataclasses.fields(proof)} == {
        "action",
        "request_id",
        "arguments_hash",
        "binding_hash",
        "journal_record_hash",
        "journal_seq",
        "claimed_now",
    }
    assert not hasattr(proof, "__dict__")
    # Proof must be frozen, with the precise dataclass exception.
    with pytest.raises(dataclasses.FrozenInstanceError):
        proof.request_id = "tampered"  # type: ignore[misc]


def test_claimed_now_false_rejects_re_consume(tmp_path: Path) -> None:
    """Second consume must be rejected because claimed_now=False."""
    queue, _service, _authority = _echo_queue(tmp_path)
    request_id, args_hash = _resolve_manual(queue)
    kwargs = {
        "owner_key_hash": "owner-a",
        "session_id": "session-a",
        "run_id": "run-a",
        "tool_name": "dangerous_tool",
        "arguments_hash": args_hash,
        "require_manual": True,
    }
    queue.consume_approved_binding(request_id, **kwargs)
    with pytest.raises(PermissionError):
        queue.consume_approved_binding(request_id, **kwargs)


# ---------------------------------------------------------------------------
# Contract F: proof stores defensive decision snapshot
# ---------------------------------------------------------------------------


def test_proof_decision_projection_is_defensive(tmp_path: Path) -> None:
    """The compatibility decision projection must be a fresh closed snapshot."""
    queue, _service, _authority = _echo_queue(tmp_path)
    request_id, args_hash = _resolve_manual(queue)
    proof = queue.consume_approved_binding(
        request_id,
        owner_key_hash="owner-a",
        session_id="session-a",
        run_id="run-a",
        tool_name="dangerous_tool",
        arguments_hash=args_hash,
        require_manual=True,
    )
    projection_a = proof.decision
    projection_b = proof.decision
    assert projection_a is not projection_b
    assert projection_a.action is ApprovalDecisionType.APPROVE
    assert projection_a.request_id == proof.request_id
    assert projection_a.edited_arguments is None
    with pytest.raises(dataclasses.FrozenInstanceError):
        projection_a.request_id = "tampered"  # type: ignore[misc]
    assert proof.decision.request_id == proof.request_id


# ---------------------------------------------------------------------------
# Contract 1: authority missing -> fail closed
# ---------------------------------------------------------------------------


def test_sink_only_without_authority_fails_closed(tmp_path: Path) -> None:
    """When authoritative sink exists but authority is missing, claim fails."""
    service = EchoSafetyService(state_dir=tmp_path / "echo")
    queue = ApprovalQueue(
        default_mode=ApprovalMode.MANUAL,
        ledger_path=tmp_path / "approvals.jsonl",
    )
    queue.set_echo_event_sink(wire_echo_approval_sink(service, product_id="js-agent"))
    request_id, args_hash = _resolve_manual(queue)
    with pytest.raises(PermissionError, match="authority"):
        queue.consume_approved_binding(
            request_id,
            owner_key_hash="owner-a",
            session_id="session-a",
            run_id="run-a",
            tool_name="dangerous_tool",
            arguments_hash=args_hash,
            require_manual=True,
        )


def test_mirror_only_without_sink_or_authority_allowed_for_legacy(tmp_path: Path) -> None:
    """Mirror-only path is allowed only when no authoritative sink exists."""
    queue = ApprovalQueue(
        default_mode=ApprovalMode.MANUAL,
        ledger_path=tmp_path / "approvals.jsonl",
    )
    request_id, args_hash = _resolve_manual(queue)
    proof = queue.consume_approved_binding(
        request_id,
        owner_key_hash="owner-a",
        session_id="session-a",
        run_id="run-a",
        tool_name="dangerous_tool",
        arguments_hash=args_hash,
        require_manual=True,
    )
    assert proof.decision.action is ApprovalDecisionType.APPROVE


# ---------------------------------------------------------------------------
# RED 13: set_echo_authority seal blocks set_echo_event_sink
# ---------------------------------------------------------------------------


def test_sealed_authority_blocks_set_echo_event_sink(tmp_path: Path) -> None:
    """After set_echo_authority seals, set_echo_event_sink must reject."""
    queue, _service, _authority = _echo_queue(tmp_path)
    with pytest.raises(RuntimeError, match="sealed"):
        queue.set_echo_event_sink(lambda _event: None)


# ---------------------------------------------------------------------------
# Contract 2: two queues same Echo -> only one winner
# ---------------------------------------------------------------------------


def test_two_queues_same_echo_one_winner(tmp_path: Path) -> None:
    queue1, _service, authority = _echo_queue(tmp_path)
    request_id, args_hash = _resolve_manual(queue1)

    queue2 = ApprovalQueue(
        default_mode=ApprovalMode.MANUAL,
        ledger_path=tmp_path / "approvals.jsonl",
    )
    queue2.set_echo_authority(authority)

    kwargs = {
        "owner_key_hash": "owner-a",
        "session_id": "session-a",
        "run_id": "run-a",
        "tool_name": "dangerous_tool",
        "arguments_hash": args_hash,
        "require_manual": True,
    }
    proof1 = queue1.consume_approved_binding(request_id, **kwargs)
    assert proof1.journal_record_hash

    with pytest.raises(PermissionError):
        queue2.consume_approved_binding(request_id, **kwargs)


# ---------------------------------------------------------------------------
# Contract B: _argument_hash uses stable_payload_hash
# ---------------------------------------------------------------------------


def test_argument_hash_uses_stable_payload_hash() -> None:
    """arguments_hash must equal stable_payload_hash for the same dict."""
    args = {"b": 2, "a": 1, "nested": {"d": 4, "c": 3}}
    expected = stable_payload_hash(args)
    assert ApprovalQueue.arguments_hash(args) == expected


# ---------------------------------------------------------------------------
# Contract A: JSON-safe bounded deep snapshot; no custom objects/NaN/Inf
# ---------------------------------------------------------------------------


def test_request_rejects_non_json_safe_arguments(tmp_path: Path) -> None:
    """Custom objects that are not JSON-safe must be rejected."""
    queue, _s, _a = _echo_queue(tmp_path)

    class Secret:
        def __str__(self) -> str:
            return "RAW_SECRET_MUST_NOT_ESCAPE"

    with pytest.raises(ValueError) as exc_info:
        queue.request_decision(
            "dangerous_tool",
            {"obj": Secret()},  # type: ignore[dict-item]
            context="web",
            session_id="session-a",
            run_id="run-a",
            owner_key_hash="owner-a",
            queue_if_unhandled=True,
        )
    assert str(exc_info.value) == "approval snapshot is not JSON-safe"
    assert "RAW_SECRET_MUST_NOT_ESCAPE" not in str(exc_info.value)


def test_request_rejects_nan_inf(tmp_path: Path) -> None:
    """NaN/Inf must be rejected (not JSON-safe)."""
    queue, _s, _a = _echo_queue(tmp_path)
    with pytest.raises(ValueError, match="approval snapshot is not JSON-safe"):
        queue.request_decision(
            "dangerous_tool",
            {"value": float("nan")},
            context="web",
            session_id="session-a",
            run_id="run-a",
            owner_key_hash="owner-a",
            queue_if_unhandled=True,
        )


@pytest.mark.parametrize(
    "arguments",
    [
        ({"value": float("inf")}),
        ({"value": float("-inf")}),
        ({"tuple": (1, 2)}),
    ],
)
def test_request_rejects_other_non_exact_json_values(
    tmp_path: Path,
    arguments: dict[str, Any],
) -> None:
    queue, _s, _a = _echo_queue(tmp_path)
    with pytest.raises(ValueError, match="approval snapshot is not JSON-safe"):
        queue.request_decision(
            "dangerous_tool",
            arguments,
            context="web",
            session_id="session-a",
            run_id="run-a",
            owner_key_hash="owner-a",
            queue_if_unhandled=True,
        )


def test_request_rejects_dict_and_list_subclasses(tmp_path: Path) -> None:
    queue, _s, _a = _echo_queue(tmp_path)

    class DictSubclass(dict[str, Any]):
        pass

    class ListSubclass(list[Any]):
        pass

    for arguments in (
        DictSubclass({"ok": True}),
        {"nested": DictSubclass({"ok": True})},
        {"nested": ListSubclass([1])},
    ):
        with pytest.raises(ValueError, match="approval snapshot is not JSON-safe"):
            queue.request_decision(
                "dangerous_tool",
                arguments,
                context="web",
                session_id="session-a",
                run_id="run-a",
                owner_key_hash="owner-a",
                queue_if_unhandled=True,
            )


@pytest.mark.parametrize(
    "arguments",
    [
        {"deep": [[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[0]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]},
        {"many": list(range(20_000))},
        {"x": "v" * (2 * 1024 * 1024)},
        {"k" * 2048: "v"},
    ],
    ids=["depth", "nodes", "serialized-bytes-and-string", "key-length"],
)
def test_request_rejects_snapshot_resource_limit_overflow(
    tmp_path: Path,
    arguments: dict[str, Any],
) -> None:
    queue, _s, _a = _echo_queue(tmp_path)
    with pytest.raises(ValueError, match="approval snapshot exceeds limits"):
        queue.request_decision(
            "dangerous_tool",
            arguments,
            context="web",
            session_id="session-a",
            run_id="run-a",
            owner_key_hash="owner-a",
            queue_if_unhandled=True,
        )


def test_snapshot_rejects_aggregate_bytes_before_json_serialization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Several individually valid strings must hit the aggregate bound early."""
    called = False

    def unexpected_dumps(*_args: Any, **_kwargs: Any) -> str:
        nonlocal called
        called = True
        raise AssertionError("json.dumps must not run after the aggregate limit is known")

    monkeypatch.setattr(approvals_module.json, "dumps", unexpected_dumps)
    with pytest.raises(ValueError, match="approval snapshot exceeds limits"):
        ApprovalQueue.snapshot_arguments(
            {f"part-{index}": "x" * (60 * 1024) for index in range(5)}
        )
    assert called is False


@pytest.mark.parametrize(
    "arguments",
    [
        {"numbers": [10**4000] * 70},
        {"escaped": "\x00" * 50_000},
    ],
    ids=["repeated-large-integers", "control-character-json-escaping"],
)
def test_snapshot_stream_budget_rejects_before_whole_document_dumps(
    arguments: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The 256 KiB limit includes number text, escapes, and JSON structure."""
    called = False

    def unexpected_dumps(*_args: Any, **_kwargs: Any) -> str:
        nonlocal called
        called = True
        raise AssertionError("whole-document json.dumps must not be called")

    monkeypatch.setattr(approvals_module.json, "dumps", unexpected_dumps)
    with pytest.raises(ValueError, match="approval snapshot exceeds limits"):
        ApprovalQueue.snapshot_arguments(arguments)
    assert called is False


@pytest.mark.parametrize("arguments", [{"bad\ud800": "value"}, {"bad": "value\ud800"}])
def test_snapshot_maps_unpaired_surrogate_to_fixed_safe_error(
    arguments: dict[str, Any],
) -> None:
    with pytest.raises(ValueError) as exc_info:
        ApprovalQueue.snapshot_arguments(arguments)
    assert str(exc_info.value) == "approval snapshot is not JSON-safe"
    assert "surrogate" not in str(exc_info.value).lower()


def test_snapshot_depth_boundary_is_explicit() -> None:
    """Root is depth zero; a node at depth 32 is allowed, depth 33 is not."""

    def nested_list(levels: int) -> Any:
        value: Any = 0
        for _ in range(levels):
            value = [value]
        return value

    assert ApprovalQueue.snapshot_arguments({"value": nested_list(31)})
    with pytest.raises(ValueError, match="approval snapshot exceeds limits"):
        ApprovalQueue.snapshot_arguments({"value": nested_list(32)})


def test_set_callback_rejects_non_json_safe_binding(tmp_path: Path) -> None:
    queue, _s, _a = _echo_queue(tmp_path)
    with pytest.raises(ValueError, match="approval snapshot is not JSON-safe"):
        queue.set_callback(
            "session-a",
            lambda _request: True,
            owner_key_hash="owner-a",
            run_id="run-a",
            tool_name="dangerous_tool",
            arguments={"bad": (1, 2)},
        )


def test_callback_receives_independent_clone(tmp_path: Path) -> None:
    """Callback must receive an independent clone; mutating it must not
    affect the queue's internal state or the caller's dict."""
    queue, _s, _a = _echo_queue(tmp_path)
    arguments = {"path": "test", "nested": {"key": "value"}}
    received: list[dict[str, Any]] = []

    def callback(req: Any) -> ApprovalDecision:
        received.append(req.arguments)
        # Mutate the received arguments
        req.arguments["path"] = "mutated"
        req.arguments["nested"]["key"] = "mutated"
        return ApprovalDecision(
            ApprovalDecisionType.APPROVE, request_id=req.id, reason="callback"
        )

    queue.set_callback(
        "session-a",
        callback,
        owner_key_hash="owner-a",
        run_id="run-a",
        tool_name="dangerous_tool",
        arguments=arguments,
    )
    decision = queue.request_decision(
        "dangerous_tool",
        arguments,
        context="web",
        session_id="session-a",
        run_id="run-a",
        owner_key_hash="owner-a",
    )
    assert decision.action is ApprovalDecisionType.APPROVE
    # Caller's dict must be unchanged
    assert arguments["path"] == "test"
    assert arguments["nested"]["key"] == "value"
    # The stored resolved record must use the original (unmutated) hash
    final_hash = queue.arguments_hash(arguments)
    proof = queue.consume_approved_binding(
        decision.request_id,
        owner_key_hash="owner-a",
        session_id="session-a",
        run_id="run-a",
        tool_name="dangerous_tool",
        arguments_hash=final_hash,
        require_manual=True,
    )
    assert proof.journal_record_hash


def test_callback_exception_log_does_not_expose_custom_exception_type(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    queue, _service, _authority = _echo_queue(tmp_path)
    log_calls: list[tuple[Any, ...]] = []
    monkeypatch.setattr(
        approvals_module.logger,
        "error",
        lambda *args, **_kwargs: log_calls.append(args),
    )

    class SensitiveCallbackSecretError(Exception):
        pass

    def callback(_req: Any) -> ApprovalDecision:
        raise SensitiveCallbackSecretError("raw callback detail")

    queue.set_callback(
        "session-a",
        callback,
        owner_key_hash="owner-a",
        run_id="run-a",
        tool_name="dangerous_tool",
        arguments={"path": "safe"},
    )
    decision = queue.request_decision(
        "dangerous_tool",
        {"path": "safe"},
        context="web",
        session_id="session-a",
        run_id="run-a",
        owner_key_hash="owner-a",
        queue_if_unhandled=True,
    )
    assert decision.action is ApprovalDecisionType.PENDING
    rendered_calls = repr(log_calls)
    assert "SensitiveCallbackSecretError" not in rendered_calls
    assert "raw callback detail" not in rendered_calls
    assert log_calls == [("Approval callback failed",)]


def test_callback_authoritative_append_failure_never_falls_back(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An uncertain authoritative terminal append must propagate and retire pending state."""
    queue, service, _authority = _echo_queue(tmp_path)
    original_record = service.record_approval_event

    def record_then_fail(**kwargs: Any) -> None:
        original_record(**kwargs)
        if kwargs["event_type"] == "approval_approved":
            raise RuntimeError("authoritative append outcome is uncertain")

    monkeypatch.setattr(service, "record_approval_event", record_then_fail)
    queue.set_callback(
        "session-a",
        lambda req: ApprovalDecision(ApprovalDecisionType.APPROVE, request_id=req.id),
        owner_key_hash="owner-a",
        run_id="run-a",
        tool_name="dangerous_tool",
        arguments={"path": "safe"},
    )

    with pytest.raises(RuntimeError, match="authoritative append outcome is uncertain"):
        queue.request_decision(
            "dangerous_tool",
            {"path": "safe"},
            context="web",
            session_id="session-a",
            run_id="run-a",
            owner_key_hash="owner-a",
            queue_if_unhandled=True,
        )

    records = [
        record
        for record in _journal_records(service)
        if record.record_type == "approval"
    ]
    terminal = [
        record
        for record in records
        if record.payload.get("event_type")
        in {"approval_approved", "approval_edited", "approval_rejected"}
    ]
    assert len(terminal) == 1
    request_id = str(terminal[0].payload["request_id"])
    assert queue.get_pending_request(request_id, owner_key_hash="owner-a") is None
    assert queue.take_decision(request_id, owner_key_hash="owner-a") is None
    args_hash = queue.arguments_hash({"path": "safe"})
    proof = queue.consume_approved_binding(
        request_id,
        **_consume_kwargs(request_id, args_hash),
    )
    assert proof.claimed_now is True
    assert proof.journal_record_hash == _echo_claims(service, request_id)[0].record_hash
    with pytest.raises(PermissionError):
        queue.consume_approved_binding(
            request_id,
            **_consume_kwargs(request_id, args_hash),
        )
    assert len(_echo_terminals(service, request_id)) == 1
    assert len(_echo_claims(service, request_id)) == 1


def test_authority_success_mirror_failure_is_cache_only_and_restart_claims_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A derived mirror error cannot turn an authoritative success into an API failure."""
    queue, service, authority = _echo_queue(tmp_path)
    original_mirror = queue._append_ledger_mirror  # noqa: SLF001
    failed = False

    def mirror_then_fail(event: dict[str, Any]) -> None:
        nonlocal failed
        original_mirror(event)
        if event["event_type"] == "approval_approved" and not failed:
            failed = True
            raise OSError("RAW_PRIVATE_MIRROR_PATH")

    monkeypatch.setattr(queue, "_append_ledger_mirror", mirror_then_fail)
    queue.set_callback(
        "session-a",
        lambda req: ApprovalDecision(ApprovalDecisionType.APPROVE, request_id=req.id),
        owner_key_hash="owner-a",
        run_id="run-a",
        tool_name="dangerous_tool",
        arguments={"path": "safe"},
    )
    decision = queue.request_decision(
        "dangerous_tool",
        {"path": "safe"},
        context="web",
        session_id="session-a",
        run_id="run-a",
        owner_key_hash="owner-a",
        queue_if_unhandled=True,
    )
    assert decision.action is ApprovalDecisionType.APPROVE

    restarted = ApprovalQueue(
        default_mode=ApprovalMode.MANUAL,
        ledger_path=tmp_path / "approvals.jsonl",
    )
    restarted.set_echo_authority(authority)
    proof = restarted.consume_approved_binding(
        decision.request_id,
        owner_key_hash="owner-a",
        session_id="session-a",
        run_id="run-a",
        tool_name="dangerous_tool",
        arguments_hash=queue.arguments_hash({"path": "safe"}),
        require_manual=True,
    )
    assert proof.claimed_now is True
    claims = _echo_claims(service, decision.request_id)
    terminals = _echo_terminals(service, decision.request_id)
    assert len(terminals) == 1
    assert len(claims) == 1
    assert proof.journal_record_hash == claims[0].record_hash
    with pytest.raises(PermissionError):
        restarted.consume_approved_binding(
            decision.request_id,
            owner_key_hash="owner-a",
            session_id="session-a",
            run_id="run-a",
            tool_name="dangerous_tool",
            arguments_hash=queue.arguments_hash({"path": "safe"}),
            require_manual=True,
        )
    assert len(_echo_claims(service, decision.request_id)) == 1
    assert len(_echo_terminals(service, decision.request_id)) == 1


@pytest.mark.parametrize(
    ("action", "arguments", "edited_arguments", "event_type"),
    [
        (
            ApprovalDecisionType.APPROVE,
            {"path": "safe"},
            None,
            "approval_approved",
        ),
        (
            ApprovalDecisionType.EDIT,
            {"path": "original"},
            {"path": "edited"},
            "approval_edited",
        ),
    ],
)
def test_authority_success_mirror_before_write_same_process_claims_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    action: ApprovalDecisionType,
    arguments: dict[str, Any],
    edited_arguments: dict[str, Any] | None,
    event_type: str,
) -> None:
    """Echo-backed memory must authorize consume when the mirror never wrote a terminal."""
    queue, service, _authority = _echo_queue(tmp_path)
    ledger_path = tmp_path / "approvals.jsonl"
    _install_mirror_before_write_failure(queue, monkeypatch)
    request_id, args_hash = _resolve_manual(
        queue,
        arguments=arguments,
        action=action,
        edited_arguments=edited_arguments,
    )
    delivered = queue.take_decision(request_id, owner_key_hash="owner-a")
    assert delivered is not None
    assert delivered.action is action
    assert queue.take_decision(request_id, owner_key_hash="owner-a") is None
    _assert_mirror_has_no_terminal(ledger_path)
    terminals = _echo_terminals(service, request_id)
    assert len(terminals) == 1
    assert terminals[0].payload["event_type"] == event_type
    assert len(_echo_claims(service, request_id)) == 0

    proof = queue.consume_approved_binding(request_id, **_consume_kwargs(request_id, args_hash))
    assert proof.claimed_now is True
    assert proof.action is action
    claims = _echo_claims(service, request_id)
    assert len(claims) == 1
    assert proof.journal_record_hash == claims[0].record_hash
    assert proof.journal_record_hash.startswith("sha256:")
    with pytest.raises(PermissionError):
        queue.consume_approved_binding(request_id, **_consume_kwargs(request_id, args_hash))
    assert len(_echo_terminals(service, request_id)) == 1
    assert len(_echo_claims(service, request_id)) == 1
    _assert_no_leaked_mirror_error(tmp_path)


def test_restart_recovers_echo_terminal_when_mirror_terminal_absent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A new queue must recover the Echo terminal without the original process memory."""
    queue, service, authority = _echo_queue(tmp_path)
    ledger_path = tmp_path / "approvals.jsonl"
    _install_mirror_before_write_failure(queue, monkeypatch)
    request_id, args_hash = _resolve_manual(queue)
    original_memory = id(queue._resolved_decisions)  # noqa: SLF001
    assert queue._resolved_decisions.get(request_id) is not None  # noqa: SLF001
    _assert_mirror_has_no_terminal(ledger_path)
    assert len(_echo_terminals(service, request_id)) == 1
    del queue

    restarted = ApprovalQueue(
        default_mode=ApprovalMode.MANUAL,
        ledger_path=ledger_path,
    )
    restarted.set_echo_authority(authority)
    assert id(restarted._resolved_decisions) != original_memory  # noqa: SLF001
    assert restarted._resolved_decisions.get(request_id) is None  # noqa: SLF001
    _assert_mirror_has_no_terminal(ledger_path)

    proof = restarted.consume_approved_binding(
        request_id,
        **_consume_kwargs(request_id, args_hash),
    )
    assert proof.claimed_now is True
    claims = _echo_claims(service, request_id)
    assert len(claims) == 1
    assert proof.journal_record_hash == claims[0].record_hash
    with pytest.raises(PermissionError):
        restarted.consume_approved_binding(
            request_id,
            **_consume_kwargs(request_id, args_hash),
        )
    assert len(_echo_terminals(service, request_id)) == 1
    assert len(_echo_claims(service, request_id)) == 1
    _assert_no_leaked_mirror_error(tmp_path)


def test_archived_echo_terminal_without_mirror_claims_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Compacted Echo history remains the only claim oracle when the mirror is empty."""
    queue, service, authority = _echo_queue(tmp_path)
    ledger_path = tmp_path / "approvals.jsonl"
    _install_mirror_before_write_failure(queue, monkeypatch)
    request_id, args_hash = _resolve_manual(queue)
    before_rows = len(_approval_rows(service, request_id))
    service.record_approval_event(
        tenant_id="owner-a",
        product_id="js-agent",
        session_id="session-a",
        run_id="run-a",
        event_type="approval_requested",
        request_id="approval_archive_filler_recovery",
        tool_name="dangerous_tool",
        arguments_hash=queue.arguments_hash({"filler": True}),
        extra={
            "context": "web",
            "requested_at": time.time(),
            "expires_at": time.time() + 3600,
            "approval_mode": "manual",
            "arguments_hash_scheme": "stable_payload_hash:v1",
        },
    )
    journal_path = service.journal_path_for_scope(
        "owner-a", product_id="js-agent", session_id="session-a"
    )
    assert service.compact_journals(max_records=1)[str(journal_path)] is True
    del queue

    restarted = ApprovalQueue(
        default_mode=ApprovalMode.MANUAL,
        ledger_path=ledger_path,
    )
    restarted.set_echo_authority(authority)
    assert restarted._resolved_decisions.get(request_id) is None  # noqa: SLF001
    _assert_mirror_has_no_terminal(ledger_path)

    proof = restarted.consume_approved_binding(
        request_id,
        **_consume_kwargs(request_id, args_hash),
    )
    assert proof.claimed_now is True
    claims = _echo_claims(service, request_id)
    assert len(claims) == 1
    assert proof.journal_record_hash == claims[0].record_hash
    with pytest.raises(PermissionError):
        restarted.consume_approved_binding(
            request_id,
            **_consume_kwargs(request_id, args_hash),
        )
    assert len(_echo_terminals(service, request_id)) == 1
    assert len(_echo_claims(service, request_id)) == 1
    assert len(_approval_rows(service, request_id)) == before_rows + 1
    _assert_no_leaked_mirror_error(tmp_path)


def test_authority_lookup_rejects_missing_echo_terminal(tmp_path: Path) -> None:
    queue, service, _authority = _echo_queue(tmp_path)
    fake_id = "approval_missing_terminal_0001"
    args_hash = queue.arguments_hash({"path": "missing"})
    before = len(_approval_rows(service, fake_id))
    with pytest.raises(PermissionError):
        queue.consume_approved_binding(fake_id, **_consume_kwargs(fake_id, args_hash))
    assert _approval_rows(service, fake_id) == []
    assert before == 0


def test_authority_lookup_rejects_conflicting_echo_terminals(tmp_path: Path) -> None:
    queue, service, authority = _echo_queue(tmp_path)
    request_id, args_hash = _resolve_manual(queue)
    record = queue._resolved_record_for_claim(request_id)  # noqa: SLF001
    assert record is not None
    service.record_approval_event(
        tenant_id="owner-a",
        product_id="js-agent",
        session_id="session-a",
        run_id="run-a",
        event_type="approval_approved",
        request_id=request_id,
        tool_name="dangerous_tool",
        arguments_hash=args_hash,
        extra={
            "context": "web",
            "requested_at": record.requested_at,
            "expires_at": record.expires_at,
            "approval_mode": "manual",
            "arguments_hash_scheme": "stable_payload_hash:v1",
        },
    )
    restarted = ApprovalQueue(
        default_mode=ApprovalMode.MANUAL,
        ledger_path=tmp_path / "approvals.jsonl",
    )
    restarted.set_echo_authority(authority)
    with pytest.raises(PermissionError):
        restarted.consume_approved_binding(
            request_id,
            **_consume_kwargs(request_id, args_hash),
        )
    assert _echo_claims(service, request_id) == []


@pytest.mark.parametrize(
    "follow_up",
    ["approval_expired", "approval_rejected", "approval_cancelled", "already_claimed"],
)
def test_authority_lookup_rejects_invalidated_echo_terminal(
    tmp_path: Path,
    follow_up: str,
) -> None:
    queue, service, authority = _echo_queue(tmp_path)
    request_id, args_hash = _resolve_manual(queue)
    record = queue._resolved_record_for_claim(request_id)  # noqa: SLF001
    assert record is not None
    if follow_up == "already_claimed":
        first = authority.claim_once(
            tenant_id="owner-a",
            session_id="session-a",
            run_id="run-a",
            request_id=request_id,
            tool_name="dangerous_tool",
            arguments_hash=args_hash,
            approval_mode="manual",
            expires_at=record.expires_at,
            requested_at=record.requested_at,
        )
        assert first.claimed_now is True
    elif follow_up == "approval_expired":
        service.record_approval_event(
            tenant_id="owner-a",
            product_id="js-agent",
            session_id="session-a",
            run_id="run-a",
            event_type="approval_expired",
            request_id=request_id,
            tool_name="dangerous_tool",
            arguments_hash=args_hash,
            extra={
                "requested_at": record.requested_at,
                "expires_at": record.expires_at,
                "approval_mode": "manual",
                "arguments_hash_scheme": "stable_payload_hash:v1",
                "reason_code": "timeout",
            },
        )
    else:
        service.record_approval_event(
            tenant_id="owner-a",
            product_id="js-agent",
            session_id="session-a",
            run_id="run-a",
            event_type=follow_up,
            request_id=request_id,
            tool_name="dangerous_tool",
            arguments_hash=args_hash,
            extra={
                "requested_at": record.requested_at,
                "expires_at": record.expires_at,
                "approval_mode": "manual",
                "arguments_hash_scheme": "stable_payload_hash:v1",
                "reason_code": "session_revoked",
            },
        )
    restarted = ApprovalQueue(
        default_mode=ApprovalMode.MANUAL,
        ledger_path=tmp_path / "approvals.jsonl",
    )
    restarted.set_echo_authority(authority)
    with pytest.raises(PermissionError):
        restarted.consume_approved_binding(
            request_id,
            **_consume_kwargs(request_id, args_hash),
        )
    if follow_up != "already_claimed":
        assert _echo_claims(service, request_id) == []


def test_authority_lookup_rejects_expired_echo_terminal(tmp_path: Path) -> None:
    queue, service, authority = _echo_queue(tmp_path)
    request_id = "approval_expired_terminal_0001"
    args_hash = queue.arguments_hash({"path": "expired"})
    now = time.time()
    service.record_approval_event(
        tenant_id="owner-a",
        product_id="js-agent",
        session_id="session-a",
        run_id="run-a",
        event_type="approval_approved",
        request_id=request_id,
        tool_name="dangerous_tool",
        arguments_hash=args_hash,
        extra={
            "context": "web",
            "requested_at": now - 120,
            "expires_at": now - 1,
            "approval_mode": "manual",
            "arguments_hash_scheme": "stable_payload_hash:v1",
        },
    )
    restarted = ApprovalQueue(
        default_mode=ApprovalMode.MANUAL,
        ledger_path=tmp_path / "approvals.jsonl",
    )
    restarted.set_echo_authority(authority)
    with pytest.raises(PermissionError):
        restarted.consume_approved_binding(
            request_id,
            **_consume_kwargs(request_id, args_hash),
        )
    assert _echo_claims(service, request_id) == []


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("owner_key_hash", "owner-other"),
        ("session_id", "session-other"),
        ("run_id", "run-other"),
        ("tool_name", "other_tool"),
        ("arguments_hash", "sha256:" + "f" * 64),
    ],
)
def test_restart_consume_rejects_binding_mismatch_from_echo_terminal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: str,
) -> None:
    queue, service, authority = _echo_queue(tmp_path)
    ledger_path = tmp_path / "approvals.jsonl"
    _install_mirror_before_write_failure(queue, monkeypatch)
    request_id, args_hash = _resolve_manual(queue)
    del queue
    restarted = ApprovalQueue(
        default_mode=ApprovalMode.MANUAL,
        ledger_path=ledger_path,
    )
    restarted.set_echo_authority(authority)
    kwargs = _consume_kwargs(request_id, args_hash)
    kwargs[field] = value
    with pytest.raises(PermissionError):
        restarted.consume_approved_binding(request_id, **kwargs)
    assert _echo_claims(service, request_id) == []


def test_authority_lookup_rejects_missing_hash_scheme(tmp_path: Path) -> None:
    queue, service, authority = _echo_queue(tmp_path)
    request_id = "approval_missing_scheme_0001"
    args_hash = queue.arguments_hash({"path": "noscheme"})
    now = time.time()
    service.record_approval_event(
        tenant_id="owner-a",
        product_id="js-agent",
        session_id="session-a",
        run_id="run-a",
        event_type="approval_approved",
        request_id=request_id,
        tool_name="dangerous_tool",
        arguments_hash=args_hash,
        extra={
            "context": "web",
            "requested_at": now,
            "expires_at": now + 300,
            "approval_mode": "manual",
        },
    )
    restarted = ApprovalQueue(
        default_mode=ApprovalMode.MANUAL,
        ledger_path=tmp_path / "approvals.jsonl",
    )
    restarted.set_echo_authority(authority)
    with pytest.raises(PermissionError):
        restarted.consume_approved_binding(
            request_id,
            **_consume_kwargs(request_id, args_hash),
        )
    assert _echo_claims(service, request_id) == []


def test_mirror_only_with_authority_is_not_production_proof(tmp_path: Path) -> None:
    """A derived mirror row cannot authorize execution when Echo has no terminal."""
    ledger_path = tmp_path / "approvals.jsonl"
    seed = ApprovalQueue(default_mode=ApprovalMode.MANUAL, ledger_path=ledger_path)
    request_id = "approval_mirror_only_0001"
    args_hash = seed.arguments_hash({"path": "mirror-only"})
    now = time.time()
    seed._append_ledger_mirror(  # noqa: SLF001
        {
            "event_type": "approval_approved",
            "request_id": request_id,
            "tool_name": "dangerous_tool",
            "context": "web",
            "session_id": "session-a",
            "run_id": "run-a",
            "owner_key_hash": "owner-a",
            "arguments_hash": args_hash,
            "arguments_hash_scheme": "stable_payload_hash:v1",
            "timestamp": now,
            "requested_at": now,
            "expires_at": now + 300,
            "approval_mode": "manual",
        }
    )
    service = EchoSafetyService(state_dir=tmp_path / "echo")
    authority = wire_echo_approval_authority(service, product_id="js-agent")
    queue = ApprovalQueue(default_mode=ApprovalMode.MANUAL, ledger_path=ledger_path)
    queue.set_echo_authority(authority)
    with pytest.raises(PermissionError):
        queue.consume_approved_binding(
            request_id,
            **_consume_kwargs(request_id, args_hash),
        )
    assert _echo_terminals(service, request_id) == []
    assert _echo_claims(service, request_id) == []


def test_lookup_approval_resolution_unknown_partition_is_side_effect_free(
    tmp_path: Path,
) -> None:
    service = EchoSafetyService(state_dir=tmp_path / "echo")
    ledger_root = _ledger_root(service)
    before = _echo_tree_snapshot(ledger_root)
    before_partitions = _partition_session_set(ledger_root)
    found = service.lookup_approval_resolution(
        tenant_id="owner-unknown-resolution",
        product_id="js-agent",
        session_id="session-unknown-resolution",
        request_id="approval_unknown_resolution_0001",
    )
    assert found is None
    assert _echo_tree_snapshot(ledger_root) == before
    assert _partition_session_set(ledger_root) == before_partitions


def test_lookup_approval_claim_unknown_partition_is_side_effect_free(
    tmp_path: Path,
) -> None:
    service = EchoSafetyService(state_dir=tmp_path / "echo")
    ledger_root = _ledger_root(service)
    before = _echo_tree_snapshot(ledger_root)
    before_partitions = _partition_session_set(ledger_root)
    found = service.lookup_approval_claim(
        tenant_id="owner-unknown-claim",
        product_id="js-agent",
        session_id="session-unknown-claim",
        request_id="approval_unknown_claim_0001",
    )
    assert found is None
    assert _echo_tree_snapshot(ledger_root) == before
    assert _partition_session_set(ledger_root) == before_partitions


def test_repeated_unknown_owners_do_not_create_partitions(tmp_path: Path) -> None:
    service = EchoSafetyService(state_dir=tmp_path / "echo")
    ledger_root = _ledger_root(service)
    before = _echo_tree_snapshot(ledger_root)
    before_partitions = _partition_session_set(ledger_root)
    for index in range(5):
        assert (
            service.lookup_approval_resolution(
                tenant_id=f"owner-unknown-{index}",
                product_id="js-agent",
                session_id=f"session-unknown-{index}",
                request_id=f"approval_unknown_repeat_{index:04d}",
            )
            is None
        )
        assert (
            service.lookup_approval_claim(
                tenant_id=f"owner-unknown-{index}",
                product_id="js-agent",
                session_id=f"session-unknown-{index}",
                request_id=f"approval_unknown_repeat_{index:04d}",
            )
            is None
        )
    assert _echo_tree_snapshot(ledger_root) == before
    assert _partition_session_set(ledger_root) == before_partitions


def test_consume_and_validate_unknown_binding_are_side_effect_free(
    tmp_path: Path,
) -> None:
    service = EchoSafetyService(state_dir=tmp_path / "echo")
    authority = wire_echo_approval_authority(service, product_id="js-agent")
    queue = ApprovalQueue(
        default_mode=ApprovalMode.MANUAL,
        ledger_path=tmp_path / "approvals.jsonl",
    )
    queue.set_echo_authority(authority)
    ledger_root = _ledger_root(service)
    before = _echo_tree_snapshot(ledger_root)
    before_partitions = _partition_session_set(ledger_root)
    request_id = "approval_unknown_binding_0001"
    args_hash = queue.arguments_hash({"path": "missing"})
    kwargs = _consume_kwargs(
        request_id,
        args_hash,
        owner_key_hash="owner-unknown-binding",
        session_id="session-unknown-binding",
    )
    with pytest.raises(PermissionError):
        queue.validate_approved_binding(request_id, **kwargs)
    with pytest.raises(PermissionError):
        queue.consume_approved_binding(request_id, **kwargs)
    assert _echo_tree_snapshot(ledger_root) == before
    assert _partition_session_set(ledger_root) == before_partitions


def test_lookup_unknown_session_never_retires_existing_session(tmp_path: Path) -> None:
    service = EchoSafetyService(
        state_dir=tmp_path / "echo",
        ledger_config=EchoLedgerConfig(max_session_partitions_per_owner=2),
    )
    _record_synthetic_terminal(
        service,
        owner="owner-cap",
        session="session-one",
        request_id="approval_cap_session_one",
    )
    _record_synthetic_terminal(
        service,
        owner="owner-cap",
        session="session-two",
        request_id="approval_cap_session_two",
    )
    product_slug, owner_slug, first_slug = _scope_partition_slugs(
        tenant_id="owner-cap",
        product_id="js-agent",
        session_id="session-one",
    )
    _product_slug, _owner_slug, second_slug = _scope_partition_slugs(
        tenant_id="owner-cap",
        product_id="js-agent",
        session_id="session-two",
    )
    owner_root = _ledger_root(service) / "partitions" / product_slug / owner_slug
    first_root = owner_root / first_slug
    second_root = owner_root / second_slug
    first_inodes = _session_file_inodes(first_root)
    second_inodes = _session_file_inodes(second_root)
    first_tree = _echo_tree_snapshot(first_root)
    second_tree = _echo_tree_snapshot(second_root)
    before_partitions = _partition_session_set(_ledger_root(service))
    assert len(before_partitions) == 2

    found = service.lookup_approval_resolution(
        tenant_id="owner-cap",
        product_id="js-agent",
        session_id="session-three",
        request_id="approval_cap_session_three",
    )
    assert found is None
    assert _partition_session_set(_ledger_root(service)) == before_partitions
    assert first_root.is_dir()
    assert second_root.is_dir()
    assert not (owner_root / _scope_partition_slugs(
        tenant_id="owner-cap",
        product_id="js-agent",
        session_id="session-three",
    )[2]).exists()
    assert _session_file_inodes(first_root) == first_inodes
    assert _session_file_inodes(second_root) == second_inodes
    assert _echo_tree_snapshot(first_root) == first_tree
    assert _echo_tree_snapshot(second_root) == second_tree
    assert (
        service.lookup_approval_resolution(
            tenant_id="owner-cap",
            product_id="js-agent",
            session_id="session-one",
            request_id="approval_cap_session_one",
        )
        is not None
    )
    assert (
        service.lookup_approval_resolution(
            tenant_id="owner-cap",
            product_id="js-agent",
            session_id="session-two",
            request_id="approval_cap_session_two",
        )
        is not None
    )


def test_lookup_approval_resolution_existing_active_partition_succeeds(
    tmp_path: Path,
) -> None:
    queue, service, authority = _echo_queue(tmp_path)
    request_id, args_hash = _resolve_manual(queue)
    resolution = authority.lookup_resolution(
        tenant_id="owner-a",
        session_id="session-a",
        request_id=request_id,
    )
    assert resolution is not None
    assert resolution.action == "approval_approved"
    assert resolution.arguments_hash == args_hash
    assert resolution.request_id == request_id
    assert not hasattr(resolution, "arguments")
    assert authority.lookup_claim(
        tenant_id="owner-a",
        session_id="session-a",
        request_id=request_id,
    ) is None


def test_lookup_approval_resolution_compacted_archive_succeeds(tmp_path: Path) -> None:
    queue, service, authority = _echo_queue(tmp_path)
    request_id, args_hash = _resolve_manual(queue)
    service.record_approval_event(
        tenant_id="owner-a",
        product_id="js-agent",
        session_id="session-a",
        run_id="run-a",
        event_type="approval_requested",
        request_id="approval_archive_lookup_filler",
        tool_name="dangerous_tool",
        arguments_hash=queue.arguments_hash({"filler": True}),
        extra={
            "context": "web",
            "requested_at": time.time(),
            "expires_at": time.time() + 3600,
            "approval_mode": "manual",
            "arguments_hash_scheme": "stable_payload_hash:v1",
        },
    )
    journal_path = service.journal_path_for_scope(
        "owner-a", product_id="js-agent", session_id="session-a"
    )
    assert service.compact_journals(max_records=1)[str(journal_path)] is True
    resolution = authority.lookup_resolution(
        tenant_id="owner-a",
        session_id="session-a",
        request_id=request_id,
    )
    assert resolution is not None
    assert resolution.arguments_hash == args_hash
    proof = queue.consume_approved_binding(
        request_id,
        **_consume_kwargs(request_id, args_hash),
    )
    assert proof.claimed_now is True
    with pytest.raises(PermissionError):
        queue.consume_approved_binding(
            request_id,
            **_consume_kwargs(request_id, args_hash),
        )


def test_fresh_service_lookup_survives_real_writer_ancestor_modes(
    tmp_path: Path,
) -> None:
    """A new service must recover a real writer partition whose parents are 0755."""
    queue, service, _authority = _echo_queue(tmp_path)
    request_id, args_hash = _resolve_manual(queue)
    _partitions, product_dir, owner_dir, session_dir = _partition_dirs(
        service, owner="owner-a", session="session-a"
    )
    assert stat.S_IMODE(product_dir.stat().st_mode) == 0o755
    assert stat.S_IMODE(owner_dir.stat().st_mode) == 0o755
    assert stat.S_IMODE(session_dir.stat().st_mode) == 0o700
    state_dir = tmp_path / "echo"
    del queue, service, _authority

    fresh = _fresh_service(state_dir)
    resolution = fresh.lookup_approval_resolution(
        tenant_id="owner-a",
        product_id="js-agent",
        session_id="session-a",
        request_id=request_id,
    )
    assert resolution is not None
    assert resolution.arguments_hash == args_hash
    restarted = ApprovalQueue(
        default_mode=ApprovalMode.MANUAL,
        ledger_path=tmp_path / "approvals.jsonl",
    )
    restarted.set_echo_authority(wire_echo_approval_authority(fresh, product_id="js-agent"))
    proof = restarted.consume_approved_binding(
        request_id,
        **_consume_kwargs(request_id, args_hash),
    )
    assert proof.claimed_now is True
    with pytest.raises(PermissionError):
        restarted.consume_approved_binding(
            request_id,
            **_consume_kwargs(request_id, args_hash),
        )


def test_lookup_does_not_construct_file_echo_ledger(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    queue, service, _authority = _echo_queue(tmp_path)
    request_id, args_hash = _resolve_manual(queue)
    partitions, product_dir, owner_dir, _session_dir = _partition_dirs(
        service, owner="owner-a", session="session-a"
    )
    _chmod_writer_ancestors_private(partitions, product_dir, owner_dir)
    state_dir = tmp_path / "echo"
    del queue, service, _authority
    fresh = _fresh_service(state_dir)

    def _forbidden_init(self: FileEchoLedger, *args: Any, **kwargs: Any) -> None:
        raise AssertionError("FileEchoLedger must not be constructed for lookup")

    monkeypatch.setattr(FileEchoLedger, "__init__", _forbidden_init)
    resolution = fresh.lookup_approval_resolution(
        tenant_id="owner-a",
        product_id="js-agent",
        session_id="session-a",
        request_id=request_id,
    )
    assert resolution is not None
    assert resolution.arguments_hash == args_hash


def test_lookup_missing_lock_is_side_effect_free(tmp_path: Path) -> None:
    queue, service, _authority = _echo_queue(tmp_path)
    request_id, _args_hash = _resolve_manual(queue)
    _partitions, _product_dir, _owner_dir, session_dir = _partition_dirs(
        service, owner="owner-a", session="session-a"
    )
    lock_path = session_dir / "chat.jsonl.lock"
    assert lock_path.is_file()
    lock_path.unlink()
    ledger_root = _ledger_root(service)
    before = _echo_tree_snapshot(ledger_root)
    before_inodes = _session_file_inodes(session_dir)
    found = service.lookup_approval_resolution(
        tenant_id="owner-a",
        product_id="js-agent",
        session_id="session-a",
        request_id=request_id,
    )
    assert found is None
    assert not lock_path.exists()
    assert _echo_tree_snapshot(ledger_root) == before
    assert _session_file_inodes(session_dir) == before_inodes


def test_lookup_journal_unlink_race_does_not_recreate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    queue, service, _authority = _echo_queue(tmp_path)
    request_id, _args_hash = _resolve_manual(queue)
    partitions, product_dir, owner_dir, session_dir = _partition_dirs(
        service, owner="owner-a", session="session-a"
    )
    journal_path = session_dir / "chat.jsonl"
    _chmod_writer_ancestors_private(partitions, product_dir, owner_dir)
    state_dir = tmp_path / "echo"
    del queue, service, _authority
    real_open = os.open

    def open_unlink(
        path: str | bytes | os.PathLike[str],
        flags: int,
        *args: Any,
        dir_fd: int | None = None,
        **kwargs: Any,
    ) -> int:
        name = os.fsdecode(path)
        if dir_fd is not None and name == "chat.jsonl":
            try:
                os.unlink(name, dir_fd=dir_fd)
            except FileNotFoundError:
                pass
        elif (
            dir_fd is None
            and "partitions" in name.replace("\\", "/")
            and name.endswith("/chat.jsonl")
        ):
            Path(name).unlink(missing_ok=True)
        return real_open(path, flags, *args, dir_fd=dir_fd, **kwargs)

    monkeypatch.setattr(os, "open", open_unlink)
    fresh = _fresh_service(state_dir)
    before_inodes = {
        path.name: path.stat().st_ino
        for path in session_dir.iterdir()
        if path.is_file()
    }
    found = fresh.lookup_approval_resolution(
        tenant_id="owner-a",
        product_id="js-agent",
        session_id="session-a",
        request_id=request_id,
    )
    assert found is None
    assert not journal_path.exists()
    assert not any(path.name.endswith(".tmp") for path in session_dir.iterdir())
    after_inodes = {
        path.name: path.stat().st_ino
        for path in session_dir.iterdir()
        if path.is_file()
    }
    assert "chat.jsonl" not in after_inodes
    assert after_inodes.get("journal.key") == before_inodes.get("journal.key")
    assert after_inodes.get("permit.key") == before_inodes.get("permit.key")


@pytest.mark.parametrize("target", ["journal", "key", "lock", "session"])
def test_lookup_symlink_swap_does_not_touch_canary(tmp_path: Path, target: str) -> None:
    queue, service, _authority = _echo_queue(tmp_path)
    request_id, _args_hash = _resolve_manual(queue)
    _partitions, _product_dir, _owner_dir, session_dir = _partition_dirs(
        service, owner="owner-a", session="session-a"
    )
    canary = tmp_path / "outside_canary.txt"
    canary.write_text("CANARY_PAYLOAD", encoding="utf-8")
    os.chmod(canary, 0o600)
    canary_stat = canary.stat()
    outside_dir = tmp_path / "outside_session"
    if target == "session":
        outside_dir.mkdir(mode=0o700)
        marker = outside_dir / "marker.txt"
        marker.write_text("SESSION_CANARY", encoding="utf-8")
        os.chmod(marker, 0o600)
        marker_stat = marker.stat()
        session_dir.rename(session_dir.with_name(session_dir.name + ".orig"))
        session_dir.symlink_to(outside_dir)
    else:
        names = {
            "journal": "chat.jsonl",
            "key": "journal.key",
            "lock": "chat.jsonl.lock",
        }
        target_path = session_dir / names[target]
        target_path.unlink()
        target_path.symlink_to(canary)
    found = service.lookup_approval_resolution(
        tenant_id="owner-a",
        product_id="js-agent",
        session_id="session-a",
        request_id=request_id,
    )
    assert found is None
    if target == "session":
        after_marker = marker.stat()
        assert marker.read_text(encoding="utf-8") == "SESSION_CANARY"
        assert stat.S_IMODE(after_marker.st_mode) == 0o600
        assert (after_marker.st_dev, after_marker.st_ino) == (
            marker_stat.st_dev,
            marker_stat.st_ino,
        )
        assert {path.name for path in outside_dir.iterdir()} == {"marker.txt"}
    else:
        after = canary.stat()
        assert canary.read_text(encoding="utf-8") == "CANARY_PAYLOAD"
        assert stat.S_IMODE(after.st_mode) == 0o600
        assert (after.st_dev, after.st_ino) == (canary_stat.st_dev, canary_stat.st_ino)


@pytest.mark.parametrize("target", ["journal", "lock"])
@pytest.mark.parametrize("kind", ["fifo", "directory", "hardlink"])
def test_lookup_rejects_special_journal_without_blocking(
    tmp_path: Path,
    target: str,
    kind: str,
) -> None:
    queue, service, _authority = _echo_queue(tmp_path)
    request_id, _args_hash = _resolve_manual(queue)
    _partitions, _product_dir, _owner_dir, session_dir = _partition_dirs(
        service, owner="owner-a", session="session-a"
    )
    node = session_dir / ("chat.jsonl" if target == "journal" else "chat.jsonl.lock")
    backup = session_dir / (node.name + ".bak")
    node.replace(backup)
    if kind == "fifo":
        os.mkfifo(node, 0o600)
    elif kind == "directory":
        node.mkdir(mode=0o700)
    else:
        other = tmp_path / f"hardlink-{target}"
        other.write_bytes(backup.read_bytes() if backup.is_file() else b"lock")
        os.link(other, node)
    ledger_root = _ledger_root(service)
    before = _echo_tree_snapshot(ledger_root)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(
            service.lookup_approval_resolution,
            tenant_id="owner-a",
            product_id="js-agent",
            session_id="session-a",
            request_id=request_id,
        )
        try:
            found = future.result(timeout=1.5)
        except concurrent.futures.TimeoutError:
            pytest.fail("lookup blocked on special journal node")
    assert found is None
    assert _echo_tree_snapshot(ledger_root) == before


def test_lookup_rename_recreate_does_not_read_attacker_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    queue, service, _authority = _echo_queue(tmp_path)
    request_id, args_hash = _resolve_manual(queue)
    partitions, product_dir, owner_dir, session_dir = _partition_dirs(
        service, owner="owner-a", session="session-a"
    )
    _chmod_writer_ancestors_private(partitions, product_dir, owner_dir)
    state_dir = tmp_path / "echo"
    del queue, service, _authority
    real_open = os.open
    attacker_payload = "attacker-not-a-journal\n"

    def _recreate_attacker(session: Path) -> None:
        if session.exists() and not session.name.endswith(".moved"):
            session.rename(session.with_name(session.name + ".moved"))
        if not session.exists():
            session.mkdir(mode=0o700)
        journal = session / "chat.jsonl"
        if not journal.exists():
            journal.write_text(attacker_payload, encoding="utf-8")

    def open_recreate(
        path: str | bytes | os.PathLike[str],
        flags: int,
        *args: Any,
        dir_fd: int | None = None,
        **kwargs: Any,
    ) -> int:
        name = os.fsdecode(path)
        if dir_fd is not None and name == "chat.jsonl":
            try:
                _recreate_attacker(Path(os.readlink(f"/dev/fd/{dir_fd}")))
            except OSError:
                pass
        elif (
            dir_fd is None
            and "partitions" in name.replace("\\", "/")
            and name.endswith("/chat.jsonl")
            and flags & os.O_CREAT
        ):
            _recreate_attacker(Path(name).parent)
        return real_open(path, flags, *args, dir_fd=dir_fd, **kwargs)

    monkeypatch.setattr(os, "open", open_recreate)
    fresh = _fresh_service(state_dir)
    found = fresh.lookup_approval_resolution(
        tenant_id="owner-a",
        product_id="js-agent",
        session_id="session-a",
        request_id=request_id,
    )
    assert found is None or found.arguments_hash == args_hash
    if session_dir.exists() and (session_dir / "chat.jsonl").is_file():
        text = (session_dir / "chat.jsonl").read_text(encoding="utf-8")
        if text == attacker_payload:
            assert found is None or found.arguments_hash == args_hash
            assert not (session_dir / "chat.jsonl.lock").exists()


def test_lookup_does_not_resurrect_retired_session(tmp_path: Path) -> None:
    service = EchoSafetyService(
        state_dir=tmp_path / "echo",
        ledger_config=EchoLedgerConfig(max_session_partitions_per_owner=2),
    )
    first_id = "approval_retire_one"
    _record_synthetic_terminal(
        service, owner="owner-cap", session="session-one", request_id=first_id
    )
    _record_synthetic_terminal(
        service, owner="owner-cap", session="session-two", request_id="approval_retire_two"
    )
    _record_synthetic_terminal(
        service,
        owner="owner-cap",
        session="session-three",
        request_id="approval_retire_three",
    )
    ledger_root = _ledger_root(service)
    before = _echo_tree_snapshot(ledger_root)
    found = service.lookup_approval_resolution(
        tenant_id="owner-cap",
        product_id="js-agent",
        session_id="session-one",
        request_id=first_id,
    )
    assert found is None
    assert _echo_tree_snapshot(ledger_root) == before
    _product, _owner, retired_slug = _scope_partition_slugs(
        tenant_id="owner-cap",
        product_id="js-agent",
        session_id="session-one",
    )
    assert retired_slug not in " ".join(_partition_session_set(ledger_root))


def test_lookup_fails_closed_while_partition_guard_exclusive(tmp_path: Path) -> None:
    queue, service, _authority = _echo_queue(tmp_path)
    request_id, _args_hash = _resolve_manual(queue)
    guard = _ledger_root(service) / "partitions.guard"
    assert guard.is_file()
    ctx = multiprocessing.get_context("spawn")
    ready = ctx.Event()
    release = ctx.Event()
    holder = ctx.Process(
        target=_hold_exclusive_lock_until_released,
        args=(str(guard), ready, release),
    )
    holder.start()
    try:
        assert ready.wait(5)
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(
                service.lookup_approval_resolution,
                tenant_id="owner-a",
                product_id="js-agent",
                session_id="session-a",
                request_id=request_id,
            )
            try:
                found = future.result(timeout=1.5)
            except concurrent.futures.TimeoutError:
                pytest.fail("lookup blocked while partition guard was exclusive")
        assert found is None
    finally:
        release.set()
        holder.join(5)
        if holder.is_alive():
            holder.terminate()


def test_lookup_corrupt_tail_does_not_repair_journal(tmp_path: Path) -> None:
    queue, service, _authority = _echo_queue(tmp_path)
    request_id, _args_hash = _resolve_manual(queue)
    _partitions, _product_dir, _owner_dir, session_dir = _partition_dirs(
        service, owner="owner-a", session="session-a"
    )
    journal_path = session_dir / "chat.jsonl"
    journal_path.write_bytes(journal_path.read_bytes() + b"\n{not-json")
    ledger_root = _ledger_root(service)
    before = _echo_tree_snapshot(ledger_root)
    found = service.lookup_approval_resolution(
        tenant_id="owner-a",
        product_id="js-agent",
        session_id="session-a",
        request_id=request_id,
    )
    assert found is None
    assert _echo_tree_snapshot(ledger_root) == before


def test_callback_and_http_decide_race_has_one_winning_terminal(tmp_path: Path) -> None:
    """HTTP resolution that wins while callback runs must be the sole terminal."""
    queue, service, _authority = _echo_queue(tmp_path)
    callback_entered = threading.Event()
    release_callback = threading.Event()
    callback_request_ids: list[str] = []

    def callback(req: Any) -> ApprovalDecision:
        callback_request_ids.append(req.id)
        callback_entered.set()
        assert release_callback.wait(timeout=5)
        return ApprovalDecision(
            ApprovalDecisionType.EDIT,
            request_id=req.id,
            edited_arguments={"x": 2},
        )

    queue.set_callback(
        "session-a",
        callback,
        owner_key_hash="owner-a",
        run_id="run-a",
        tool_name="dangerous_tool",
        arguments={"x": 1},
    )
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        callback_future = pool.submit(
            queue.request_decision,
            "dangerous_tool",
            {"x": 1},
            "web",
            ApprovalMode.MANUAL,
            "session-a",
            None,
            run_id="run-a",
            owner_key_hash="owner-a",
            queue_if_unhandled=True,
        )
        assert callback_entered.wait(timeout=5)
        request_id = callback_request_ids[0]
        http_winner = queue.decide(
            request_id,
            ApprovalDecisionType.EDIT,
            edited_arguments={"x": 3},
            owner_key_hash="owner-a",
        )
        release_callback.set()
        callback_result = callback_future.result(timeout=5)

    assert http_winner.action is ApprovalDecisionType.EDIT
    assert http_winner.edited_arguments == {"x": 3}
    assert callback_result.action is ApprovalDecisionType.EDIT
    assert callback_result.edited_arguments == {"x": 3}
    terminals = [
        record
        for record in _journal_records(service)
        if record.record_type == "approval"
        and record.payload.get("request_id") == request_id
        and record.payload.get("event_type")
        in {
            "approval_approved",
            "approval_edited",
            "approval_rejected",
            "approval_responded",
            "approval_expired",
            "approval_cancelled",
        }
    ]
    assert len(terminals) == 1
    assert terminals[0].payload["event_type"] == "approval_edited"
    assert terminals[0].payload["arguments_hash"] == queue.arguments_hash({"x": 3})
    assert queue.get_stats()["resolved"] == 1
    proof = queue.consume_approved_binding(
        request_id,
        owner_key_hash="owner-a",
        session_id="session-a",
        run_id="run-a",
        tool_name="dangerous_tool",
        arguments_hash=queue.arguments_hash({"x": 3}),
        require_manual=True,
    )
    assert proof.claimed_now is True


def test_http_decide_uncertain_append_retires_request_without_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A terminal possibly persisted by Echo can never be resolved a second time."""
    queue, service, _authority = _echo_queue(tmp_path)
    pending = queue.request_decision(
        "dangerous_tool",
        {"x": 1},
        context="web",
        session_id="session-a",
        run_id="run-a",
        owner_key_hash="owner-a",
        queue_if_unhandled=True,
    )
    original_record = service.record_approval_event

    def record_then_fail(**kwargs: Any) -> None:
        original_record(**kwargs)
        if kwargs["event_type"] == "approval_edited":
            raise RuntimeError("authoritative append outcome is uncertain")

    monkeypatch.setattr(service, "record_approval_event", record_then_fail)
    with pytest.raises(RuntimeError, match="authoritative append outcome is uncertain"):
        queue.decide(
            pending.request_id,
            ApprovalDecisionType.EDIT,
            edited_arguments={"x": 2},
            owner_key_hash="owner-a",
        )
    assert queue.get_pending_request(pending.request_id, owner_key_hash="owner-a") is None
    assert queue.take_decision(pending.request_id, owner_key_hash="owner-a") is None
    args_hash = queue.arguments_hash({"x": 2})
    proof = queue.consume_approved_binding(
        pending.request_id,
        **_consume_kwargs(pending.request_id, args_hash),
    )
    assert proof.claimed_now is True
    assert proof.journal_record_hash == _echo_claims(service, pending.request_id)[0].record_hash
    with pytest.raises(PermissionError):
        queue.consume_approved_binding(
            pending.request_id,
            **_consume_kwargs(pending.request_id, args_hash),
        )

    monkeypatch.setattr(service, "record_approval_event", original_record)
    retry = queue.decide(
        pending.request_id,
        ApprovalDecisionType.EDIT,
        edited_arguments={"x": 3},
        owner_key_hash="owner-a",
    )
    assert retry.action is ApprovalDecisionType.PENDING
    terminals = [
        record
        for record in _journal_records(service)
        if record.record_type == "approval"
        and record.payload.get("request_id") == pending.request_id
        and record.payload.get("event_type")
        in {
            "approval_approved",
            "approval_edited",
            "approval_rejected",
            "approval_responded",
            "approval_expired",
            "approval_cancelled",
        }
    ]
    assert len(terminals) == 1
    assert terminals[0].payload["arguments_hash"] == args_hash
    assert len(_echo_claims(service, pending.request_id)) == 1


@pytest.mark.parametrize("raw_action", ["edit", "approve", "unknown"])
def test_callback_rejects_non_enum_action_without_terminal(
    tmp_path: Path,
    raw_action: str,
) -> None:
    """StrEnum equality must not let a raw string cross the authority boundary."""
    queue, service, _authority = _echo_queue(tmp_path)

    def callback(req: Any) -> ApprovalDecision:
        return ApprovalDecision(  # type: ignore[arg-type]
            raw_action,
            request_id=req.id,
            edited_arguments={"x": 2},
        )

    queue.set_callback(
        "session-a",
        callback,
        owner_key_hash="owner-a",
        run_id="run-a",
        tool_name="dangerous_tool",
        arguments={"x": 1},
    )
    decision = queue.request_decision(
        "dangerous_tool",
        {"x": 1},
        context="web",
        session_id="session-a",
        run_id="run-a",
        owner_key_hash="owner-a",
        queue_if_unhandled=True,
    )
    assert type(decision.action) is ApprovalDecisionType
    assert decision.action is ApprovalDecisionType.PENDING
    terminals = [
        record
        for record in _journal_records(service)
        if record.record_type == "approval"
        and record.payload.get("event_type") != "approval_requested"
    ]
    assert terminals == []


def test_callback_respond_uses_responded_terminal(tmp_path: Path) -> None:
    queue, service, _authority = _echo_queue(tmp_path)
    queue.set_callback(
        "session-a",
        lambda req: ApprovalDecision(
            ApprovalDecisionType.RESPOND,
            request_id=req.id,
            response="safe response",
        ),
        owner_key_hash="owner-a",
        run_id="run-a",
        tool_name="dangerous_tool",
        arguments={"x": 1},
    )
    decision = queue.request_decision(
        "dangerous_tool",
        {"x": 1},
        context="web",
        session_id="session-a",
        run_id="run-a",
        owner_key_hash="owner-a",
    )
    assert type(decision.action) is ApprovalDecisionType
    assert decision.action is ApprovalDecisionType.RESPOND
    terminal_types = [
        record.payload.get("event_type")
        for record in _journal_records(service)
        if record.record_type == "approval"
        and record.payload.get("event_type") != "approval_requested"
    ]
    assert terminal_types == ["approval_responded"]


def test_callback_pending_is_not_a_resolution(tmp_path: Path) -> None:
    queue, service, _authority = _echo_queue(tmp_path)
    queue.set_callback(
        "session-a",
        lambda req: ApprovalDecision(ApprovalDecisionType.PENDING, request_id=req.id),
        owner_key_hash="owner-a",
        run_id="run-a",
        tool_name="dangerous_tool",
        arguments={"x": 1},
    )
    decision = queue.request_decision(
        "dangerous_tool",
        {"x": 1},
        context="web",
        session_id="session-a",
        run_id="run-a",
        owner_key_hash="owner-a",
        queue_if_unhandled=True,
    )
    assert decision.action is ApprovalDecisionType.PENDING
    assert queue.get_pending_request(decision.request_id, owner_key_hash="owner-a") is not None
    assert [
        record
        for record in _journal_records(service)
        if record.record_type == "approval"
        and record.payload.get("event_type") != "approval_requested"
    ] == []


@pytest.mark.parametrize("invalid_result", ["reject", 1, object()])
def test_callback_rejects_truthy_non_decision_results_without_terminal(
    tmp_path: Path,
    invalid_result: object,
) -> None:
    queue, service, _authority = _echo_queue(tmp_path)
    queue.set_callback(
        "session-a",
        lambda _req: invalid_result,  # type: ignore[arg-type,return-value]
        owner_key_hash="owner-a",
        run_id="run-a",
        tool_name="dangerous_tool",
        arguments={"x": 1},
    )
    decision = queue.request_decision(
        "dangerous_tool",
        {"x": 1},
        context="web",
        session_id="session-a",
        run_id="run-a",
        owner_key_hash="owner-a",
        queue_if_unhandled=True,
    )
    assert decision.action is ApprovalDecisionType.PENDING
    assert [
        record
        for record in _journal_records(service)
        if record.record_type == "approval"
        and record.payload.get("event_type") != "approval_requested"
    ] == []


def test_callback_respond_requires_exact_nonempty_string(tmp_path: Path) -> None:
    queue, service, _authority = _echo_queue(tmp_path)
    queue.set_callback(
        "session-a",
        lambda req: ApprovalDecision(
            ApprovalDecisionType.RESPOND,
            request_id=req.id,
            response=object(),  # type: ignore[arg-type]
        ),
        owner_key_hash="owner-a",
        run_id="run-a",
        tool_name="dangerous_tool",
        arguments={"x": 1},
    )
    decision = queue.request_decision(
        "dangerous_tool",
        {"x": 1},
        context="web",
        session_id="session-a",
        run_id="run-a",
        owner_key_hash="owner-a",
        queue_if_unhandled=True,
    )
    assert decision.action is ApprovalDecisionType.PENDING
    assert [
        record
        for record in _journal_records(service)
        if record.record_type == "approval"
        and record.payload.get("event_type") != "approval_requested"
    ] == []


@pytest.mark.parametrize("raw_action", ["edit", "approve", "pending", "unknown"])
def test_decide_rejects_non_enum_action(
    tmp_path: Path,
    raw_action: str,
) -> None:
    queue, service, _authority = _echo_queue(tmp_path)
    pending = queue.request_decision(
        "dangerous_tool",
        {"x": 1},
        context="web",
        session_id="session-a",
        run_id="run-a",
        owner_key_hash="owner-a",
        queue_if_unhandled=True,
    )
    with pytest.raises(ValueError, match="approval action is invalid"):
        queue.decide(  # type: ignore[arg-type]
            pending.request_id,
            raw_action,
            edited_arguments={"x": 2},
            owner_key_hash="owner-a",
        )
    assert queue.get_pending_request(pending.request_id, owner_key_hash="owner-a") is not None
    assert [
        record
        for record in _journal_records(service)
        if record.record_type == "approval"
        and record.payload.get("event_type") != "approval_requested"
    ] == []


@pytest.mark.parametrize("failure_phase", ["before_append", "after_append"])
def test_requested_append_failure_never_publishes_pending(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_phase: str,
) -> None:
    queue, service, _authority = _echo_queue(tmp_path)
    original_record = service.record_approval_event
    attempted_request_ids: list[str] = []

    def fail_requested(**kwargs: Any) -> None:
        if kwargs["event_type"] != "approval_requested":
            original_record(**kwargs)
            return
        attempted_request_ids.append(kwargs["request_id"])
        if failure_phase == "after_append":
            original_record(**kwargs)
        raise RuntimeError("requested append failed")

    monkeypatch.setattr(service, "record_approval_event", fail_requested)
    with pytest.raises(RuntimeError, match="requested append failed"):
        queue.request_decision(
            "dangerous_tool",
            {"x": 1},
            context="web",
            session_id="session-a",
            run_id="run-a",
            owner_key_hash="owner-a",
            queue_if_unhandled=True,
        )
    assert queue.get_pending(owner_key_hash="owner-a") == []
    request_id = attempted_request_ids[0]
    monkeypatch.setattr(service, "record_approval_event", original_record)
    assert (
        queue.decide(
            request_id,
            ApprovalDecisionType.APPROVE,
            owner_key_hash="owner-a",
        ).action
        is ApprovalDecisionType.PENDING
    )
    with pytest.raises(PermissionError):
        queue.consume_approved_binding(
            request_id,
            owner_key_hash="owner-a",
            session_id="session-a",
            run_id="run-a",
            tool_name="dangerous_tool",
            arguments_hash=queue.arguments_hash({"x": 1}),
            require_manual=True,
        )


def test_cli_uncertain_terminal_retires_request_without_second_resolution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    queue, service, _authority = _echo_queue(tmp_path)
    queue._input_stream = lambda _prompt: "y"  # noqa: SLF001 - CLI decision fixture
    original_record = service.record_approval_event
    request_ids: list[str] = []

    def record_then_fail(**kwargs: Any) -> None:
        original_record(**kwargs)
        if kwargs["event_type"] == "approval_approved":
            request_ids.append(kwargs["request_id"])
            raise RuntimeError("CLI terminal outcome is uncertain")

    monkeypatch.setattr(service, "record_approval_event", record_then_fail)
    with pytest.raises(RuntimeError, match="CLI terminal outcome is uncertain"):
        queue.request_decision(
            "dangerous_tool",
            {"x": 1},
            context="cli",
            session_id="session-a",
            run_id="run-a",
            owner_key_hash="owner-a",
        )
    request_id = request_ids[0]
    assert queue.get_pending_request(request_id, owner_key_hash="owner-a") is None
    monkeypatch.setattr(service, "record_approval_event", original_record)
    assert (
        queue.decide(
            request_id,
            ApprovalDecisionType.APPROVE,
            owner_key_hash="owner-a",
        ).action
        is ApprovalDecisionType.PENDING
    )
    terminals = [
        record
        for record in _journal_records(service)
        if record.record_type == "approval"
        and record.payload.get("request_id") == request_id
        and record.payload.get("event_type")
        in {"approval_approved", "approval_rejected"}
    ]
    assert len(terminals) == 1


def test_cli_and_http_decide_race_has_one_winning_terminal(tmp_path: Path) -> None:
    queue, service, _authority = _echo_queue(tmp_path)
    prompt_entered = threading.Event()
    release_prompt = threading.Event()

    def input_stream(_prompt: str) -> str:
        prompt_entered.set()
        assert release_prompt.wait(timeout=5)
        return "y"

    queue._input_stream = input_stream  # noqa: SLF001
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        cli_future = pool.submit(
            queue.request_decision,
            "dangerous_tool",
            {"x": 1},
            "cli",
            ApprovalMode.MANUAL,
            "session-a",
            None,
            run_id="run-a",
            owner_key_hash="owner-a",
            queue_if_unhandled=True,
        )
        assert prompt_entered.wait(timeout=5)
        pending = queue.get_pending(owner_key_hash="owner-a")
        assert len(pending) == 1
        winner = queue.decide(
            pending[0].id,
            ApprovalDecisionType.EDIT,
            edited_arguments={"x": 3},
            owner_key_hash="owner-a",
        )
        release_prompt.set()
        cli_result = cli_future.result(timeout=5)

    assert winner.action is ApprovalDecisionType.EDIT
    assert cli_result.action is ApprovalDecisionType.EDIT
    assert cli_result.edited_arguments == {"x": 3}
    terminals = [
        record
        for record in _journal_records(service)
        if record.record_type == "approval"
        and record.payload.get("request_id") == pending[0].id
        and record.payload.get("event_type") != "approval_requested"
    ]
    assert len(terminals) == 1
    assert terminals[0].payload["event_type"] == "approval_edited"


def test_no_handler_and_http_decide_race_has_one_winning_terminal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    queue, service, _authority = _echo_queue(tmp_path)
    no_handler_entered = threading.Event()
    release_no_handler = threading.Event()
    original_warning = approvals_module.logger.warning

    def blocking_warning(message: str, *args: Any, **kwargs: Any) -> None:
        if message.startswith("No approval handler"):
            no_handler_entered.set()
            assert release_no_handler.wait(timeout=5)
        original_warning(message, *args, **kwargs)

    monkeypatch.setattr(approvals_module.logger, "warning", blocking_warning)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        no_handler_future = pool.submit(
            queue.request_decision,
            "dangerous_tool",
            {"x": 1},
            "unknown",
            ApprovalMode.MANUAL,
            "session-a",
            None,
            run_id="run-a",
            owner_key_hash="owner-a",
        )
        assert no_handler_entered.wait(timeout=5)
        pending = queue.get_pending(owner_key_hash="owner-a")
        assert len(pending) == 1
        winner = queue.decide(
            pending[0].id,
            ApprovalDecisionType.EDIT,
            edited_arguments={"x": 3},
            owner_key_hash="owner-a",
        )
        release_no_handler.set()
        no_handler_result = no_handler_future.result(timeout=5)

    assert winner.action is ApprovalDecisionType.EDIT
    assert no_handler_result.action is ApprovalDecisionType.EDIT
    terminals = [
        record
        for record in _journal_records(service)
        if record.record_type == "approval"
        and record.payload.get("request_id") == pending[0].id
        and record.payload.get("event_type") != "approval_requested"
    ]
    assert len(terminals) == 1
    assert terminals[0].payload["event_type"] == "approval_edited"


def test_authoritative_sink_reentry_cannot_write_second_terminal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    queue, service, _authority = _echo_queue(tmp_path)
    original_record = service.record_approval_event
    reentrant_results: list[ApprovalDecision] = []

    def reenter_decide(**kwargs: Any) -> None:
        if kwargs["event_type"] == "approval_approved" and not reentrant_results:
            reentrant_results.append(
                queue.decide(
                    kwargs["request_id"],
                    ApprovalDecisionType.REJECT,
                    owner_key_hash="owner-a",
                )
            )
        original_record(**kwargs)

    monkeypatch.setattr(service, "record_approval_event", reenter_decide)
    pending = queue.request_decision(
        "dangerous_tool",
        {"x": 1},
        context="web",
        session_id="session-a",
        run_id="run-a",
        owner_key_hash="owner-a",
        queue_if_unhandled=True,
    )
    outer = queue.decide(
        pending.request_id,
        ApprovalDecisionType.APPROVE,
        owner_key_hash="owner-a",
    )
    assert outer.action is ApprovalDecisionType.APPROVE
    assert len(reentrant_results) == 1
    assert reentrant_results[0].action is ApprovalDecisionType.PENDING
    terminals = [
        record
        for record in _journal_records(service)
        if record.record_type == "approval"
        and record.payload.get("request_id") == pending.request_id
        and record.payload.get("event_type") != "approval_requested"
    ]
    assert len(terminals) == 1
    assert terminals[0].payload["event_type"] == "approval_approved"


# ---------------------------------------------------------------------------
# Contract 2: EDIT final hash throughout, mutation after decision has no effect
# ---------------------------------------------------------------------------


def test_edit_final_hash_throughout(tmp_path: Path) -> None:
    """EDIT binds defensive-copy of edited final snapshot; mutation has no effect."""
    queue, _service, _authority = _echo_queue(tmp_path)
    original = {"path": "original.txt"}
    edited = {"path": "edited.txt"}

    pending = queue.request_decision(
        "dangerous_tool",
        original,
        context="web",
        session_id="session-a",
        run_id="run-a",
        owner_key_hash="owner-a",
        queue_if_unhandled=True,
    )
    edited_copy = dict(edited)
    queue.decide(
        pending.request_id,
        ApprovalDecisionType.EDIT,
        edited_arguments=edited_copy,
        owner_key_hash="owner-a",
    )

    # Mutate the copy after decision
    edited_copy["path"] = "mutated.txt"

    final_hash = queue.arguments_hash(edited)
    proof = queue.consume_approved_binding(
        pending.request_id,
        owner_key_hash="owner-a",
        session_id="session-a",
        run_id="run-a",
        tool_name="dangerous_tool",
        arguments_hash=final_hash,
        require_manual=True,
    )
    assert proof.journal_record_hash

    mutated_hash = queue.arguments_hash({"path": "mutated.txt"})
    with pytest.raises(PermissionError):
        queue.consume_approved_binding(
            pending.request_id,
            owner_key_hash="owner-a",
            session_id="session-a",
            run_id="run-a",
            tool_name="dangerous_tool",
            arguments_hash=mutated_hash,
            require_manual=True,
        )


def test_edit_nested_mutation_has_no_effect(tmp_path: Path) -> None:
    """Deeply nested dict mutation after decide must not change the binding."""
    queue, _service, _authority = _echo_queue(tmp_path)
    original = {"config": {"path": "original", "opts": {"flag": True}}}
    edited = {"config": {"path": "edited", "opts": {"flag": False}}}

    pending = queue.request_decision(
        "dangerous_tool",
        original,
        context="web",
        session_id="session-a",
        run_id="run-a",
        owner_key_hash="owner-a",
        queue_if_unhandled=True,
    )
    edited_deepcopy = copy.deepcopy(edited)
    queue.decide(
        pending.request_id,
        ApprovalDecisionType.EDIT,
        edited_arguments=edited_deepcopy,
        owner_key_hash="owner-a",
    )

    edited_deepcopy["config"]["path"] = "mutated"
    edited_deepcopy["config"]["opts"]["flag"] = True

    final_hash = queue.arguments_hash(edited)
    proof = queue.consume_approved_binding(
        pending.request_id,
        owner_key_hash="owner-a",
        session_id="session-a",
        run_id="run-a",
        tool_name="dangerous_tool",
        arguments_hash=final_hash,
        require_manual=True,
    )
    assert proof.journal_record_hash


# ---------------------------------------------------------------------------
# Contract C: approval_edited event arguments_hash is the final edited hash
# ---------------------------------------------------------------------------


def test_edit_event_arguments_hash_is_final_edited(tmp_path: Path) -> None:
    """The authoritative approval_edited event must carry the final edited hash."""
    queue, service, _authority = _echo_queue(tmp_path)
    original = {"path": "original.txt"}
    edited = {"path": "edited.txt"}

    pending = queue.request_decision(
        "dangerous_tool",
        original,
        context="web",
        session_id="session-a",
        run_id="run-a",
        owner_key_hash="owner-a",
        queue_if_unhandled=True,
    )
    queue.decide(
        pending.request_id,
        ApprovalDecisionType.EDIT,
        edited_arguments=edited,
        owner_key_hash="owner-a",
    )

    records = _journal_records(service)
    edited_events = [
        r for r in records
        if r.record_type == "approval"
        and r.payload.get("event_type") == "approval_edited"
    ]
    assert len(edited_events) == 1
    event = edited_events[0].payload
    expected_hash = queue.arguments_hash(edited)
    assert event["arguments_hash"] == expected_hash
    assert event["arguments_hash_scheme"] == "stable_payload_hash:v1"
    # Raw args must not be in the event
    assert "edited_arguments" not in event
    assert "original.txt" not in json.dumps(event, default=str)


# ---------------------------------------------------------------------------
# Contract D: durable recovery restores exact EDIT final hash
# ---------------------------------------------------------------------------


def test_durable_recovery_restores_edit_final_hash(tmp_path: Path) -> None:
    """After restart, the resolved record must carry the EDIT final hash."""
    queue, _service, authority = _echo_queue(tmp_path)
    original = {"path": "original.txt"}
    edited = {"path": "edited.txt"}
    pending = queue.request_decision(
        "dangerous_tool",
        original,
        context="web",
        session_id="session-a",
        run_id="run-a",
        owner_key_hash="owner-a",
        queue_if_unhandled=True,
    )
    queue.decide(
        pending.request_id,
        ApprovalDecisionType.EDIT,
        edited_arguments=edited,
        owner_key_hash="owner-a",
    )
    del queue

    # Restart with same ledger + authority
    restarted = ApprovalQueue(
        default_mode=ApprovalMode.MANUAL,
        ledger_path=tmp_path / "approvals.jsonl",
    )
    restarted.set_echo_authority(authority)

    final_hash = restarted.arguments_hash(edited)
    proof = restarted.consume_approved_binding(
        pending.request_id,
        owner_key_hash="owner-a",
        session_id="session-a",
        run_id="run-a",
        tool_name="dangerous_tool",
        arguments_hash=final_hash,
        require_manual=True,
    )
    assert proof.journal_record_hash


def test_signed_legacy_row_without_hash_scheme_cannot_authorize(tmp_path: Path) -> None:
    """A validly MACed pre-scheme row is still non-authoritative."""
    ledger_path = tmp_path / "approvals.jsonl"
    queue = ApprovalQueue(default_mode=ApprovalMode.MANUAL, ledger_path=ledger_path)
    request_id = "approval_legacy_without_scheme"
    arguments_hash = queue.arguments_hash({"path": "legacy.txt"})
    now = time.time()
    queue._append_ledger_mirror(  # noqa: SLF001 - signed legacy fixture
        {
            "event_type": "approval_approved",
            "request_id": request_id,
            "tool_name": "dangerous_tool",
            "context": "web",
            "session_id": "session-a",
            "run_id": "run-a",
            "owner_key_hash": "owner-a",
            "arguments_hash": arguments_hash,
            "timestamp": now,
            "requested_at": now,
            "expires_at": now + 300,
            "approval_mode": "manual",
        }
    )
    restarted = ApprovalQueue(default_mode=ApprovalMode.MANUAL, ledger_path=ledger_path)
    with pytest.raises(PermissionError):
        restarted.consume_approved_binding(
            request_id,
            owner_key_hash="owner-a",
            session_id="session-a",
            run_id="run-a",
            tool_name="dangerous_tool",
            arguments_hash=arguments_hash,
            require_manual=True,
        )


def test_durable_recovery_rejects_multiple_valid_terminal_rows(tmp_path: Path) -> None:
    """A signed mirror with two resolutions is ambiguous, never last-wins."""
    ledger_path = tmp_path / "approvals.jsonl"
    queue = ApprovalQueue(default_mode=ApprovalMode.MANUAL, ledger_path=ledger_path)
    request_id = "approval_ambiguous_terminals"
    now = time.time()
    common = {
        "request_id": request_id,
        "tool_name": "dangerous_tool",
        "context": "web",
        "session_id": "session-a",
        "run_id": "run-a",
        "owner_key_hash": "owner-a",
        "arguments_hash_scheme": "stable_payload_hash:v1",
        "timestamp": now,
        "requested_at": now,
        "expires_at": now + 300,
        "approval_mode": "manual",
    }
    first_hash = queue.arguments_hash({"path": "first.txt"})
    second_hash = queue.arguments_hash({"path": "second.txt"})
    queue._append_ledger_mirror(  # noqa: SLF001 - signed ambiguity fixture
        {**common, "event_type": "approval_approved", "arguments_hash": first_hash}
    )
    queue._append_ledger_mirror(  # noqa: SLF001 - signed ambiguity fixture
        {**common, "event_type": "approval_edited", "arguments_hash": second_hash}
    )

    restarted = ApprovalQueue(default_mode=ApprovalMode.MANUAL, ledger_path=ledger_path)
    with pytest.raises(PermissionError):
        restarted.consume_approved_binding(
            request_id,
            owner_key_hash="owner-a",
            session_id="session-a",
            run_id="run-a",
            tool_name="dangerous_tool",
            arguments_hash=second_hash,
            require_manual=True,
        )


# ---------------------------------------------------------------------------
# Contract 2: callback decision normalized to real request_id
# ---------------------------------------------------------------------------


def test_callback_decision_wrong_request_id_normalized(tmp_path: Path) -> None:
    """Callback returns ApprovalDecision with wrong request_id; system must
    normalize to the real pending request_id."""
    queue, _service, _authority = _echo_queue(tmp_path)
    arguments = {"path": "test.txt"}

    def callback(_req: Any) -> ApprovalDecision:
        return ApprovalDecision(
            ApprovalDecisionType.APPROVE,
            request_id="bogus-id",
            reason="callback",
        )

    queue.set_callback(
        "session-a",
        callback,
        owner_key_hash="owner-a",
        run_id="run-a",
        tool_name="dangerous_tool",
        arguments=arguments,
    )

    decision = queue.request_decision(
        "dangerous_tool",
        arguments,
        context="web",
        session_id="session-a",
        run_id="run-a",
        owner_key_hash="owner-a",
    )
    assert decision.request_id != "bogus-id"
    assert decision.action is ApprovalDecisionType.APPROVE

    final_hash = queue.arguments_hash(arguments)
    proof = queue.consume_approved_binding(
        decision.request_id,
        owner_key_hash="owner-a",
        session_id="session-a",
        run_id="run-a",
        tool_name="dangerous_tool",
        arguments_hash=final_hash,
        require_manual=True,
    )
    assert proof.journal_record_hash


def test_callback_nested_argument_mutation_after_return(tmp_path: Path) -> None:
    """Callback returns EDIT with nested args; caller mutates the returned
    dict afterwards -- the stored binding must not change."""
    queue, _service, _authority = _echo_queue(tmp_path)
    original = {"config": {"path": "original"}}
    edited = {"config": {"path": "edited"}}

    def callback(_req: Any) -> ApprovalDecision:
        return ApprovalDecision(
            ApprovalDecisionType.EDIT,
            edited_arguments=copy.deepcopy(edited),
            reason="edit",
        )

    queue.set_callback(
        "session-a",
        callback,
        owner_key_hash="owner-a",
        run_id="run-a",
        tool_name="dangerous_tool",
        arguments=original,
    )

    decision = queue.request_decision(
        "dangerous_tool",
        original,
        context="web",
        session_id="session-a",
        run_id="run-a",
        owner_key_hash="owner-a",
    )
    assert decision.action is ApprovalDecisionType.EDIT
    assert isinstance(decision.edited_arguments, dict)

    # Mutate the decision's edited_arguments after the callback returned
    decision.edited_arguments["config"]["path"] = "mutated"

    final_hash = queue.arguments_hash(edited)
    proof = queue.consume_approved_binding(
        decision.request_id,
        owner_key_hash="owner-a",
        session_id="session-a",
        run_id="run-a",
        tool_name="dangerous_tool",
        arguments_hash=final_hash,
        require_manual=True,
    )
    assert proof.journal_record_hash


# ---------------------------------------------------------------------------
# Contract E: take_decision does not destructively pop before CAS
# ---------------------------------------------------------------------------


def test_take_decision_does_not_pop_before_cas(tmp_path: Path) -> None:
    """take_decision must not remove the record; consume must still work."""
    queue, _service, _authority = _echo_queue(tmp_path)
    request_id, args_hash = _resolve_manual(queue)

    # Compatibility delivery is once-only, but the claimable resolved row
    # must remain until the authoritative CAS succeeds.
    decision = queue.take_decision(request_id, owner_key_hash="owner-a")
    assert decision is not None
    assert decision.action is ApprovalDecisionType.APPROVE
    assert queue.take_decision(request_id, owner_key_hash="owner-a") is None

    # consume_approved_binding must still succeed (record not popped)
    proof = queue.consume_approved_binding(
        request_id,
        owner_key_hash="owner-a",
        session_id="session-a",
        run_id="run-a",
        tool_name="dangerous_tool",
        arguments_hash=args_hash,
        require_manual=True,
    )
    assert proof.journal_record_hash


def test_delivery_markers_are_removed_on_reject_and_resolved_eviction() -> None:
    """Once-only compatibility markers must remain bounded with resolved rows."""
    queue = ApprovalQueue(default_mode=ApprovalMode.MANUAL)
    rejected = queue.request_decision(
        "dangerous_tool",
        {"index": -1},
        context="web",
        queue_if_unhandled=True,
    )
    queue.decide(rejected.request_id, ApprovalDecisionType.REJECT)
    assert queue.take_decision(rejected.request_id) is not None
    assert rejected.request_id not in queue._delivered_decisions  # noqa: SLF001

    first = queue.request_decision(
        "dangerous_tool",
        {"index": 0},
        context="web",
        mode=ApprovalMode.AUTO_APPROVE,
    )
    assert queue.take_decision(first.request_id) is not None
    assert first.request_id in queue._delivered_decisions  # noqa: SLF001
    for index in range(1, 1025):
        queue.request_decision(
            "dangerous_tool",
            {"index": index},
            context="web",
            mode=ApprovalMode.AUTO_APPROVE,
        )
    assert first.request_id not in queue._resolved_decisions  # noqa: SLF001
    assert first.request_id not in queue._delivered_decisions  # noqa: SLF001


# ---------------------------------------------------------------------------
# Contract G: AUTO_APPROVE persists resolved snapshot and Echo prerequisite
# ---------------------------------------------------------------------------


def test_auto_approve_persists_snapshot_and_echo_prerequisite(tmp_path: Path) -> None:
    """AUTO_APPROVE must persist approval_approved in Echo before CAS."""
    queue, service, authority = _echo_queue(tmp_path)
    arguments = {"path": "auto.txt"}
    decision = queue.request_decision(
        "dangerous_tool",
        arguments,
        context="web",
        mode=ApprovalMode.AUTO_APPROVE,
        session_id="session-a",
        run_id="run-a",
        owner_key_hash="owner-a",
    )
    assert decision.action is ApprovalDecisionType.APPROVE

    # Echo must have an approval_approved event
    records = _journal_records(service)
    approved = [
        r for r in records
        if r.record_type == "approval"
        and r.payload.get("event_type") == "approval_approved"
    ]
    assert len(approved) == 1

    # CAS claim must succeed because the prerequisite exists
    final_hash = queue.arguments_hash(arguments)
    proof = queue.consume_approved_binding(
        decision.request_id,
        owner_key_hash="owner-a",
        session_id="session-a",
        run_id="run-a",
        tool_name="dangerous_tool",
        arguments_hash=final_hash,
        require_manual=False,
    )
    assert proof.journal_record_hash


# ---------------------------------------------------------------------------
# Contract 4: dangerous tool uses Echo CAS, not record_event
# ---------------------------------------------------------------------------


class _SecurityConfig:
    defense_mode = "enforce"
    protected_commands: list[str] = []
    protected_paths: list[str] = []
    allow_workspace_delete = False
    encoding_guard = True
    tool_result_scan = True
    script_provenance = False
    max_loop_iterations = 5
    tool_name_loop_threshold = 4


class _Defense:
    def evaluate(self, _context: Any) -> Any:
        return SimpleNamespace(blocked=False)


class _Audit:
    def __init__(self) -> None:
        self.calls: list[tuple[Any, ...]] = []

    def log(self, *args: Any, **kwargs: Any) -> None:
        self.calls.append(args)


class _Events:
    def __init__(self) -> None:
        self.events: list[Any] = []

    def emit(self, _event: Any) -> None:
        self.events.append(_event)


class _Secrets:
    def detect_and_redact(self, value: str, _scope: str) -> str:
        return value


def _build_tool_executor(
    tmp_path: Path,
    handler: Any,
    *,
    dangerous: bool = True,
    mode: ApprovalMode = ApprovalMode.AUTO_APPROVE,
):
    from js.agent.tool_executor import ToolExecutorMixin
    from js.echo.durable_thread import EchoDurableExecutor
    from js.security.guard import BehaviorGuard
    from js.tools.registry import ToolRegistry, ToolSpec

    settings = SimpleNamespace(
        echo_engine="on",
        product_id="product-a",
        workspace=tmp_path,
        state_dir=tmp_path,
        tools=SimpleNamespace(
            max_concurrent_tools=4,
            tool_output_budget_chars=10_000,
            shell_timeout=30.0,
        ),
        security=_SecurityConfig(),
    )
    guard = BehaviorGuard(settings.security, tmp_path)
    registry = ToolRegistry(settings.tools, guard)
    registry.register(
        ToolSpec(
            name="dangerous_action",
            description="test",
            parameters=[],
            dangerous=dangerous,
        ),
        handler,
    )

    class _Executor(ToolExecutorMixin):
        pass

    executor = _Executor()
    executor.settings = settings
    executor.registry = registry
    executor.defense_strategies = _Defense()
    executor.audit = _Audit()
    executor.event_store = _Events()
    executor.secrets = _Secrets()
    executor.guard = guard
    executor.logger = SimpleNamespace(debug=lambda *_a, **_kw: None)
    executor._role = None
    executor._echo_durable_executor = EchoDurableExecutor(
        max_claim_pending=8,
        max_finish_pending=8,
        claim_workers=2,
        finish_workers=2,
        thread_name_prefix="echo-b2-test",
    )
    executor.echo_safety_service = EchoSafetyService(state_dir=tmp_path)
    executor.approvals = ApprovalQueue(
        default_mode=mode,
        ledger_path=tmp_path / "echo_approvals.jsonl",
    )
    # Only call set_echo_authority (auto-wires sink + seals)
    authority = wire_echo_approval_authority(
        executor.echo_safety_service, product_id="product-a"
    )
    executor.approvals.set_echo_authority(authority)
    return executor


@pytest.mark.asyncio
async def test_dangerous_tool_uses_echo_cas_claim_not_record_event(tmp_path: Path) -> None:
    """approval_execution_claimed must come from Echo CAS, not record_event."""
    from js.echo.ledger.journal import FileEchoLedger
    from js.tools.registry import ToolResult

    call_count = 0

    async def handler() -> ToolResult:
        nonlocal call_count
        call_count += 1
        return ToolResult(success=True, output="ok")

    executor = _build_tool_executor(tmp_path, handler)

    _msg, result = await executor._execute_tool_call(
        {
            "id": "call-a",
            "type": "function",
            "function": {"name": "dangerous_action", "arguments": "{}"},
        },
        session_id="session-a",
        run_id="run-a",
        user_input="run it",
        owner_key_hash="tenant-a",
    )
    assert result.success is True
    assert call_count == 1

    journal_path = executor.echo_safety_service.journal_path_for_scope(
        "tenant-a", product_id="product-a", session_id="session-a"
    )
    records = FileEchoLedger(
        journal_path,
        mac_key=executor.echo_safety_service.journal_key_for_scope(
            "tenant-a", product_id="product-a", session_id="session-a"
        ),
    ).records

    claimed_events = [
        r for r in records
        if r.record_type == "approval"
        and r.payload.get("event_type") == "approval_execution_claimed"
    ]
    assert len(claimed_events) == 1
    assert "binding_hash" in claimed_events[0].payload

    bound_events = [
        r for r in records
        if r.record_type == "approval"
        and r.payload.get("event_type") == "approval_execution_bound"
    ]
    assert len(bound_events) == 1
    bound = bound_events[0].payload
    assert "claim_receipt_hash" in bound
    assert "execution_effect_id" in bound
    assert bound["claim_receipt_hash"] == claimed_events[0].record_hash
    finalized_events = [
        r
        for r in records
        if r.record_type == "approval"
        and r.payload.get("event_type") == "approval_execution_finalized"
    ]
    assert len(finalized_events) == 1
    assert finalized_events[0].payload["claim_receipt_hash"] == claimed_events[0].record_hash


@pytest.mark.asyncio
async def test_dangerous_tool_event_and_audit_payloads_are_hash_only(tmp_path: Path) -> None:
    from js.tools.registry import ToolResult

    async def handler(**_kwargs: Any) -> ToolResult:
        return ToolResult(success=True, output="ok")

    executor = _build_tool_executor(tmp_path, handler)
    raw_argument = "RAW_PRIVATE_ARGUMENT_123"
    _message, result = await executor._execute_tool_call(
        {
            "id": "call-private",
            "type": "function",
            "function": {
                "name": "dangerous_action",
                "arguments": json.dumps({"label": raw_argument}),
            },
        },
        session_id="session-a",
        run_id="run-a",
        user_input="run it",
        owner_key_hash="tenant-a",
    )
    assert result.success is True
    serialized_events = json.dumps(
        [event.to_dict() for event in executor.event_store.events],
        sort_keys=True,
    )
    serialized_audit = json.dumps(executor.audit.calls, default=str, sort_keys=True)
    assert raw_argument not in serialized_events
    assert raw_argument not in serialized_audit
    assert "arguments_hash" in serialized_events
    assert "arguments_hash" in serialized_audit


@pytest.mark.asyncio
async def test_dangerous_tool_caller_mutation_after_cas_cannot_change_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A caller-owned nested dict cannot change the post-CAS tool payload."""
    from js.tools.registry import ToolResult

    seen: list[dict[str, Any]] = []

    async def handler(**kwargs: Any) -> ToolResult:
        seen.append(copy.deepcopy(kwargs))
        return ToolResult(success=True, output="ok")

    executor = _build_tool_executor(tmp_path, handler)
    caller_arguments = {"payload": {"value": "APPROVED_VALUE"}}
    original_consume = executor.approvals.consume_approved_binding

    def mutate_after_real_cas(request_id: str, **kwargs: Any) -> ApprovalClaimProof:
        proof = original_consume(request_id, **kwargs)
        caller_arguments["payload"]["value"] = "MUTATED_AFTER_CAS"
        return proof

    monkeypatch.setattr(
        executor.approvals,
        "consume_approved_binding",
        mutate_after_real_cas,
    )
    _message, result = await executor._execute_tool_call(
        {
            "id": "call-mutation",
            "type": "function",
            "function": {"name": "dangerous_action", "arguments": caller_arguments},
        },
        session_id="session-a",
        run_id="run-a",
        user_input="run it",
        owner_key_hash="tenant-a",
    )

    assert result.success is True
    assert caller_arguments["payload"]["value"] == "MUTATED_AFTER_CAS"
    assert seen == [{"payload": {"value": "APPROVED_VALUE"}}]


@pytest.mark.asyncio
async def test_missing_claim_receipt_fails_before_execution_effect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from js.tools.registry import ToolResult

    handler_calls = 0

    async def handler() -> ToolResult:
        nonlocal handler_calls
        handler_calls += 1
        return ToolResult(success=True, output="unexpected")

    executor = _build_tool_executor(tmp_path, handler)
    original_consume = executor.approvals.consume_approved_binding

    def remove_receipt(request_id: str, **kwargs: Any) -> ApprovalClaimProof:
        proof = original_consume(request_id, **kwargs)
        return dataclasses.replace(proof, journal_record_hash="")

    monkeypatch.setattr(executor.approvals, "consume_approved_binding", remove_receipt)
    execution_begins = 0
    original_begin = executor.echo_safety_service.begin_tool_effect

    def counted_begin(*args: Any, **kwargs: Any):
        nonlocal execution_begins
        if kwargs.get("tool_name") != "echo_approval":
            execution_begins += 1
        return original_begin(*args, **kwargs)

    monkeypatch.setattr(executor.echo_safety_service, "begin_tool_effect", counted_begin)

    _message, result = await executor._execute_tool_call(
        {
            "id": "call-missing-receipt",
            "type": "function",
            "function": {"name": "dangerous_action", "arguments": "{}"},
        },
        session_id="session-a",
        run_id="run-a",
        user_input="run it",
        owner_key_hash="tenant-a",
    )
    assert result.success is False
    assert "approval claim failed" in (result.error or "")
    assert execution_begins == 0
    assert handler_calls == 0
    assert executor.audit.calls == []


@pytest.mark.asyncio
async def test_dangerous_tool_cas_loser_zero_side_effects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CAS loser: no lease issue/verify/consume, no audit/event, no
    begin_tool_effect, no handler call.

    The consume wrapper steals the *dynamic real request* immediately before
    production performs its own claim.  This proves the mainline call loses;
    pre-claiming an unrelated request would be a fake green.
    """
    from js.tools.registry import ToolResult

    handler_calls = 0

    async def handler() -> ToolResult:
        nonlocal handler_calls
        handler_calls += 1
        return ToolResult(success=True, output="ok")

    executor = _build_tool_executor(tmp_path, handler, mode=ApprovalMode.MANUAL)

    def approve_callback(req: Any) -> ApprovalDecision:
        return ApprovalDecision(
            ApprovalDecisionType.APPROVE, request_id=req.id, reason="test"
        )

    executor.approvals.set_callback(
        "session-a",
        approve_callback,
        owner_key_hash="tenant-a",
        run_id="run-a",
        tool_name="dangerous_action",
        arguments={},
    )

    lease_authority = executor._get_echo_tool_lease_authority()
    lease_counts = dict.fromkeys(("issue", "verify", "consume"), 0)
    for method_name in tuple(lease_counts):
        original_method = getattr(type(lease_authority), method_name)

        def counted(
            self: Any,
            *args: Any,
            __name: str = method_name,
            __fn: Any = original_method,
            **kwargs: Any,
        ):
            if self is lease_authority:
                lease_counts[__name] += 1
            return __fn(self, *args, **kwargs)

        monkeypatch.setattr(type(lease_authority), method_name, counted)

    begin_non_approval = 0
    original_begin = executor.echo_safety_service.begin_tool_effect

    def counted_begin(*args: Any, **kwargs: Any):
        nonlocal begin_non_approval
        if kwargs.get("tool_name") != "echo_approval":
            begin_non_approval += 1
        return original_begin(*args, **kwargs)

    monkeypatch.setattr(executor.echo_safety_service, "begin_tool_effect", counted_begin)

    authorize_calls = 0
    original_authorize = executor._authorize_echo_tool_lease

    def counted_authorize(*args: Any, **kwargs: Any):
        nonlocal authorize_calls
        authorize_calls += 1
        return original_authorize(*args, **kwargs)

    monkeypatch.setattr(executor, "_authorize_echo_tool_lease", counted_authorize)

    downstream_baseline: dict[str, Any] | None = None
    original_consume = executor.approvals.consume_approved_binding

    def steal_real_claim(request_id: str, **kwargs: Any) -> ApprovalClaimProof:
        nonlocal downstream_baseline
        record = executor.approvals._resolved_record_for_claim(request_id)  # noqa: SLF001
        assert record is not None
        authority = executor.approvals._echo_authority  # noqa: SLF001
        assert authority is not None
        stolen = authority.claim_once(
            tenant_id=kwargs["owner_key_hash"],
            session_id=kwargs["session_id"],
            run_id=kwargs["run_id"],
            request_id=request_id,
            tool_name=kwargs["tool_name"],
            arguments_hash=kwargs["arguments_hash"],
            approval_mode=record.approval_mode.value,
            expires_at=record.expires_at,
            requested_at=record.requested_at,
        )
        assert stolen.claimed_now is True
        downstream_baseline = {
            "lease": dict(lease_counts),
            "audit": len(executor.audit.calls),
            "events": len(executor.event_store.events),
            "begin": begin_non_approval,
            "authorize": authorize_calls,
        }
        assert lease_counts == {"issue": 1, "verify": 1, "consume": 1}, lease_counts
        assert executor.audit.calls == []
        assert [event.event_type for event in executor.event_store.events] == [
            "approval_requested"
        ]
        assert not any(
            event.event_type in {"approval_granted", "tool_called"}
            for event in executor.event_store.events
        )
        assert authorize_calls == 0
        assert begin_non_approval == 0
        return original_consume(request_id, **kwargs)

    monkeypatch.setattr(executor.approvals, "consume_approved_binding", steal_real_claim)

    # Now execute the tool -- CAS should lose
    _msg, result = await executor._execute_tool_call(
        {
            "id": "call-a",
            "type": "function",
            "function": {"name": "dangerous_action", "arguments": "{}"},
        },
        session_id="session-a",
        run_id="run-a",
        user_input="run it",
        owner_key_hash="tenant-a",
    )

    assert downstream_baseline is not None, "production never attempted the approval CAS"
    assert downstream_baseline == {
        "lease": {"issue": 1, "verify": 1, "consume": 1},
        "audit": 0,
        "events": 1,
        "begin": 0,
        "authorize": 0,
    }
    assert handler_calls == 0
    assert result.success is False
    assert lease_counts == downstream_baseline["lease"]
    assert len(executor.audit.calls) == downstream_baseline["audit"]
    assert len(executor.event_store.events) == downstream_baseline["events"]
    assert begin_non_approval == downstream_baseline["begin"] == 0
    assert authorize_calls == 0


# ---------------------------------------------------------------------------
# RED 11: CAS prerequisite - no prior approval_approved/edited -> claim rejects
# ---------------------------------------------------------------------------


def test_cas_prerequisite_no_prior_approval_rejects(tmp_path: Path) -> None:
    """Direct claim without prior approval_approved/edited in Echo must reject."""
    queue, service, authority = _echo_queue(tmp_path)
    fake_request_id = "approval_fake_0000000000000000"
    fake_args_hash = queue.arguments_hash({"path": "fake.txt"})
    with pytest.raises((PermissionError, ValueError)):
        authority.claim_once(
            tenant_id="owner-a",
            session_id="session-a",
            run_id="run-a",
            request_id=fake_request_id,
            tool_name="dangerous_tool",
            arguments_hash=fake_args_hash,
            approval_mode="manual",
            expires_at=time.time() + 3600,
            requested_at=time.time(),
        )
    # Verify no claim record was written to Echo
    records = _journal_records(service)
    claimed = [
        r for r in records
        if r.record_type == "approval"
        and r.payload.get("event_type") == "approval_execution_claimed"
        and r.payload.get("request_id") == fake_request_id
    ]
    assert len(claimed) == 0


# ---------------------------------------------------------------------------
# RED 12: record_approval_event rejects reserved types and extra core fields
# ---------------------------------------------------------------------------


def test_record_approval_event_rejects_reserved_claimed_type(tmp_path: Path) -> None:
    """record_approval_event must reject approval_execution_claimed (CAS-only)."""
    _queue, service, _authority = _echo_queue(tmp_path)
    with pytest.raises((ValueError, PermissionError)):
        service.record_approval_event(
            tenant_id="owner-a",
            product_id="js-agent",
            session_id="session-a",
            run_id="run-a",
            event_type="approval_execution_claimed",
            request_id="test-id",
            tool_name="dangerous_tool",
            arguments_hash="sha256:" + "0" * 64,
        )


def test_record_approval_event_rejects_extra_core_field_override(tmp_path: Path) -> None:
    """extra must not override core fields like event_type, request_id, etc."""
    _queue, service, _authority = _echo_queue(tmp_path)
    with pytest.raises((ValueError, PermissionError)):
        service.record_approval_event(
            tenant_id="owner-a",
            product_id="js-agent",
            session_id="session-a",
            run_id="run-a",
            event_type="approval_approved",
            request_id="test-id",
            tool_name="dangerous_tool",
            arguments_hash="sha256:" + "0" * 64,
            extra={
                "event_type": "approval_execution_claimed",
                "request_id": "different-id",
            },
        )


def test_record_approval_event_rejects_unknown_extra_and_plain_reason(tmp_path: Path) -> None:
    _queue, service, _authority = _echo_queue(tmp_path)
    common = {
        "tenant_id": "owner-a",
        "product_id": "js-agent",
        "session_id": "session-a",
        "run_id": "run-a",
        "event_type": "approval_approved",
        "request_id": "test-id",
        "tool_name": "dangerous_tool",
        "arguments_hash": "sha256:" + "0" * 64,
    }
    with pytest.raises(ValueError, match="approval event extra fields are invalid"):
        service.record_approval_event(**common, extra={"unknown": "value"})
    with pytest.raises(ValueError, match="approval event extra fields are invalid"):
        service.record_approval_event(**common, extra={"reason": "RAW_PRIVATE_REASON"})


def test_approval_core_arguments_hash_rejects_raw_text_before_persistence(
    tmp_path: Path,
) -> None:
    """Core approval APIs accept only a canonical sha256 reference."""
    _queue, service, authority = _echo_queue(tmp_path)
    raw_arguments = '{"path":"RAW_PRIVATE_ARGUMENT_123"}'
    common = {
        "tenant_id": "owner-a",
        "session_id": "session-a",
        "run_id": "run-a",
        "request_id": "approval_raw_hash",
        "tool_name": "dangerous_tool",
        "arguments_hash": raw_arguments,
    }

    with pytest.raises(ValueError, match="approval arguments hash is invalid"):
        service.record_approval_event(
            product_id="js-agent",
            event_type="approval_approved",
            **common,
        )
    with pytest.raises(ValueError, match="approval arguments hash is invalid"):
        authority.claim_once(
            **common,
            approval_mode="manual",
            expires_at=time.time() + 3600,
            requested_at=time.time(),
        )

    persisted = "".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in tmp_path.rglob("*")
        if path.is_file()
    )
    assert "RAW_PRIVATE_ARGUMENT_123" not in persisted


@pytest.mark.parametrize("invalid_time", [float("nan"), float("inf"), float("-inf")])
def test_approval_core_rejects_non_finite_timestamps_before_persistence(
    tmp_path: Path,
    invalid_time: float,
) -> None:
    queue, service, authority = _echo_queue(tmp_path)
    arguments_hash = queue.arguments_hash({"path": "safe"})
    with pytest.raises(ValueError, match="approval event time is invalid"):
        service.record_approval_event(
            tenant_id="owner-a",
            product_id="js-agent",
            session_id="session-a",
            run_id="run-a",
            event_type="approval_requested",
            request_id="approval_bad_time",
            tool_name="dangerous_tool",
            arguments_hash=arguments_hash,
            extra={
                "requested_at": invalid_time,
                "expires_at": time.time() + 3600,
                "approval_mode": "manual",
                "arguments_hash_scheme": "stable_payload_hash:v1",
            },
        )
    with pytest.raises(ValueError, match="approval claim time is invalid"):
        authority.claim_once(
            tenant_id="owner-a",
            session_id="session-a",
            run_id="run-a",
            request_id="approval_bad_time",
            tool_name="dangerous_tool",
            arguments_hash=arguments_hash,
            approval_mode="manual",
            expires_at=float("inf"),
            requested_at=invalid_time,
        )

    persisted = "".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in tmp_path.rglob("*")
        if path.is_file()
    )
    assert "NaN" not in persisted
    assert "Infinity" not in persisted


def test_latest_terminal_event_prevents_claim(tmp_path: Path) -> None:
    queue, service, authority = _echo_queue(tmp_path)
    request_id, arguments_hash = _resolve_manual(queue)
    record = queue._resolved_record_for_claim(request_id)  # noqa: SLF001
    assert record is not None
    service.record_approval_event(
        tenant_id="owner-a",
        product_id="js-agent",
        session_id="session-a",
        run_id="run-a",
        event_type="approval_cancelled",
        request_id=request_id,
        tool_name="dangerous_tool",
        arguments_hash=arguments_hash,
        extra={
            "arguments_hash_scheme": "stable_payload_hash:v1",
            "reason_code": "session_revoked",
        },
    )
    with pytest.raises(PermissionError):
        authority.claim_once(
            tenant_id="owner-a",
            session_id="session-a",
            run_id="run-a",
            request_id=request_id,
            tool_name="dangerous_tool",
            arguments_hash=arguments_hash,
            approval_mode="manual",
            expires_at=record.expires_at,
            requested_at=record.requested_at,
        )


def test_echo_claim_rejects_multiple_resolution_terminals(tmp_path: Path) -> None:
    """Echo semantic CAS independently rejects even identical duplicate approvals."""
    queue, service, authority = _echo_queue(tmp_path)
    request_id, arguments_hash = _resolve_manual(queue)
    record = queue._resolved_record_for_claim(request_id)  # noqa: SLF001
    assert record is not None
    service.record_approval_event(
        tenant_id="owner-a",
        product_id="js-agent",
        session_id="session-a",
        run_id="run-a",
        event_type="approval_approved",
        request_id=request_id,
        tool_name="dangerous_tool",
        arguments_hash=arguments_hash,
        extra={
            "context": "web",
            "requested_at": record.requested_at,
            "expires_at": record.expires_at,
            "approval_mode": "manual",
            "arguments_hash_scheme": "stable_payload_hash:v1",
        },
    )
    with pytest.raises(PermissionError):
        authority.claim_once(
            tenant_id="owner-a",
            session_id="session-a",
            run_id="run-a",
            request_id=request_id,
            tool_name="dangerous_tool",
            arguments_hash=arguments_hash,
            approval_mode="manual",
            expires_at=record.expires_at,
            requested_at=record.requested_at,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("run_id", "run-other"),
        ("tool_name", "other_tool"),
        ("arguments_hash", "sha256:" + "f" * 64),
        ("approval_mode", "auto_approve"),
        ("expires_at", 1.0),
        ("requested_at", 1.0),
    ],
)
def test_cas_prerequisite_requires_exact_precursor_binding(
    tmp_path: Path,
    field: str,
    value: Any,
) -> None:
    queue, _service, authority = _echo_queue(tmp_path)
    request_id, arguments_hash = _resolve_manual(queue)
    record = queue._resolved_record_for_claim(request_id)  # noqa: SLF001
    assert record is not None
    claim = {
        "tenant_id": "owner-a",
        "session_id": "session-a",
        "run_id": "run-a",
        "request_id": request_id,
        "tool_name": "dangerous_tool",
        "arguments_hash": arguments_hash,
        "approval_mode": "manual",
        "expires_at": record.expires_at,
        "requested_at": record.requested_at,
    }
    claim[field] = value
    with pytest.raises(PermissionError):
        authority.claim_once(**claim)


# ---------------------------------------------------------------------------
# Contract 5: CAS claimed row is unique
# ---------------------------------------------------------------------------


def test_cas_claimed_row_unique(tmp_path: Path) -> None:
    """Echo journal has exactly one approval_execution_claimed per request_id."""
    queue, service, _authority = _echo_queue(tmp_path)
    request_id, args_hash = _resolve_manual(queue)
    kwargs = {
        "owner_key_hash": "owner-a",
        "session_id": "session-a",
        "run_id": "run-a",
        "tool_name": "dangerous_tool",
        "arguments_hash": args_hash,
        "require_manual": True,
    }
    queue.consume_approved_binding(request_id, **kwargs)

    records = _journal_records(service)
    claimed = [
        r for r in records
        if r.record_type == "approval"
        and r.payload.get("event_type") == "approval_execution_claimed"
        and r.payload.get("request_id") == request_id
    ]
    assert len(claimed) == 1


def test_claim_and_lookup_remain_consumed_after_journal_compaction(
    tmp_path: Path,
) -> None:
    """Verified archive history remains an exactly-once claim oracle."""
    queue, service, authority = _echo_queue(tmp_path)
    request_id, arguments_hash = _resolve_manual(queue)
    record = queue._resolved_record_for_claim(request_id)  # noqa: SLF001
    assert record is not None
    claim = {
        "tenant_id": "owner-a",
        "session_id": "session-a",
        "run_id": "run-a",
        "request_id": request_id,
        "tool_name": "dangerous_tool",
        "arguments_hash": arguments_hash,
        "approval_mode": "manual",
        "expires_at": record.expires_at,
        "requested_at": record.requested_at,
    }

    first = authority.claim_once(**claim)
    assert first.claimed_now is True
    service.record_approval_event(
        tenant_id="owner-a",
        product_id="js-agent",
        session_id="session-a",
        run_id="run-a",
        event_type="approval_requested",
        request_id="approval_archive_filler",
        tool_name="dangerous_tool",
        arguments_hash=queue.arguments_hash({"filler": True}),
        extra={
            "context": "web",
            "requested_at": time.time(),
            "expires_at": time.time() + 3600,
            "approval_mode": "manual",
            "arguments_hash_scheme": "stable_payload_hash:v1",
        },
    )
    journal_path = service.journal_path_for_scope(
        "owner-a", product_id="js-agent", session_id="session-a"
    )
    assert service.compact_journals(max_records=1)[str(journal_path)] is True
    archived = authority.lookup_claim(
        tenant_id="owner-a",
        session_id="session-a",
        request_id=request_id,
    )
    assert archived is not None
    assert archived.claimed_now is False

    # Reintroducing an otherwise valid prerequisite must never resurrect an
    # archived claim.  The prior claim remains the durable deny oracle.
    service.record_approval_event(
        tenant_id="owner-a",
        product_id="js-agent",
        session_id="session-a",
        run_id="run-a",
        event_type="approval_approved",
        request_id=request_id,
        tool_name="dangerous_tool",
        arguments_hash=arguments_hash,
        extra={
            "context": "web",
            "requested_at": record.requested_at,
            "expires_at": record.expires_at,
            "approval_mode": "manual",
            "arguments_hash_scheme": "stable_payload_hash:v1",
        },
    )
    second = authority.claim_once(**claim)
    assert second.claimed_now is False

    from js.echo.ledger.journal import FileEchoLedger

    logical = FileEchoLedger(
        journal_path,
        mac_key=service.journal_key_for_scope(
            "owner-a", product_id="js-agent", session_id="session-a"
        ),
    ).verified_logical_records()
    claimed = [
        item
        for item in logical
        if item.record_type == "approval"
        and isinstance(item.payload, dict)
        and item.payload.get("event_type") == "approval_execution_claimed"
        and item.payload.get("request_id") == request_id
    ]
    assert len(claimed) == 1


# ---------------------------------------------------------------------------
# Contract 4: claim after failure -> must re-approve
# ---------------------------------------------------------------------------


def test_claim_consumed_even_if_later_fails(tmp_path: Path) -> None:
    """Claim is consumed; subsequent failure requires re-approval."""
    queue, _service, _authority = _echo_queue(tmp_path)
    request_id, args_hash = _resolve_manual(queue)
    kwargs = {
        "owner_key_hash": "owner-a",
        "session_id": "session-a",
        "run_id": "run-a",
        "tool_name": "dangerous_tool",
        "arguments_hash": args_hash,
        "require_manual": True,
    }
    queue.consume_approved_binding(request_id, **kwargs)
    with pytest.raises(PermissionError):
        queue.consume_approved_binding(request_id, **kwargs)


# ---------------------------------------------------------------------------
# Contract 7: ledger only contains closed-set identity and hashes
# ---------------------------------------------------------------------------


def test_ledger_contains_no_raw_args(tmp_path: Path) -> None:
    """Ledger/log contains only closed-set identity and hashes, not raw args."""
    queue, service, _authority = _echo_queue(tmp_path)
    secret_args = {"path": "/secret/path", "api_key": "sk-leak-123456789012345"}
    request_id, args_hash = _resolve_manual(
        queue,
        arguments=secret_args,
        reason="RAW_PRIVATE_REASON_123",
    )
    kwargs = {
        "owner_key_hash": "owner-a",
        "session_id": "session-a",
        "run_id": "run-a",
        "tool_name": "dangerous_tool",
        "arguments_hash": args_hash,
        "require_manual": True,
    }
    queue.consume_approved_binding(request_id, **kwargs)

    records = _journal_records(service)
    raw_journal = json.dumps(
        [dict(r.payload) for r in records if r.record_type == "approval"],
        default=str,
    )
    assert "/secret/path" not in raw_journal
    assert "sk-leak" not in raw_journal
    assert "api_key" not in raw_journal
    assert "RAW_PRIVATE_REASON_123" not in raw_journal


# ---------------------------------------------------------------------------
# Contract 6: Connector write anchors receipt hash via EffectInterpreter
# ---------------------------------------------------------------------------


def _connector_runtime_bundle(tmp_path: Path):
    """Build a real EffectInterpreter with connector manager + dispatch issuer."""
    from js.echo.capability import LeaseAuthority
    from js.echo.ledger.service import EchoSafetyService
    from js.echo.turn_runtime import EchoRuntime
    from js.security.approvals import wire_echo_approval_authority

    workspace = tmp_path / "workspace"
    state_dir = tmp_path / "state"
    workspace.mkdir(exist_ok=True)
    state_dir.mkdir(exist_ok=True)
    settings = SimpleNamespace(
        product_id="js-agent",
        workspace=workspace,
        state_dir=state_dir,
        security=SimpleNamespace(network_enabled=False, network_allowlist=()),
        echo_budget=SimpleNamespace(max_elapsed_ms=900_000),
        _appshell_managed=False,
    )
    authority = LeaseAuthority(
        mac_key=b"r4-boundary-lease-key-32-bytes!",
        now_fn=lambda: 1_000,
        ledger_path=state_dir / "leases.jsonl",
    )
    echo_service = EchoSafetyService(state_dir=state_dir / "echo")
    approval_queue = ApprovalQueue(
        default_mode=ApprovalMode.MANUAL,
        ledger_path=state_dir / "approvals.jsonl",
    )
    approval_authority = wire_echo_approval_authority(echo_service, product_id="js-agent")
    approval_queue.set_echo_authority(approval_authority)

    agent = SimpleNamespace(
        settings=settings,
        approvals=approval_queue,
        _current_allowed_tools=set(),
        _tool_lease_authority=authority,
        _echo_safety_service=echo_service,
    )
    agent._get_echo_tool_lease_authority = lambda: authority
    runtime = EchoRuntime(agent)
    agent.echo_runtime = runtime
    context = runtime.build_context(
        channel="test",
        owner_key_hash="owner-a",
        session_id="session-a",
        run_id="run-a",
    )
    return agent, runtime, context, authority, echo_service


def _connector_write_request(
    agent: Any,
    context: Any,
    authority: Any,
    *,
    params: dict[str, Any],
):
    import dataclasses

    from js.connectors.contracts import (
        ConnectionRefV2,
        ConnectorExecutionRequestV1,
        ConnectorManifestV1,
        DirectoryGrantV1,
        canonical_params_digest,
    )
    from js.echo.mode_contract import AppMode, ConnectionRefV1

    manifest = ConnectorManifestV1(
        connector_type="local_publish",
        capabilities=("read", "write"),
        read_scopes=("artifacts",),
        write_scopes=("publish",),
        approval_policy="explicit",
    )
    connection = ConnectionRefV2(
        ref=ConnectionRefV1(
            mode=AppMode.PERSONAL,
            owner="owner-a",
            workspace=None,
            connector_type="local_publish",
            connection_id="publish-a",
            authorized_by="owner-a",
        ),
        manifest_digest=manifest.canonical_hash(),
        vault_ref=None,
    )
    grant = DirectoryGrantV1(
        mode=AppMode.PERSONAL,
        workspace=None,
        root=str(context.workspace),
    )
    placeholder = authority.issue(
        product_id="js-agent",
        owner_key_hash="owner-a",
        session_id="session-a",
        run_id="run-a",
        tool_name="connector.local_publish.write",
        args_schema="sha256:" + "0" * 64,
        resource_scope="connection:publish-a:publish",
        fs_roots=(grant.root,),
        network_policy="deny",
        network_hosts=(),
        max_bytes=10 * 1024 * 1024,
        max_duration_ms=30_000,
        max_invocations=1,
        ttl_ms=60_000,
    )
    request = ConnectorExecutionRequestV1(
        task_ref=context.task_ref,
        connection=connection,
        manifest=manifest,
        operation="write",
        scope="publish",
        params_digest=canonical_params_digest(params),
        directory_grant=grant,
        approval_id="approval-placeholder",
        lease=placeholder,
    )
    approval_arguments = {
        "authority_binding_hash": request.authority_binding_hash(),
        "scope": "publish",
    }
    pending = agent.approvals.request_decision(
        "connector.local_publish.write",
        approval_arguments,
        context="web",
        session_id="session-a",
        run_id="run-a",
        owner_key_hash="owner-a",
        queue_if_unhandled=True,
    )
    agent.approvals.decide(
        pending.request_id,
        ApprovalDecisionType.APPROVE,
        owner_key_hash="owner-a",
    )
    lease = authority.issue(
        product_id="js-agent",
        owner_key_hash="owner-a",
        session_id="session-a",
        run_id="run-a",
        tool_name="connector.local_publish.write",
        args_schema=request.authority_binding_hash(),
        resource_scope="connection:publish-a:publish",
        fs_roots=(grant.root,),
        network_policy="deny",
        network_hosts=(),
        max_bytes=10 * 1024 * 1024,
        max_duration_ms=30_000,
        max_invocations=1,
        ttl_ms=60_000,
    )
    return dataclasses.replace(
        request,
        approval_id=pending.request_id,
        lease=lease,
    )


@pytest.mark.asyncio
async def test_connector_write_anchors_receipt_hash_in_dispatch(tmp_path: Path) -> None:
    """Connector write must put fresh proof.journal_record_hash into dispatch
    capability's approval_claim_receipt_hash."""
    agent, runtime, context, authority, echo_service = _connector_runtime_bundle(tmp_path)
    params = {
        "artifact_ref": {"uri": "echo://artifact/opaque-a"},
        "filename": "artifact.txt",
    }
    request = _connector_write_request(agent, context, authority, params=params)

    captured_issue: list[dict[str, Any]] = []
    real_issuer = runtime.effects._dispatch_issuer
    assert real_issuer is not None

    class CaptureIssuer:
        def issue(self, **kwargs: Any):
            captured_issue.append(dict(kwargs))
            return real_issuer.issue(**kwargs)

    runtime.effects._dispatch_issuer = CaptureIssuer()

    await runtime.execute_connector_effect(request, params=params, context=context)
    assert len(captured_issue) == 1

    # The dispatch capability must have been consumed, but we can verify
    # by checking that the approval was consumed (CAS succeeded)
    approval_id = request.approval_id
    assert approval_id is not None

    # Verify approval_execution_claimed exists in Echo journal with binding_hash
    from js.echo.ledger.journal import FileEchoLedger

    journal_path = echo_service.journal_path_for_scope(
        "owner-a", product_id="js-agent", session_id="session-a"
    )
    records = FileEchoLedger(
        journal_path,
        mac_key=echo_service.journal_key_for_scope(
            "owner-a", product_id="js-agent", session_id="session-a"
        ),
    ).records
    claimed = [
        r for r in records
        if r.record_type == "approval"
        and r.payload.get("event_type") == "approval_execution_claimed"
        and r.payload.get("request_id") == approval_id
    ]
    assert len(claimed) == 1
    assert "binding_hash" in claimed[0].payload
    assert captured_issue[0]["approval_claim_receipt_hash"] == claimed[0].record_hash


@pytest.mark.asyncio
async def test_connector_nested_params_mutation_after_cas_cannot_change_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Dispatch uses a bounded deep snapshot, never caller-owned nested params."""
    agent, runtime, context, authority, _echo_service = _connector_runtime_bundle(tmp_path)
    params = {
        "artifact_ref": {"uri": "echo://artifact/APPROVED_VALUE"},
        "filename": "artifact.txt",
    }
    request = _connector_write_request(agent, context, authority, params=params)
    original_consume = agent.approvals.consume_approved_binding

    def mutate_after_real_cas(request_id: str, **kwargs: Any) -> ApprovalClaimProof:
        proof = original_consume(request_id, **kwargs)
        params["artifact_ref"]["uri"] = "echo://artifact/MUTATED_AFTER_CAS"
        return proof

    monkeypatch.setattr(
        agent.approvals,
        "consume_approved_binding",
        mutate_after_real_cas,
    )
    manager = runtime.effects._connector_manager
    assert manager is not None
    original_dispatch = manager._dispatch_authorized
    dispatched: list[dict[str, Any]] = []

    async def capture_dispatch(*args: Any, **kwargs: Any):
        dispatched.append(copy.deepcopy(kwargs["params"]))
        return await original_dispatch(*args, **kwargs)

    monkeypatch.setattr(manager, "_dispatch_authorized", capture_dispatch)
    await runtime.execute_connector_effect(request, params=params, context=context)

    assert params["artifact_ref"]["uri"] == "echo://artifact/MUTATED_AFTER_CAS"
    assert dispatched == [
        {
            "artifact_ref": {"uri": "echo://artifact/APPROVED_VALUE"},
            "filename": "artifact.txt",
        }
    ]


@pytest.mark.asyncio
async def test_connector_loser_zero_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CAS loser: no anchor, no lease consume, no dispatch."""
    agent, runtime, context, authority, echo_service = _connector_runtime_bundle(tmp_path)
    params = {
        "artifact_ref": {"uri": "echo://artifact/opaque-a"},
        "filename": "artifact.txt",
    }
    request = _connector_write_request(agent, context, authority, params=params)
    approval_id = request.approval_id
    assert approval_id is not None

    calls = {"anchor_lookup": 0, "anchor_pending": 0, "anchor_final": 0,
             "lease_consume": 0, "issuer": 0, "dispatch": 0}

    for method_name, counter_name in (
        ("lookup_lease_consume_anchor", "anchor_lookup"),
        ("record_lease_consume_pending", "anchor_pending"),
        ("record_lease_consume_finalized", "anchor_final"),
    ):
        original_method = getattr(echo_service, method_name)

        def counted_echo(
            *args: Any,
            __name: str = counter_name,
            __fn: Any = original_method,
            **kwargs: Any,
        ):
            calls[__name] += 1
            return __fn(*args, **kwargs)

        monkeypatch.setattr(echo_service, method_name, counted_echo)

    original_consume_bound = type(authority).consume_bound

    def counted_consume_bound(self: Any, *args: Any, **kwargs: Any):
        if self is authority:
            calls["lease_consume"] += 1
        return original_consume_bound(self, *args, **kwargs)

    monkeypatch.setattr(type(authority), "consume_bound", counted_consume_bound)

    real_issuer = runtime.effects._dispatch_issuer
    assert real_issuer is not None

    class CountingIssuer:
        def issue(self, **kwargs: Any):
            calls["issuer"] += 1
            return real_issuer.issue(**kwargs)

    runtime.effects._dispatch_issuer = CountingIssuer()
    manager = runtime.effects._connector_manager
    assert manager is not None
    original_dispatch = manager._dispatch_authorized

    async def counted_dispatch(*args: Any, **kwargs: Any):
        calls["dispatch"] += 1
        return await original_dispatch(*args, **kwargs)

    monkeypatch.setattr(manager, "_dispatch_authorized", counted_dispatch)

    original_consume = agent.approvals.consume_approved_binding
    baseline: dict[str, int] | None = None

    def steal_real_claim(request_id: str, **kwargs: Any) -> ApprovalClaimProof:
        nonlocal baseline
        assert request_id == approval_id
        record = agent.approvals._resolved_record_for_claim(request_id)  # noqa: SLF001
        assert record is not None
        auth = agent.approvals._echo_authority  # noqa: SLF001
        assert auth is not None
        receipt = auth.claim_once(
            tenant_id=kwargs["owner_key_hash"],
            session_id=kwargs["session_id"],
            run_id=kwargs["run_id"],
            request_id=request_id,
            tool_name=kwargs["tool_name"],
            arguments_hash=kwargs["arguments_hash"],
            approval_mode=record.approval_mode.value,
            expires_at=record.expires_at,
            requested_at=record.requested_at,
        )
        assert receipt.claimed_now is True
        baseline = dict(calls)
        return original_consume(request_id, **kwargs)

    monkeypatch.setattr(agent.approvals, "consume_approved_binding", steal_real_claim)

    with pytest.raises(PermissionError):
        await runtime.execute_connector_effect(request, params=params, context=context)
    assert baseline is not None, "production never attempted the approval CAS"
    assert calls == baseline == {
        "anchor_lookup": 0,
        "anchor_pending": 0,
        "anchor_final": 0,
        "lease_consume": 0,
        "issuer": 0,
        "dispatch": 0,
    }


@pytest.mark.asyncio
async def test_connector_missing_claim_receipt_fails_before_anchor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A malformed fresh proof cannot cross into anchor/lease/issuer/dispatch."""
    agent, runtime, context, authority, echo_service = _connector_runtime_bundle(tmp_path)
    params = {
        "artifact_ref": {"uri": "echo://artifact/opaque-a"},
        "filename": "artifact.txt",
    }
    request = _connector_write_request(agent, context, authority, params=params)
    original_consume = agent.approvals.consume_approved_binding

    def remove_receipt(request_id: str, **kwargs: Any) -> ApprovalClaimProof:
        proof = original_consume(request_id, **kwargs)
        return dataclasses.replace(proof, journal_record_hash="")

    monkeypatch.setattr(agent.approvals, "consume_approved_binding", remove_receipt)
    calls = {"anchor": 0, "lease_consume": 0, "issuer": 0, "dispatch": 0}

    original_lookup = echo_service.lookup_lease_consume_anchor

    def counted_lookup(*args: Any, **kwargs: Any):
        calls["anchor"] += 1
        return original_lookup(*args, **kwargs)

    monkeypatch.setattr(echo_service, "lookup_lease_consume_anchor", counted_lookup)
    original_consume_bound = type(authority).consume_bound

    def counted_consume_bound(self: Any, *args: Any, **kwargs: Any):
        if self is authority:
            calls["lease_consume"] += 1
        return original_consume_bound(self, *args, **kwargs)

    monkeypatch.setattr(type(authority), "consume_bound", counted_consume_bound)
    real_issuer = runtime.effects._dispatch_issuer
    assert real_issuer is not None

    class CountingIssuer:
        def issue(self, **kwargs: Any):
            calls["issuer"] += 1
            return real_issuer.issue(**kwargs)

    runtime.effects._dispatch_issuer = CountingIssuer()
    manager = runtime.effects._connector_manager
    assert manager is not None
    original_dispatch = manager._dispatch_authorized

    async def counted_dispatch(*args: Any, **kwargs: Any):
        calls["dispatch"] += 1
        return await original_dispatch(*args, **kwargs)

    monkeypatch.setattr(manager, "_dispatch_authorized", counted_dispatch)
    with pytest.raises(PermissionError, match="approval claim proof is invalid"):
        await runtime.execute_connector_effect(request, params=params, context=context)
    assert calls == {"anchor": 0, "lease_consume": 0, "issuer": 0, "dispatch": 0}


@pytest.mark.asyncio
async def test_connector_read_no_proof_required(tmp_path: Path) -> None:
    """Read path does not require an approval proof."""
    import dataclasses

    from js.connectors.contracts import (
        ConnectionRefV2,
        ConnectorExecutionRequestV1,
        ConnectorManifestV1,
        DirectoryGrantV1,
        canonical_params_digest,
    )
    from js.echo.mode_contract import AppMode, ConnectionRefV1

    agent, runtime, context, authority, _echo = _connector_runtime_bundle(tmp_path)
    source_file = tmp_path / "workspace" / "source.txt"
    source_file.write_text("test content", encoding="utf-8")

    manifest = ConnectorManifestV1(
        connector_type="local_import",
        capabilities=("read",),
        read_scopes=("files",),
        approval_policy="read_only",
    )
    connection = ConnectionRefV2(
        ref=ConnectionRefV1(
            mode=AppMode.PERSONAL,
            owner="owner-a",
            workspace=None,
            connector_type="local_import",
            connection_id="import-a",
            authorized_by="owner-a",
        ),
        manifest_digest=manifest.canonical_hash(),
        vault_ref=None,
    )
    grant = DirectoryGrantV1(
        mode=AppMode.PERSONAL,
        workspace=None,
        root=str(context.workspace),
    )
    params = {"path": "source.txt"}
    placeholder = authority.issue(
        product_id="js-agent",
        owner_key_hash="owner-a",
        session_id="session-a",
        run_id="run-a",
        tool_name="connector.local_import.read",
        args_schema="sha256:" + "0" * 64,
        resource_scope="connection:import-a:files",
        fs_roots=(grant.root,),
        network_policy="deny",
        network_hosts=(),
        max_bytes=10 * 1024 * 1024,
        max_duration_ms=30_000,
        max_invocations=1,
        ttl_ms=60_000,
    )
    request = ConnectorExecutionRequestV1(
        task_ref=context.task_ref,
        connection=connection,
        manifest=manifest,
        operation="read",
        scope="files",
        params_digest=canonical_params_digest(params),
        directory_grant=grant,
        approval_id=None,
        lease=placeholder,
    )
    lease = authority.issue(
        product_id="js-agent",
        owner_key_hash="owner-a",
        session_id="session-a",
        run_id="run-a",
        tool_name="connector.local_import.read",
        args_schema=request.authority_binding_hash(),
        resource_scope="connection:import-a:files",
        fs_roots=(grant.root,),
        network_policy="deny",
        network_hosts=(),
        max_bytes=10 * 1024 * 1024,
        max_duration_ms=30_000,
        max_invocations=1,
        ttl_ms=60_000,
    )
    request = dataclasses.replace(request, lease=lease)

    captured_issue: list[dict[str, Any]] = []
    real_issuer = runtime.effects._dispatch_issuer
    assert real_issuer is not None

    class CaptureIssuer:
        def issue(self, **kwargs: Any):
            captured_issue.append(dict(kwargs))
            return real_issuer.issue(**kwargs)

    runtime.effects._dispatch_issuer = CaptureIssuer()
    outcome = await runtime.execute_connector_effect(request, params=params, context=context)
    assert outcome.success is True
    assert len(captured_issue) == 1
    assert captured_issue[0]["approval_claim_receipt_hash"] is None


# ---------------------------------------------------------------------------
# Contract 1: JSAgent installs sealed Echo authority (only set_echo_authority)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_jsagent_installs_sealed_echo_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """JSAgent must install sealed Echo authority via set_echo_authority only."""
    from js.agent import JSAgent
    from js.config import JSSettings, SecurityConfig

    calls: list[str] = []
    original_authority = ApprovalQueue.set_echo_authority
    original_sink = ApprovalQueue.set_echo_event_sink

    def counted_authority(self: ApprovalQueue, authority: ApprovalEchoAuthority) -> None:
        calls.append("authority")
        original_authority(self, authority)

    def counted_sink(self: ApprovalQueue, sink: Any) -> None:
        calls.append("sink")
        original_sink(self, sink)

    monkeypatch.setattr(ApprovalQueue, "set_echo_authority", counted_authority)
    monkeypatch.setattr(ApprovalQueue, "set_echo_event_sink", counted_sink)

    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        max_turns=1,
        echo_engine="on",
        security=SecurityConfig(api_key_required=False),
    )
    agent = JSAgent(settings)
    try:
        assert calls == ["authority"]
        assert agent.approvals._echo_authority is not None
        assert agent.approvals._echo_authority_sealed is True
        with pytest.raises(RuntimeError, match="sealed"):
            agent.approvals.set_echo_event_sink(lambda _e: None)
    finally:
        await agent.close()
