"""Shared membrane contract anchors (Echo + Orin).

Sibling Orin work may extend this module; keep Echo-shared names stable.
"""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest

from js.orind.membrane import (
    CommitMembrane,
    CommitState,
    InvalidTransition,
    OperationSpec,
)

NOW_MS = 2_000_000_000_000
OWNER_KEY_HASH = "sha256:" + "1" * 64
EFFECT_HASH = "sha256:" + "2" * 64


def _spec() -> OperationSpec:
    token = uuid4().hex
    return OperationSpec(
        operation_id=f"operation:{token}",
        draft_id=f"draft:{token}",
        task_id=f"task:{token}",
        owner_key_hash=OWNER_KEY_HASH,
        session_id=f"session:{token}",
        effect_type="file.commit",
        executor_id="cell.file",
        side_effect_class="R2",
        canonical_effect_hash=EFFECT_HASH,
        witness_id=f"state:{token}",
        intent_id=f"intent:{token}",
        profile="work",
        destinations=(),
        bytes_out=17,
        idempotency_key=f"idem:{token}",
    )


def test_membrane_rejects_commit_without_receipt(tmp_path: Path) -> None:
    """COMMITTED → RECEIPTED requires a receipt_id; empty receipt is denied."""

    membrane = CommitMembrane(tmp_path / "membrane.db", now_fn=lambda: NOW_MS)
    try:
        spec = _spec()
        membrane.propose(spec)
        membrane.transition(spec.operation_id, CommitState.PREFLIGHTED)
        membrane.prepare(
            spec.operation_id,
            max_invocations=20,
            max_bytes_out=1 << 20,
            export_pass_id=None,
            require_personal_pass=False,
            now_ms=NOW_MS,
        )
        membrane.begin_commit(spec.operation_id)
        membrane.transition(spec.operation_id, CommitState.COMMITTED)
        with pytest.raises((InvalidTransition, ValueError)):
            membrane.transition(spec.operation_id, CommitState.RECEIPTED, receipt_id="")
    finally:
        membrane.close()
