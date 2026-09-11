"""Eval-gate wiring on the Host evolution desk."""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest
from echo_core.evolve.eval_gate import EvalGateDenied, eval_gate

from js.evolution.cycle import STATUS_REGRESSED, EvolutionCycle


def test_eval_gate_rejects_none() -> None:
    with pytest.raises(EvalGateDenied):
        eval_gate(None, baseline=1.0)
    assert "skip" not in inspect.signature(eval_gate).parameters
    assert "disable" not in inspect.signature(eval_gate).parameters


def test_host_cycle_cannot_skip_eval(tmp_path: Path) -> None:
    cycle = EvolutionCycle(tmp_path)
    proposal = cycle.generate("owner-a", max_proposals=1)[0]
    updated = cycle.approve_and_apply(proposal.proposal_id, "owner-a", decided_by="admin")
    assert updated.status == STATUS_REGRESSED
