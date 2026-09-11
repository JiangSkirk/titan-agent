"""Eval gate has no off switch. A missing benchmark is a fail, not a skip."""

from __future__ import annotations

from collections.abc import Callable

EvalFn = Callable[[], float]


class EvalGateDenied(PermissionError):
    """Widen candidate failed the mandatory eval gate."""

    def __init__(self, message: str, score: float | None = None) -> None:
        super().__init__(message)
        self.score = score


def eval_gate(
    benchmark: EvalFn | None,
    *,
    baseline: float,
) -> float:
    """Run the eval. There is no disable flag."""

    if benchmark is None:
        raise EvalGateDenied("eval gate cannot be skipped")
    score = float(benchmark())
    if score < baseline:
        raise EvalGateDenied("eval gate: score below baseline", score)
    return score
