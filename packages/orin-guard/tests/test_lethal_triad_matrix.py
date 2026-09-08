"""Matrix-driven lethal trifecta conjunction contracts."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from orin_guard.kernel.conjunction import ConjunctionDenied, check_conjunction, require_conjunction

TESTDATA = Path(__file__).resolve().parents[1] / "testdata" / "lethal_triad_matrix.yaml"


def _cases() -> list[dict[str, object]]:
    payload = yaml.safe_load(TESTDATA.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    cases = payload["cases"]
    assert isinstance(cases, list)
    return cases


@pytest.mark.parametrize("case", _cases(), ids=lambda c: str(c["id"]))
def test_lethal_triad_matrix(case: dict[str, object]) -> None:
    grants = frozenset(str(g) for g in case["grants"])  # type: ignore[arg-type]
    expect = str(case["expect"])
    verdict = check_conjunction(grants)
    if expect == "deny":
        assert verdict.allowed is False
        with pytest.raises(ConjunctionDenied, match="unsatisfiable"):
            require_conjunction(grants)
    else:
        assert expect == "allow"
        assert verdict.allowed is True
        require_conjunction(grants)
