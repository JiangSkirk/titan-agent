"""Host GuardianSPI adapter tests."""

from __future__ import annotations

import pytest
from echo_core.spi.guardian import GuardianDenied
from orin_guard.kernel.gate import GateKernel

from js.echo.guardian_adapter import OrinGuardian


def test_orin_guardian_stamps_and_consumes_once() -> None:
    guardian = OrinGuardian(GateKernel(b"k" * 32))
    ticket = guardian.stamp(
        owner="o",
        session="s",
        run="r",
        effect_class="tool",
        grants=frozenset({"private.read"}),
        budget=1,
    )
    guardian.consume(ticket, owner="o", run="r")
    with pytest.raises(GuardianDenied):
        guardian.consume(ticket, owner="o", run="r")
