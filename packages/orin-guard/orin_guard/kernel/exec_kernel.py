"""CaMeL-style execution kernel: privileged plan vs quarantined data.

The planner channel may see owner intent. The data channel may read
untrusted content but has no tool rights. Slot fills that carry taint
into a sink are refused.
"""

from __future__ import annotations

from dataclasses import dataclass

from echo_core.sinks import SINK_FS_WRITE, SINK_NETWORK_EGRESS, sinks_for_tool
from echo_core.taint import SECRET, WEB_CONTENT


class ExecKernelDenied(PermissionError):
    """Plan/check refused."""


@dataclass(frozen=True, slots=True)
class PlanStep:
    tool: str
    slot_taint: int = 0


@dataclass(frozen=True, slots=True)
class ExecPlan:
    steps: tuple[PlanStep, ...]
    privileged: bool


class ExecKernel:
    def check(self, plan: ExecPlan) -> None:
        for step in plan.steps:
            sinks = sinks_for_tool(step.tool)
            if step.slot_taint & WEB_CONTENT and sinks & (SINK_NETWORK_EGRESS | SINK_FS_WRITE):
                raise ExecKernelDenied("tainted slot cannot fill a write/egress sink")
            if step.slot_taint & SECRET and sinks & SINK_NETWORK_EGRESS:
                raise ExecKernelDenied("SECRET data cannot egress")
            if not plan.privileged and sinks != 0:
                raise ExecKernelDenied("quarantined channel has no tool rights")


__all__ = ["ExecKernel", "ExecKernelDenied", "ExecPlan", "PlanStep"]
