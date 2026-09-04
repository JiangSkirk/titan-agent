#!/usr/bin/env python3
"""Standalone orin-guard quickstart. No js-agent required."""

from __future__ import annotations

from orin_guard.kernel.dual import PolicyPlane
from orin_guard.kernel.gate import GateKernel, TicketDenied


def main() -> None:
    kernel = GateKernel(b"k" * 32)
    plane = PolicyPlane("o", "s", "r", "tool", frozenset({"private.read"}), 1)
    ticket = kernel.issue(plane, now=100.0)
    receipt = kernel.consume(ticket, owner="o", run="r", now=200.0)
    print("consumed once:", bool(receipt))
    ticket2 = kernel.issue(plane, now=100.0)
    try:
        kernel.consume(ticket2, owner="o", run="r", now=401.0)
    except TicketDenied as exc:
        print("expired fail-closed:", exc)


if __name__ == "__main__":
    main()
