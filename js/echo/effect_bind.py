"""Context bind for EffectAuthority D1 receipts on the Host effect hot path.

``_execute_tool_call`` and connector dispatch refuse naked execution unless an
admitted lease receipt is bound here by ``EffectInterpreter``.
"""

from __future__ import annotations

from contextvars import ContextVar, Token
from dataclasses import dataclass

from echo_core.effect_authority import EffectAuthorityError, LeaseReceipt

_effect_exec_receipt: ContextVar[LeaseReceipt | None] = ContextVar(
    "echo_effect_exec_receipt",
    default=None,
)


@dataclass(frozen=True, slots=True)
class EffectExecToken:
    """Opaque bind handle so callers must reset via :func:`reset_effect_exec_receipt`."""

    _token: Token[LeaseReceipt | None]


def set_effect_exec_receipt(receipt: LeaseReceipt) -> EffectExecToken:
    return EffectExecToken(_token=_effect_exec_receipt.set(receipt))


def reset_effect_exec_receipt(handle: EffectExecToken) -> None:
    _effect_exec_receipt.reset(handle._token)


def current_effect_exec_receipt() -> LeaseReceipt | None:
    return _effect_exec_receipt.get()


def require_effect_exec_receipt() -> LeaseReceipt:
    receipt = _effect_exec_receipt.get()
    if receipt is None:
        raise EffectAuthorityError(
            "naked effect execution bypasses Echo EffectAuthority; D1 receipt required"
        )
    return receipt


__all__ = [
    "EffectExecToken",
    "current_effect_exec_receipt",
    "require_effect_exec_receipt",
    "reset_effect_exec_receipt",
    "set_effect_exec_receipt",
]
