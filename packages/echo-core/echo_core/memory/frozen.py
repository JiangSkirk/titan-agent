"""Bounded frozen memory. Over-limit fails closed so the turn must consolidate."""

from __future__ import annotations


class FrozenMemoryFull(MemoryError):
    """The freeze buffer is full; the agent must consolidate this turn."""


class FrozenMemory:
    def __init__(self, *, max_items: int = 64) -> None:
        self.max_items = max_items
        self._items: list[str] = []

    def add(self, text: str) -> None:
        if len(self._items) >= self.max_items:
            raise FrozenMemoryFull("frozen memory is full; consolidate this turn")
        self._items.append(text)

    def items(self) -> tuple[str, ...]:
        return tuple(self._items)
