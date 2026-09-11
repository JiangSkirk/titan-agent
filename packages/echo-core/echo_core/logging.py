"""Stdlib logger port. echo-core must not import ``js.utils.log``."""

from __future__ import annotations

import logging
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class Logger(Protocol):
    """Minimal logger surface used by sandbox and ledger adapters."""

    def debug(self, msg: str, *args: Any, **kwargs: Any) -> None: ...
    def info(self, msg: str, *args: Any, **kwargs: Any) -> None: ...
    def warning(self, msg: str, *args: Any, **kwargs: Any) -> None: ...
    def error(self, msg: str, *args: Any, **kwargs: Any) -> None: ...
    def exception(self, msg: str, *args: Any, **kwargs: Any) -> None: ...


def get_logger(name: str) -> logging.Logger:
    """Return a stdlib logger. Hosts may reconfigure logging.basicConfig."""

    return logging.getLogger(name)


__all__ = ["Logger", "get_logger"]
