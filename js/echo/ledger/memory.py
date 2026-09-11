"""Compatibility shim — implementation lives in echo_core."""
from __future__ import annotations

import sys

import echo_core.ledger.memory as _impl
from echo_core.ledger.memory import *  # noqa: F403

sys.modules[__name__] = _impl
