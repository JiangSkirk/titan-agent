"""Compatibility shim — implementation lives in echo_core."""
from __future__ import annotations

import sys

import echo_core.ledger.partition_retention as _impl
from echo_core.ledger.partition_retention import *  # noqa: F403

sys.modules[__name__] = _impl
