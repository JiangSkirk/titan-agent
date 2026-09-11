"""Compatibility shim — implementation lives in echo_core."""
from __future__ import annotations

import sys

import echo_core.amber as _impl
from echo_core.amber import *  # noqa: F403

sys.modules[__name__] = _impl
