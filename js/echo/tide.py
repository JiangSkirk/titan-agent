"""Compatibility shim — implementation lives in echo_core."""
from __future__ import annotations

import sys

import echo_core.tide as _impl
from echo_core.tide import *  # noqa: F403

sys.modules[__name__] = _impl
