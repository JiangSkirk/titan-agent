"""Compatibility shim — implementation lives in echo_core."""
from __future__ import annotations

import sys

import echo_core.capability_encoding as _impl
from echo_core.capability_encoding import *  # noqa: F403

sys.modules[__name__] = _impl
