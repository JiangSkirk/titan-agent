"""Compatibility shim — implementation lives in echo_core."""
from __future__ import annotations

import sys

import echo_core.os_sandbox as _impl
from echo_core.os_sandbox import *  # noqa: F403

sys.modules[__name__] = _impl
