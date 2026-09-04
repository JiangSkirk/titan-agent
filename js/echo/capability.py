"""Compatibility shim — implementation lives in echo_core."""

from __future__ import annotations

import sys

import echo_core.capability as _impl
from echo_core.capability import *  # noqa: F403
from echo_core.capability import _lease_from_payload as _lease_from_payload
from echo_core.capability import _lease_to_payload as _lease_to_payload

sys.modules[__name__] = _impl
