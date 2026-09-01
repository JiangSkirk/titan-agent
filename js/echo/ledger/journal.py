"""Compatibility shim — implementation lives in echo_core."""

from __future__ import annotations

import sys

import echo_core.ledger.journal as _impl
from echo_core.ledger.journal import *  # noqa: F403
from echo_core.ledger.journal import _read_file_records as _read_file_records
from echo_core.ledger.journal import _record_to_json as _record_to_json

sys.modules[__name__] = _impl
