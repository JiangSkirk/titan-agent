"""Compatibility shim — implementation lives in echo_core."""

from __future__ import annotations

import sys

import echo_core.mode_contract as _impl
from echo_core.mode_contract import *  # noqa: F403
from echo_core.mode_contract import (
    _OWNER_RE as _OWNER_RE,
)
from echo_core.mode_contract import (
    _SESSION_RUN_RE as _SESSION_RUN_RE,
)
from echo_core.mode_contract import (
    _validate_identity as _validate_identity,
)
from echo_core.mode_contract import (
    _validate_workspace as _validate_workspace,
)

sys.modules[__name__] = _impl
