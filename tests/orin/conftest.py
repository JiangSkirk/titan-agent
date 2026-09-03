"""Linux CI pytest tmp dirs are 0755; C1 private-path contracts require 0700."""

from __future__ import annotations

import os
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _chmod_orin_tmp_path(tmp_path: Path) -> None:
    os.chmod(tmp_path, 0o700)
