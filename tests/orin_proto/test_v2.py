"""orin/v2 frame codec tests."""

from __future__ import annotations

import pytest
from orin_proto.v2 import FrameError, pack, unpack


def test_roundtrip() -> None:
    frame = pack({"type": "hello", "pid": 1})
    payload, rest = unpack(frame)
    assert payload["type"] == "hello"
    assert rest == b""


def test_unknown_kind() -> None:
    with pytest.raises(FrameError):
        pack({"type": "not-a-kind"})


def test_v2_kinds() -> None:
    pack({"type": "conjunction.check", "grants": []})
    pack({"type": "exec.plan", "steps": []})
