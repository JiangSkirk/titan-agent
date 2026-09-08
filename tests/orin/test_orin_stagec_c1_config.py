"""WP-C1 configuration gates: default-off, lazy, and fail-fast."""

from __future__ import annotations

from pathlib import Path

import pytest

from js.config import OrinConfig
from js.orin.protocol import ProtocolError, make_envelope
from js.orind.daemon import OrinDaemon, OrinDaemonError


def test_stage_c_switches_default_off() -> None:
    config = OrinConfig()

    # Stage B: D1 enforce defaults true; Stage C cell switches stay off.
    assert config.enforce is True
    assert config.cell_identity_enforce is False
    assert config.echo_minimal_os is False


def test_cell_identity_switch_is_accepted_but_lazy_without_stage_c_conjunction() -> None:
    config = OrinConfig(cell_identity_enforce=True)

    assert config.enforce is True
    assert config.cell_identity_enforce is True


def test_product_enforce_config_constructs_but_stage_c_routes_stay_closed() -> None:
    from js.orin.stage_c import product_enforce_enabled, require_stage_c_enforce

    config = OrinConfig(enforce=True)
    assert config.enforce is True
    assert product_enforce_enabled(config) is False
    with pytest.raises(ValueError, match="conjunction incomplete"):
        require_stage_c_enforce(config)


def test_daemon_enforce_fails_before_creating_state(tmp_path: Path) -> None:
    state_dir = tmp_path / "must-not-be-created"

    with pytest.raises(OrinDaemonError, match="conjunction incomplete"):
        OrinDaemon(state_dir=state_dir, orin_enforce=True)

    assert not state_dir.exists()


def test_non_enforce_hello_schema_still_rejects_c1_only_fields() -> None:
    with pytest.raises(ProtocolError, match="unknown field"):
        make_envelope(
            "hello",
            seq=1,
            nonce="a" * 32,
            session_key=None,
            caps=["lease.v2"],
            pid=123,
            launch_nonce="b" * 32,
        )
