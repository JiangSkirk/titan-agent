"""Echo 3.0 naming and data-home tests."""

from __future__ import annotations

from echo_core import ECHO_3_ARCHITECTURE
from echo_core.homes import echo_core_home
from echo_core.os_sandbox import SandboxExecutor as CoreSandbox
from echo_core.primitives import ECHO_2_ARCHITECTURE
from orin_guard.homes import orin_guard_home


def test_echo3_name_does_not_reuse_echo2_brand() -> None:
    assert ECHO_2_ARCHITECTURE == "echo-2.0"
    assert ECHO_3_ARCHITECTURE == "echo-3.0"
    assert ECHO_3_ARCHITECTURE != ECHO_2_ARCHITECTURE


def test_package_homes_are_independent() -> None:
    assert echo_core_home().name == ".echo-core"
    assert orin_guard_home().name == ".orin-guard"
    assert echo_core_home() != orin_guard_home()


def test_js_echo_sandbox_shim_is_echo_core_module() -> None:
    import js.echo.os_sandbox as host

    assert host.SandboxExecutor is CoreSandbox
    assert host.__name__ == "echo_core.os_sandbox"
