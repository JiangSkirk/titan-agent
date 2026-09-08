"""Global test fixtures."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from js.echo import stable_payload_hash
from js.echo.capability import LeaseAuthority, sign_tool_execution_context
from js.tools.registry import ToolExecutionContext, ToolRegistry

_SHARED_TOOL_AUTHORITY = LeaseAuthority(
    mac_key=b"test-tool-lease-key-32-bytes!!",
    now_fn=lambda: 1_000,
)


def _shared_consume_context(execution_context: ToolExecutionContext) -> str | None:
    try:
        _SHARED_TOOL_AUTHORITY.consume_execution_context(execution_context, now=1_000)
    except Exception as exc:
        return f"Echo execution context lease denied: {type(exc).__name__}"
    return None


@pytest.fixture
def echo_tool_context() -> Callable[..., ToolExecutionContext]:
    """Issue a signed Echo context bound to the exact test tool call."""

    authority = _SHARED_TOOL_AUTHORITY

    def _issue(
        *,
        run_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        owner_key_hash: str = "echo-test-owner",
        resource_scope: str = "test-scope",
        fs_roots: tuple[str, ...] = (),
        network_policy: str = "deny",
        network_hosts: tuple[str, ...] = (),
        max_bytes: int = 10_000,
        max_duration_ms: int = 1_000,
        registry: ToolRegistry,
    ) -> ToolExecutionContext:
        context = ToolExecutionContext(
            owner_key_hash=owner_key_hash,
            run_id=run_id,
            tool_name=tool_name,
            args_hash=stable_payload_hash(arguments),
            fs_roots=fs_roots,
            network_policy=network_policy,
            network_hosts=network_hosts,
            max_bytes=max_bytes,
            max_duration_ms=max_duration_ms,
            resource_scope=resource_scope,
        )
        lease = authority.issue(
            owner_key_hash=context.owner_key_hash,
            run_id=context.run_id,
            tool_name=context.tool_name,
            args_schema=context.args_hash,
            resource_scope=context.resource_scope,
            fs_roots=context.fs_roots,
            network_policy=context.network_policy,
            network_hosts=context.network_hosts,
            max_bytes=context.max_bytes,
            max_duration_ms=context.max_duration_ms,
            ttl_ms=60_000,
        )
        signed = sign_tool_execution_context(
            context,
            lease=lease,
            authority=authority,
            now=1_000,
        )

        registry.install_echo_context_verifier(_shared_consume_context)
        return signed

    return _issue


@pytest.fixture(autouse=True)
def stage_b_orin_default_opt_out_for_host_tests(
    monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest
) -> None:
    """Keep Host/unit suites on in-process leases unless they opt into Orin.

    Stage B product defaults are ``orin.enabled=true`` / ``orin.enforce=true``.
    Orin-focused suites under ``tests/orin`` / ``tests/contract`` (and package
    orin-guard tests) exercise those defaults. Other Host/AppShell/Work tests
    that assumed pre-Stage-B in-process leases opt out via env without
    changing Field defaults.
    """

    path = str(getattr(request, "fspath", "") or "").replace("\\", "/")
    if any(
        marker in path
        for marker in (
            "/tests/orin/",
            "/tests/contract/",
            "/packages/orin-guard/",
            "/tests/orin_guard/",
        )
    ):
        return
    if request.node.get_closest_marker("orin_live") is not None:
        return
    monkeypatch.setenv("JS_ORIN__ENABLED", "false")
    monkeypatch.setenv("JS_WORK_ORIN__ENABLED", "false")


@pytest.fixture(autouse=True)
def bind_synthetic_effect_receipt(request: pytest.FixtureRequest):
    """Unit tests may call ``_execute_tool_call`` directly; bind a D1 receipt.

    Contract suite tests exercise naked-bypass denial and must not receive this
    ambient bind.
    """

    path = str(getattr(request, "fspath", "") or "")
    if "tests/contract" in path.replace("\\", "/"):
        yield
        return

    from echo_core.effect_authority import LeaseReceipt

    from js.echo.effect_bind import reset_effect_exec_receipt, set_effect_exec_receipt

    handle = set_effect_exec_receipt(
        LeaseReceipt(
            lease_id="test-lease",
            stamp_id="test-stamp",
            consume_receipt_hash="test-consume",
        )
    )
    try:
        yield
    finally:
        reset_effect_exec_receipt(handle)


@pytest.fixture(autouse=True)
def reset_web_globals():
    """Keep mocked web agents from leaking between tests."""
    from js.web import deps, server
    from js.web.routers import system

    for module in (deps, server, system):
        if hasattr(module, "_agent"):
            module._agent = None
        if hasattr(module, "_settings"):
            module._settings = None
        if hasattr(module, "_stats_store"):
            module._stats_store = None
    deps.set_active_model("")
    yield
    for module in (deps, server, system):
        if hasattr(module, "_agent"):
            module._agent = None
        if hasattr(module, "_settings"):
            module._settings = None
        if hasattr(module, "_stats_store"):
            module._stats_store = None
    deps.set_active_model("")


@pytest.fixture(autouse=True)
def reset_structlog_config():
    """Restore structlog defaults after tests that call configure_logging().

    CLI-style tests invoke ``configure_logging`` which permanently switches
    structlog to the stdlib logger factory; subsequent capsys-based tests
    then stop seeing log output.  Resetting after each test keeps logging
    configuration test-local.
    """
    yield
    import structlog

    structlog.reset_defaults()
