"""Single-host AppShell server with parent-controlled root routing."""

from __future__ import annotations

import asyncio
import logging
import os
from collections.abc import AsyncIterator
from contextlib import AsyncExitStack, asynccontextmanager
from pathlib import Path
from typing import Any, cast

from fastapi import FastAPI, HTTPException

from js.appshell.principal import AppShellSessionStore
from js.appshell.routing import (
    AppShellModeGate,
    AppShellRoutingMiddleware,
    AppShellWebSocketRegistry,
)
from js.config import JSSettings, settings_read_only_validation
from js.echo.turn_runtime import _workspace_handle
from js.product_storage import StorageRoots
from js.web import server as web_server
from js.web.auth import AuthManager
from js_work.config import WorkSettings, default_work_config_path, default_work_home
from js_work.tools import WorkToolProfile
from js_work.web import create_work_web_app

logger = logging.getLogger(__name__)

_WORK_STATUS_STARTING = {"status": "starting"}
_WORK_STATUS_READY = {"status": "ready"}


class _WorkAttachError(Exception):
    """Closed Work attach failure that must not kill Personal."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def work_runtime_ready(app: FastAPI) -> bool:
    """True only when the Work child is attached and routable."""
    return bool(
        getattr(app.state, "work_ready", False)
        and getattr(app.state, "work_app", None) is not None
    )


def _work_failure_code(exc: BaseException) -> str:
    message = str(exc).lower()
    if "unsafe" in message or "namespace" in message or "disjoint" in message:
        return "work_preflight_failed"
    from js.security.provider_credential_migration import CredentialMigrationFailed

    if isinstance(exc, CredentialMigrationFailed):
        return "work_config_invalid"
    return "work_runtime_unavailable"


def _unavailable_work_status(code: str) -> dict[str, str]:
    return {"status": "unavailable", "code": code}


def _personal_config_path(config: str | None) -> Path:
    if config is not None:
        return Path(os.path.abspath(os.fspath(Path(config).expanduser())))
    if env_path := os.getenv("JS_CONFIG_PATH"):
        return Path(os.path.abspath(os.fspath(Path(env_path).expanduser())))
    candidates = (
        Path.home() / ".config" / "js" / "config.yaml",
        Path.home() / ".config" / "js" / "config.toml",
    )
    return next((path for path in candidates if path.exists()), candidates[0])


def _work_config_path(config: str | None, *, home: Path | None) -> Path:
    if config is not None:
        return Path(config).expanduser()
    if env_path := os.getenv("JS_WORK_CONFIG_PATH"):
        return Path(env_path).expanduser()
    return default_work_config_path(home or Path.home())


def _sanitized_migration_settings(
    config_path: Path,
    *,
    product_id: str,
    work_home: Path | None,
) -> JSSettings:
    """Validate path-bearing config fields without accepting its plaintext key."""
    from js.security.provider_credential_migration import ProviderCredentialMigrator

    data = ProviderCredentialMigrator.inspect_config(config_path)
    providers = data.get("providers", [])
    if isinstance(providers, list):
        for provider in providers:
            if isinstance(provider, dict):
                provider.pop("api_key", None)
                provider.pop("api_key_env", None)
    if product_id == "js-work":
        base_home = work_home or Path.home()
        resolved_home = default_work_home(base_home)
        data.setdefault("work_home", resolved_home)
        data.setdefault("workspace", resolved_home / "workspace")
        data.setdefault("state_dir", resolved_home / "state")
        data["product_id"] = "js-work"
        with settings_read_only_validation():
            return WorkSettings(**data)
    with settings_read_only_validation():
        return JSSettings(**data)


def _preflight_migration_target(
    config_path: Path,
    *,
    product_id: str,
    work_home: Path | None,
) -> JSSettings | None:
    """Validate one product completely without Keychain or config effects."""
    from js.provider_credential_types import ProductId
    from js.security.provider_credential_migration import (
        CredentialMigrationFailed,
        ProviderCredentialMigrator,
    )

    if config_path.is_symlink():
        raise CredentialMigrationFailed("provider configuration is unsafe")
    suffix = config_path.suffix.lower()
    if suffix not in {".yaml", ".yml", ".toml"}:
        raise CredentialMigrationFailed("unsupported provider configuration format")
    if not config_path.exists():
        # Supported missing configs are valid fresh-install targets. They are
        # not migrated and no state directory is created during preflight.
        return None
    settings = _sanitized_migration_settings(
        config_path,
        product_id=product_id,
        work_home=work_home,
    )
    ProviderCredentialMigrator.migrate_paths_preflight(
        config_path,
        state_dir=settings.state_dir,
        product_id=cast("ProductId", product_id),
    )
    return settings


def _migrate_static_credentials(
    config_path: Path,
    *,
    credential_store: Any,
    product_id: str,
    work_home: Path | None = None,
    migration_settings: JSSettings | None = None,
) -> None:
    """Migrate before strict settings loading can observe persisted plaintext."""
    if migration_settings is None:
        return
    from typing import cast

    from js.provider_credential_types import ProductId
    from js.security.provider_credential_migration import ProviderCredentialMigrator

    scoped_product = cast("ProductId", product_id)
    scoped_store = credential_store.for_product(scoped_product)
    migrator = ProviderCredentialMigrator(
        migration_settings.state_dir,
        scoped_store,
        product_id=scoped_product,
    )
    migrator.migrate_static_config(config_path)
    migrator.recover_search_credential(config_path)


def create_appshell_app(
    *,
    personal_config: str | None = None,
    work_config: str | None = None,
    work_home: Path | None = None,
    work_profile: WorkToolProfile = WorkToolProfile.EXECUTE,
    host: str = "127.0.0.1",
    port: int = 8000,
    credential_store: Any | None = None,
) -> FastAPI:
    """Build one parent host with isolated Personal and Work child runtimes.

    Children are never selected by URL/product input. Root ``/api/*`` and
    ``/ws`` are dispatched solely from the parent ``AppShellPrincipalV1``.

    Desktop release paths inject the required macOS Keychain store.  A source
    AppShell without credentials may omit it, but then credential references
    and provider mutation fail closed.

    Personal is the ready boundary. Work is attached after the parent yields;
    a broken Work config degrades Work and never blocks the Personal sentinel.
    """
    resolved_personal_config = _personal_config_path(personal_config)
    resolved_work_config = _work_config_path(work_config, home=work_home)
    personal_migration_settings: JSSettings | None = None
    if credential_store is not None:
        personal_migration_settings = _preflight_migration_target(
            resolved_personal_config,
            product_id="js-agent",
            work_home=None,
        )
        _migrate_static_credentials(
            resolved_personal_config,
            credential_store=credential_store,
            product_id="js-agent",
            migration_settings=personal_migration_settings,
        )
    personal_settings: JSSettings
    if personal_config is not None:
        personal_settings = JSSettings.from_file(personal_config)
    else:
        personal_settings = JSSettings.from_file()
    object.__setattr__(personal_settings, "bind_host", host)
    object.__setattr__(personal_settings, "bind_port", port)
    object.__setattr__(personal_settings, "product_id", "js-agent")
    object.__setattr__(personal_settings, "_appshell_managed", True)
    if credential_store is not None:
        personal_store = credential_store.for_product("js-agent")
        object.__setattr__(personal_settings, "_credential_store", personal_store)

    personal_app = web_server.create_app(
        runtime_settings=personal_settings,
        title="JS Agent",
    )

    personal_roots = StorageRoots(
        config_path=personal_settings.config_source_path,
        workspace=personal_settings.workspace.expanduser().resolve(strict=False),
        state_dir=personal_settings.state_dir.expanduser().resolve(strict=False),
    )
    session_store = AppShellSessionStore(personal_settings.state_dir / "appshell_sessions.db")

    def _bind_child_epoch(child_app: FastAPI) -> None:
        child_app.state.web_runtime.agent.__dict__["_appshell_epoch_validator"] = (
            session_store.require_epoch_current
        )
        child_app.state.web_runtime.agent.__dict__["_appshell_operation_store"] = (
            session_store
        )

    def _wire_appshell_onboarding_peers(parent_app: FastAPI, work_app: FastAPI) -> None:
        """Link live Personal/Work settings so onboarding skip is product-wide.

        Work's lifespan may create a fresh agent/settings object; always wire
        the peer on ``web_runtime.settings`` (request-path authority), not only
        the pre-boot ``app.state.runtime_settings`` snapshot. Workspace paths,
        leases, and approvals are never mirrored.
        """
        personal_live = personal_app.state.web_runtime.settings
        work_live = work_app.state.web_runtime.settings
        for live in (personal_live, work_live):
            object.__setattr__(live, "_appshell_managed", True)
        object.__setattr__(personal_live, "_appshell_peer_settings", work_live)
        object.__setattr__(work_live, "_appshell_peer_settings", personal_live)
        personal_app.state.runtime_settings = personal_live
        work_app.state.runtime_settings = work_live
        parent_app.state.work_workspace_handle = _workspace_handle(work_live.workspace)

    def _try_build_work_app() -> FastAPI:
        from js.security.provider_credential_migration import CredentialMigrationFailed

        try:
            work_migration_settings: JSSettings | None = None
            if credential_store is not None:
                work_migration_settings = _preflight_migration_target(
                    resolved_work_config,
                    product_id="js-work",
                    work_home=work_home,
                )
                _migrate_static_credentials(
                    resolved_work_config,
                    credential_store=credential_store,
                    product_id="js-work",
                    work_home=work_home,
                    migration_settings=work_migration_settings,
                )
            work_app = create_work_web_app(
                config=work_config,
                home=work_home,
                personal_roots=personal_roots,
                profile=work_profile,
                host=host,
                port=port,
            )
            work_settings = work_app.state.runtime_settings
            object.__setattr__(work_settings, "_appshell_managed", True)
            if credential_store is not None:
                work_store = credential_store.for_product("js-work")
                object.__setattr__(work_settings, "_credential_store", work_store)
            return work_app
        except _WorkAttachError:
            raise
        except CredentialMigrationFailed as exc:
            raise _WorkAttachError(_work_failure_code(exc)) from exc
        except Exception as exc:
            raise _WorkAttachError(_work_failure_code(exc)) from exc

    def _mark_work_unavailable(parent_app: FastAPI, code: str) -> None:
        parent_app.state.work_ready = False
        parent_app.state.work_app = None
        parent_app.state.work_status = _unavailable_work_status(code)
        logger.warning("Work runtime unavailable: %s", code)

    async def _attach_work_runtime(
        parent_app: FastAPI,
        shutdown_event: asyncio.Event,
    ) -> None:
        stack = AsyncExitStack()
        try:
            try:
                work_app = await asyncio.to_thread(_try_build_work_app)
            except _WorkAttachError as exc:
                _mark_work_unavailable(parent_app, exc.code)
                return
            except Exception:
                _mark_work_unavailable(parent_app, "work_runtime_unavailable")
                return
            await stack.enter_async_context(work_app.router.lifespan_context(work_app))
            _wire_appshell_onboarding_peers(parent_app, work_app)
            _bind_child_epoch(work_app)
            parent_app.state.work_app = work_app
            parent_app.state.work_ready = True
            parent_app.state.work_status = dict(_WORK_STATUS_READY)
            identity = getattr(parent_app.state, "desktop_identity", None)
            on_attached = getattr(identity, "on_work_attached", None)
            if callable(on_attached):
                on_attached()
            await shutdown_event.wait()
        except asyncio.CancelledError:
            raise
        except Exception:
            _mark_work_unavailable(parent_app, "work_runtime_unavailable")
        finally:
            if getattr(parent_app.state, "work_ready", False):
                parent_app.state.work_ready = False
                parent_app.state.work_status = _unavailable_work_status(
                    "work_runtime_unavailable"
                )
            parent_app.state.work_app = None
            await stack.aclose()

    @asynccontextmanager
    async def appshell_lifespan(parent_app: FastAPI) -> AsyncIterator[None]:
        shutdown_event = asyncio.Event()
        async with AsyncExitStack() as stack:
            await stack.enter_async_context(
                personal_app.router.lifespan_context(personal_app)
            )
            _bind_child_epoch(personal_app)
            attach_task = asyncio.create_task(
                _attach_work_runtime(parent_app, shutdown_event)
            )
            parent_app.state._work_attach_task = attach_task
            try:
                yield
            finally:
                shutdown_event.set()
                if not attach_task.done():
                    attach_task.cancel()
                await asyncio.gather(attach_task, return_exceptions=True)

    parent = FastAPI(title="JS Agent", lifespan=appshell_lifespan)
    parent.state.personal_app = personal_app
    parent.state.work_app = None
    parent.state.work_ready = False
    parent.state.work_status = dict(_WORK_STATUS_STARTING)
    parent.state.appshell_session_store = session_store
    parent.state.appshell_mode_gate = AppShellModeGate(session_store)
    parent.state.appshell_ws_registry = AppShellWebSocketRegistry()
    parent.state.work_workspace_handle = None

    def _principal_is_active(principal: Any) -> bool:
        try:
            expected_personal = principal.mode_roles.get("personal")
            if not isinstance(expected_personal, str) or not expected_personal:
                return False
            identity = AuthManager(personal_settings.state_dir).verify_key_hash(
                principal.owner
            )
            if identity.get("role") != expected_personal:
                return False
            if "work" not in principal.mode_roles:
                return True
            work_app = getattr(parent.state, "work_app", None)
            if not work_runtime_ready(parent) or work_app is None:
                return True
            work_settings = work_app.state.runtime_settings
            work_identity = AuthManager(work_settings.state_dir).verify_key_hash(
                principal.owner
            )
            return work_identity.get("role") == principal.mode_roles["work"]
        except Exception:
            return False

    parent.state.appshell_principal_is_active = _principal_is_active

    from js.appshell.routers import router as appshell_api_router

    parent.include_router(appshell_api_router)

    @parent.get("/api/appshell/health")
    async def _health() -> dict[str, Any]:
        work_status = dict(getattr(parent.state, "work_status", _WORK_STATUS_STARTING))
        modes = ["personal"]
        if work_runtime_ready(parent):
            modes.append("work")
        return {
            "status": "ok",
            "app_id": "js-agent",
            "schema": "AppShellHealthV1",
            "modes": modes,
            "personal": {"status": "ready"},
            "work": work_status,
        }

    @parent.post("/api/workspace/switch")
    async def _legacy_switch_hidden() -> None:
        raise HTTPException(
            410,
            {
                "code": "legacy_switch_hidden",
                "use": "/api/appshell/switch",
            },
        )

    parent.add_middleware(
        AppShellRoutingMiddleware,
        owner_app=parent,
        personal_app=personal_app,
        work_app=None,
    )

    return parent
