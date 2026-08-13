"""Single-host AppShell server with parent-controlled root routing."""

from __future__ import annotations

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
    """
    resolved_personal_config = _personal_config_path(personal_config)
    resolved_work_config = _work_config_path(work_config, home=work_home)
    personal_migration_settings: JSSettings | None = None
    work_migration_settings: JSSettings | None = None
    if credential_store is not None:
        # Both products must pass the entire read-only boundary before either
        # product can create state, write Keychain, or rewrite configuration.
        personal_migration_settings = _preflight_migration_target(
            resolved_personal_config,
            product_id="js-agent",
            work_home=None,
        )
        work_migration_settings = _preflight_migration_target(
            resolved_work_config,
            product_id="js-work",
            work_home=work_home,
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

    if credential_store is not None:
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
    # Pre-lifespan peer link (may be replaced after children boot if agents
    # bind a different live settings object).
    object.__setattr__(personal_settings, "_appshell_peer_settings", work_settings)
    object.__setattr__(work_settings, "_appshell_peer_settings", personal_settings)
    session_store = AppShellSessionStore(personal_settings.state_dir / "appshell_sessions.db")

    def _wire_appshell_onboarding_peers(parent_app: FastAPI) -> None:
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

    @asynccontextmanager
    async def appshell_lifespan(parent_app: FastAPI) -> AsyncIterator[None]:
        async with AsyncExitStack() as stack:
            await stack.enter_async_context(
                personal_app.router.lifespan_context(personal_app)
            )
            await stack.enter_async_context(
                work_app.router.lifespan_context(work_app)
            )
            _wire_appshell_onboarding_peers(parent_app)
            for child_app in (personal_app, work_app):
                child_app.state.web_runtime.agent.__dict__["_appshell_epoch_validator"] = (
                    session_store.require_epoch_current
                )
                child_app.state.web_runtime.agent.__dict__["_appshell_operation_store"] = (
                    session_store
                )
            yield

    parent = FastAPI(title="JS Agent", lifespan=appshell_lifespan)
    parent.state.personal_app = personal_app
    parent.state.work_app = work_app
    parent.state.appshell_session_store = session_store
    parent.state.appshell_mode_gate = AppShellModeGate(session_store)
    parent.state.appshell_ws_registry = AppShellWebSocketRegistry()
    parent.state.work_workspace_handle = _workspace_handle(work_settings.workspace)

    def _principal_is_active(principal: Any) -> bool:
        settings_by_mode = {
            "personal": personal_settings,
            "work": work_settings,
        }
        try:
            for mode, expected_role in principal.mode_roles.items():
                identity = AuthManager(settings_by_mode[mode].state_dir).verify_key_hash(
                    principal.owner
                )
                if identity.get("role") != expected_role:
                    return False
        except Exception:
            return False
        return True

    parent.state.appshell_principal_is_active = _principal_is_active

    from js.appshell.routers import router as appshell_api_router

    parent.include_router(appshell_api_router)

    @parent.get("/api/appshell/health")
    async def _health() -> dict[str, Any]:
        return {"status": "ok", "app_id": "js-agent", "modes": ["personal", "work"]}

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
        work_app=work_app,
    )

    return parent
