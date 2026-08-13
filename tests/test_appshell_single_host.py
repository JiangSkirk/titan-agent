"""B1 single-host surface: one root, hidden children, isolated runtimes."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest
import yaml
from fastapi.testclient import TestClient


@pytest.fixture()
def appshell_app(tmp_path: Path) -> Any:
    from js.appshell.server import create_appshell_app
    from js.security.provider_credentials import fake_keychain_store
    from js_work.tools import WorkToolProfile

    personal = tmp_path / "personal.yaml"
    personal.write_text(
        yaml.safe_dump(
            {
                "workspace": str(tmp_path / "personal-workspace"),
                "state_dir": str(tmp_path / "personal-state"),
                "first_run_completed": True,
                "security": {"api_key_required": True},
                "providers": [],
            }
        ),
        encoding="utf-8",
    )
    os.chmod(personal, 0o600)
    work = tmp_path / "work.yaml"
    work.write_text(
        yaml.safe_dump(
            {
                "first_run_completed": True,
                "security": {"api_key_required": True},
                "providers": [],
            }
        ),
        encoding="utf-8",
    )
    os.chmod(work, 0o600)
    # B1A: tests must explicitly inject a fake Keychain backend.
    store, _ = fake_keychain_store()
    return create_appshell_app(
        personal_config=str(personal),
        work_config=str(work),
        work_home=tmp_path / "work-home",
        work_profile=WorkToolProfile.SAFE,
        host="127.0.0.1",
        port=8000,
        credential_store=store,
    )


def test_root_is_the_only_browser_surface(appshell_app: Any) -> None:
    with TestClient(appshell_app, base_url="http://localhost") as client:
        root = client.get("/")
        assert root.status_code == 200
        assert "text/html" in root.headers.get("content-type", "")
        assert client.get("/personal/").status_code == 404
        assert client.get("/work/").status_code == 404


def test_root_api_without_parent_session_fails_closed(appshell_app: Any) -> None:
    with TestClient(appshell_app, base_url="http://localhost") as client:
        response = client.get("/api/status")
        assert response.status_code == 401
        assert response.json()["detail"] == "AppShell session is required"


def test_child_login_and_legacy_switch_are_hidden(appshell_app: Any) -> None:
    with TestClient(
        appshell_app,
        base_url="http://localhost",
        headers={"Origin": "http://localhost"},
    ) as client:
        assert client.post("/api/auth/session", json={"api_key": "unused"}).status_code == 404
        legacy = client.post("/api/workspace/switch", json={"to_product": "js-work"})
        assert legacy.status_code == 410
        assert legacy.json()["detail"]["use"] == "/api/appshell/switch"


def test_personal_and_work_runtime_storage_remain_physically_isolated(
    appshell_app: Any,
) -> None:
    personal = appshell_app.state.personal_app.state.runtime_settings
    work = appshell_app.state.work_app.state.runtime_settings
    assert personal.product_id == "js-agent"
    assert work.product_id == "js-work"
    assert personal.state_dir != work.state_dir
    assert personal.workspace != work.workspace
    assert personal.bind_port == work.bind_port == 8000


def test_appshell_migrates_personal_and_work_provider_keys_before_loading(
    tmp_path: Path,
) -> None:
    """Desktop composition migrates each product with its own Keychain scope."""
    from js.appshell.server import create_appshell_app
    from js.provider_credential_types import ProviderCredentialRefV1
    from js.security.provider_credentials import fake_keychain_store
    from js_work.tools import WorkToolProfile

    personal_secret = "personal-inline-key"
    work_secret = "work-inline-key"
    personal = tmp_path / "personal.yaml"
    personal.write_text(
        yaml.safe_dump(
            {
                "workspace": str(tmp_path / "personal-workspace"),
                "state_dir": str(tmp_path / "personal-state"),
                "providers": [
                    {
                        "name": "personal-cloud",
                        "base_url": "https://personal.example/v1",
                        "api_key": personal_secret,
                        "api_key_env": "MUST_NOT_BE_AUTHORITY",
                        "models": [],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    os.chmod(personal, 0o600)
    work_home = tmp_path / "work-home"
    work = tmp_path / "work.yaml"
    work.write_text(
        yaml.safe_dump(
            {
                "work_home": str(work_home / ".js-work"),
                "workspace": str(work_home / ".js-work" / "workspace"),
                "state_dir": str(work_home / ".js-work" / "state"),
                "providers": [
                    {
                        "name": "work-cloud",
                        "base_url": "https://work.example/v1",
                        "api_key": work_secret,
                        "api_key_env": "MUST_NOT_BE_AUTHORITY",
                        "models": [],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    os.chmod(work, 0o600)
    store, _backend = fake_keychain_store()

    app = create_appshell_app(
        personal_config=str(personal),
        work_config=str(work),
        work_home=work_home,
        work_profile=WorkToolProfile.SAFE,
        credential_store=store,
    )

    personal_provider = yaml.safe_load(personal.read_text(encoding="utf-8"))["providers"][0]
    work_provider = yaml.safe_load(work.read_text(encoding="utf-8"))["providers"][0]
    assert personal_secret not in personal.read_text(encoding="utf-8")
    assert work_secret not in work.read_text(encoding="utf-8")
    assert "api_key_env" not in personal_provider
    assert "api_key_env" not in work_provider
    personal_ref = ProviderCredentialRefV1.model_validate(
        personal_provider["credential_ref"]
    )
    work_ref = ProviderCredentialRefV1.model_validate(work_provider["credential_ref"])
    assert personal_ref.product_id == "js-agent"
    assert work_ref.product_id == "js-work"
    assert store.for_product("js-agent").require(
        personal_ref, expected_kind="model_provider"
    ) == personal_secret
    assert store.for_product("js-work").require(
        work_ref, expected_kind="model_provider"
    ) == work_secret
    assert app.state.personal_app.state.runtime_settings.providers[0].credential_ref == (
        personal_ref
    )
    assert app.state.work_app.state.runtime_settings.providers[0].credential_ref == work_ref
    with TestClient(app, base_url="http://localhost"):
        personal_live = app.state.personal_app.state.web_runtime.settings
        work_live = app.state.work_app.state.web_runtime.settings
        assert personal_live.providers[0].api_key == personal_secret
        assert work_live.providers[0].api_key == work_secret


def test_appshell_preflights_both_products_before_any_keychain_or_config_effect(
    tmp_path: Path,
) -> None:
    from js.appshell.server import create_appshell_app
    from js.security.provider_credential_migration import CredentialMigrationFailed
    from js.security.provider_credentials import fake_keychain_store

    personal = tmp_path / "personal.yaml"
    personal.write_text(
        yaml.safe_dump(
            {
                "workspace": str(tmp_path / "personal-workspace"),
                "state_dir": str(tmp_path / "personal-state"),
                "providers": [
                    {
                        "name": "personal-cloud",
                        "base_url": "https://personal.example/v1",
                        "api_key": "personal-must-remain",
                        "models": [],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    os.chmod(personal, 0o600)
    original_personal = personal.read_bytes()
    work = tmp_path / "work.yaml"
    work.write_text("[invalid yaml", encoding="utf-8")
    os.chmod(work, 0o600)
    store, backend = fake_keychain_store()

    with pytest.raises(CredentialMigrationFailed):
        create_appshell_app(
            personal_config=str(personal),
            work_config=str(work),
            work_home=tmp_path / "work-home",
            credential_store=store,
        )

    assert personal.read_bytes() == original_personal
    assert backend._store == {}  # noqa: SLF001
    assert not (tmp_path / "personal-state").exists()


@pytest.mark.parametrize("suffix", (".YAML", ".YML", ".TOML"))
def test_appshell_accepts_uppercase_supported_config_suffixes(
    tmp_path: Path,
    suffix: str,
) -> None:
    from js.appshell.server import create_appshell_app
    from js.security.provider_credentials import fake_keychain_store

    personal = tmp_path / f"personal{suffix}"
    payload = {
        "workspace": str(tmp_path / "personal-workspace"),
        "state_dir": str(tmp_path / "personal-state"),
        "providers": [],
    }
    if suffix.lower() == ".toml":
        import tomli_w

        personal.write_text(tomli_w.dumps(payload), encoding="utf-8")
    else:
        personal.write_text(yaml.safe_dump(payload), encoding="utf-8")
    os.chmod(personal, 0o600)
    store, _backend = fake_keychain_store()

    app = create_appshell_app(
        personal_config=str(personal),
        work_home=tmp_path / "work-home",
        credential_store=store,
    )

    assert app.state.personal_app.state.runtime_settings.state_dir == Path(
        payload["state_dir"]
    )


@pytest.mark.parametrize("suffix", (".txt", ""))
def test_appshell_rejects_unsupported_missing_config_before_state_effect(
    tmp_path: Path,
    suffix: str,
) -> None:
    from js.appshell.server import create_appshell_app
    from js.security.provider_credential_migration import CredentialMigrationFailed
    from js.security.provider_credentials import fake_keychain_store

    config = tmp_path / f"missing{suffix}"
    store, backend = fake_keychain_store()

    with pytest.raises(CredentialMigrationFailed):
        create_appshell_app(
            personal_config=str(config),
            work_home=tmp_path / "work-home",
            credential_store=store,
        )

    assert not config.exists()
    assert backend._store == {}  # noqa: SLF001


def test_source_appshell_without_store_rejects_legacy_provider_key(
    tmp_path: Path,
) -> None:
    """Source composition cannot turn persisted plaintext into authority."""
    from js.appshell.server import create_appshell_app

    personal = tmp_path / "personal.yaml"
    personal.write_text(
        yaml.safe_dump(
            {
                "workspace": str(tmp_path / "personal-workspace"),
                "state_dir": str(tmp_path / "personal-state"),
                "providers": [
                    {
                        "name": "legacy",
                        "base_url": "https://provider.example/v1",
                        "api_key": "must-not-load",
                        "models": [],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="migration is required"):
        create_appshell_app(personal_config=str(personal))


def test_appshell_migration_rejects_symlink_config_before_keychain_effect(
    tmp_path: Path,
) -> None:
    from js.appshell.server import create_appshell_app
    from js.security.provider_credential_migration import CredentialMigrationFailed
    from js.security.provider_credentials import fake_keychain_store

    target = tmp_path / "target.yaml"
    target.write_text(
        yaml.safe_dump(
            {
                "workspace": str(tmp_path / "workspace"),
                "state_dir": str(tmp_path / "state"),
                "providers": [
                    {
                        "name": "legacy",
                        "base_url": "https://provider.example/v1",
                        "api_key": "must-not-migrate-through-link",
                        "models": [],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    os.chmod(target, 0o600)
    linked = tmp_path / "linked.yaml"
    linked.symlink_to(target)
    store, backend = fake_keychain_store()

    with pytest.raises(CredentialMigrationFailed):
        create_appshell_app(
            personal_config=str(linked),
            work_home=tmp_path / "work-home",
            credential_store=store,
        )

    assert backend._store == {}  # noqa: SLF001
    assert "must-not-migrate-through-link" in target.read_text(encoding="utf-8")


def test_appshell_startup_recovers_search_ref_saved_before_commit(
    tmp_path: Path,
) -> None:
    from js.appshell.server import create_appshell_app
    from js.config import JSSettings
    from js.security.provider_credential_migration import ProviderCredentialMigrator
    from js.security.provider_credentials import fake_keychain_store

    config = tmp_path / "personal.yaml"
    state = tmp_path / "personal-state"
    settings = JSSettings(
        workspace=tmp_path / "personal-workspace",
        state_dir=state,
    )
    settings.save(config)
    store, _backend = fake_keychain_store()
    migrator = ProviderCredentialMigrator(state, store, product_id="js-agent")
    ref = migrator.stage_search_credential("search-secret")
    settings.search_credential_ref = ref
    settings.save(config)
    assert migrator.receipt.get_pending()

    app = create_appshell_app(
        personal_config=str(config),
        work_home=tmp_path / "work-home",
        credential_store=store,
    )

    assert app.state.personal_app.state.runtime_settings.search_credential_ref == ref
    assert store.require(ref, expected_kind="search_provider") == "search-secret"
    assert migrator.receipt.recover() is None


def test_appshell_existing_search_ref_missing_from_keychain_is_fatal(
    tmp_path: Path,
) -> None:
    from js.appshell.server import create_appshell_app
    from js.config import JSSettings
    from js.provider_credential_types import ProviderCredentialRefV1
    from js.security.provider_credential_migration import SourceClearedButKeychainMissing
    from js.security.provider_credentials import fake_keychain_store

    config = tmp_path / "personal.yaml"
    missing_ref = ProviderCredentialRefV1(
        ref_id="e" * 32,
        product_id="js-agent",
        kind="search_provider",
    )
    settings = JSSettings(
        workspace=tmp_path / "personal-workspace",
        state_dir=tmp_path / "personal-state",
        search_credential_ref=missing_ref,
    )
    settings.save(config)
    store, backend = fake_keychain_store()

    with pytest.raises(
        SourceClearedButKeychainMissing,
        match="published credential is missing from Keychain",
    ):
        create_appshell_app(
            personal_config=str(config),
            work_home=tmp_path / "work-home",
            credential_store=store,
        )

    assert backend._store == {}  # noqa: SLF001 - no fallback credential created


def test_appshell_startup_removes_unpublished_search_orphan(tmp_path: Path) -> None:
    from js.appshell.server import create_appshell_app
    from js.config import JSSettings
    from js.security.provider_credential_migration import ProviderCredentialMigrator
    from js.security.provider_credentials import fake_keychain_store

    config = tmp_path / "personal.yaml"
    state = tmp_path / "personal-state"
    JSSettings(
        workspace=tmp_path / "personal-workspace",
        state_dir=state,
    ).save(config)
    store, _backend = fake_keychain_store()
    migrator = ProviderCredentialMigrator(state, store, product_id="js-agent")
    orphan = migrator.stage_search_credential("orphan-secret")

    app = create_appshell_app(
        personal_config=str(config),
        work_home=tmp_path / "work-home",
        credential_store=store,
    )

    assert app.state.personal_app.state.runtime_settings.search_credential_ref is None
    assert store.get(orphan, expected_kind="search_provider") is None
    assert migrator.receipt.recover() is None


def test_appshell_startup_recovers_work_search_ref_in_work_scope(
    tmp_path: Path,
) -> None:
    from js.appshell.server import create_appshell_app
    from js.config import JSSettings
    from js.security.provider_credential_migration import ProviderCredentialMigrator
    from js.security.provider_credentials import fake_keychain_store
    from js_work.config import WorkSettings

    personal_config = tmp_path / "personal.yaml"
    JSSettings(
        workspace=tmp_path / "personal-workspace",
        state_dir=tmp_path / "personal-state",
    ).save(personal_config)
    work_home = tmp_path / "work-home" / ".js-work"
    work_config = tmp_path / "work.yaml"
    work_settings = WorkSettings(
        work_home=work_home,
        workspace=work_home / "workspace",
        state_dir=work_home / "state",
    )
    work_settings.save(work_config)
    store, _backend = fake_keychain_store()
    work_store = store.for_product("js-work")
    migrator = ProviderCredentialMigrator(
        work_settings.state_dir,
        work_store,
        product_id="js-work",
    )
    ref = migrator.stage_search_credential("work-search-secret")
    work_settings.search_credential_ref = ref
    work_settings.save(work_config)

    app = create_appshell_app(
        personal_config=str(personal_config),
        work_config=str(work_config),
        work_home=tmp_path / "work-home",
        credential_store=store,
    )

    assert app.state.work_app.state.runtime_settings.search_credential_ref == ref
    assert work_store.require(ref, expected_kind="search_provider") == (
        "work-search-secret"
    )
    assert migrator.receipt.recover() is None


def test_real_appshell_composition_has_separate_local_only_connector_managers(
    appshell_app: Any,
) -> None:
    with TestClient(appshell_app, base_url="http://localhost"):
        personal_runtime = (
            appshell_app.state.personal_app.state.web_runtime.agent.echo_runtime
        )
        work_runtime = appshell_app.state.work_app.state.web_runtime.agent.echo_runtime
        assert personal_runtime._connector_manager is not work_runtime._connector_manager
        for runtime in (personal_runtime, work_runtime):
            assert {
                item["connector_type"]
                for item in runtime._connector_manager.list_available()
            } == {"local_import", "local_publish"}
            assert not runtime._connector_manager.is_available("fake")


def test_health_never_advertises_a_second_port(appshell_app: Any) -> None:
    with TestClient(appshell_app, base_url="http://localhost") as client:
        response = client.get("/api/appshell/health")
        assert response.status_code == 200
        assert response.json()["modes"] == ["personal", "work"]
        assert "8765" not in response.text


def test_ordinary_cli_help_never_advertises_a_second_port() -> None:
    from click.testing import CliRunner

    from js.ui.cli import main as js_main
    from js_work.cli import main as work_main

    runner = CliRunner()
    outputs = [
        runner.invoke(js_main, ["--help"]),
        runner.invoke(js_main, ["appshell", "--help"]),
        runner.invoke(work_main, ["--help"]),
        runner.invoke(work_main, ["web", "--help"]),
    ]
    assert all(result.exit_code == 0 for result in outputs)
    assert all("8765" not in result.output for result in outputs)
