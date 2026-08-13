"""Round 2 tests: setup exit code and web --config wiring.

1. Setup wizard must raise SystemExit(1) when any step fails (was: only
   ``logger.warning`` and then printed "Setup complete!").
2. ``_launch_web`` must actually pass the config path to ``JSSettings`` /
   ``create_app`` (was: parameter named ``_config`` and ignored).
"""

from __future__ import annotations

import inspect
import os
from pathlib import Path

import pytest
import yaml


def test_setup_wizard_raises_on_step_failure() -> None:
    """A failed setup step must abort with SystemExit(1), not continue."""
    from js.setup_wizard import SetupWizard

    wiz = SetupWizard()
    # Patch _setup_directories to raise.
    async def _boom(non_interactive: bool = False) -> None:
        raise OSError("disk full")

    wiz._setup_directories = _boom  # type: ignore[method-assign]
    with pytest.raises(SystemExit) as exc_info:
        import asyncio
        asyncio.run(wiz.run(non_interactive=True))
    assert exc_info.value.code == 1


def test_launch_web_uses_config_parameter() -> None:
    """_launch_web must not ignore the config argument."""
    from js.ui import cli
    source = inspect.getsource(cli._launch_web)
    # The old code had ``_config`` (underscore-prefixed = intentionally unused).
    assert "_config: str | None" not in source, (
        "_launch_web still names the config parameter as _config (unused)."
    )
    # The new code must reference the config parameter to load settings.
    assert "runtime_settings = JSSettings.from_file(config)" in source or \
           "JSSettings.from_file(config)" in source, (
        "_launch_web must pass config to JSSettings.from_file()."
    )


@pytest.mark.asyncio
async def test_setup_wizard_tavily_save_commits_keychain_reference(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from js.agent import JSAgent
    from js.config import JSSettings
    from js.search.engines import TavilyEngine
    from js.security.provider_credentials import fake_keychain_store
    from js.setup_wizard import SetupWizard

    config = tmp_path / "config.yaml"
    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
    )
    store, _backend = fake_keychain_store()
    wizard = SetupWizard(
        settings=settings,
        config_path=config,
        credential_store=store,
    )
    monkeypatch.setattr("js.setup_wizard.click.prompt", lambda *_args, **_kwargs: "tvly-key")

    await wizard._configure_search(non_interactive=False)
    await wizard._save_config()

    persisted = yaml.safe_load(config.read_text(encoding="utf-8"))
    assert "tvly-key" not in config.read_text(encoding="utf-8")
    ref = persisted["search_credential_ref"]
    assert ref["product_id"] == "js-agent"
    loaded = JSSettings.from_file(config, allow_hermes_merge=False)
    object.__setattr__(loaded, "_credential_store", store)
    agent = object.__new__(JSAgent)
    agent.settings = loaded
    manager = JSAgent._setup_search(agent)
    assert any(
        isinstance(engine, TavilyEngine) and engine.api_key == "tvly-key"
        for engine in manager.engines
    )
    await manager.close()


@pytest.mark.asyncio
async def test_setup_wizard_tavily_save_failure_discards_staged_key(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from js.config import JSSettings
    from js.security.provider_credentials import fake_keychain_store
    from js.setup_wizard import SetupWizard

    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
    )
    store, backend = fake_keychain_store()
    wizard = SetupWizard(
        settings=settings,
        config_path=tmp_path / "config.yaml",
        credential_store=store,
    )
    monkeypatch.setattr("js.setup_wizard.click.prompt", lambda *_args, **_kwargs: "tvly-key")
    await wizard._configure_search(non_interactive=False)

    def fail_save(*_args: object, **_kwargs: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(JSSettings, "save", fail_save)
    with pytest.raises(OSError, match="disk full"):
        await wizard._save_config()

    assert backend._store == {}  # noqa: SLF001
    assert settings.search_credential_ref is None


@pytest.mark.asyncio
async def test_setup_wizard_never_uses_tavily_environment_as_authority(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from js.config import JSSettings
    from js.security.provider_credentials import fake_keychain_store
    from js.setup_wizard import SetupWizard

    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
    )
    store, backend = fake_keychain_store()
    wizard = SetupWizard(
        settings=settings,
        config_path=tmp_path / "config.yaml",
        credential_store=store,
    )
    monkeypatch.setenv("TAVILY_API_KEY", "must-not-load")
    monkeypatch.setenv("JS_TAVILY_API_KEY", "must-not-load-either")

    await wizard._configure_search(non_interactive=True)

    assert settings.search_credential_ref is None
    assert backend._store == {}  # noqa: SLF001


@pytest.mark.asyncio
async def test_search_configuration_has_no_cross_step_intent_or_keychain_orphan(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from js.config import JSSettings
    from js.security.provider_credentials import fake_keychain_store
    from js.setup_wizard import SetupWizard

    config = tmp_path / "config.yaml"
    settings = JSSettings(workspace=tmp_path / "workspace", state_dir=tmp_path / "state")
    settings.save(config)
    store, _backend = fake_keychain_store()
    first = SetupWizard(settings=settings, config_path=config, credential_store=store)
    second = SetupWizard(
        settings=JSSettings.from_file(config, allow_hermes_merge=False),
        config_path=config,
        credential_store=store,
    )
    monkeypatch.setattr("js.setup_wizard.click.prompt", lambda *_a, **_k: "first-key")
    await first._configure_search(non_interactive=False)

    assert first._credential_migrator.receipt.recover() is None  # type: ignore[union-attr]
    assert second._credential_migrator.recover_search_credential(config) is None  # type: ignore[union-attr]
    assert _backend._store == {}  # noqa: SLF001

    await first._save_config()

    assert first._credential_migrator.receipt.recover() is None  # type: ignore[union-attr]
    assert len(_backend._store) == 1  # noqa: SLF001
    persisted = JSSettings.from_file(config, allow_hermes_merge=False)
    assert persisted.search_credential_ref == settings.search_credential_ref


def test_bound_personal_config_save_ignores_later_environment_redirect(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from js.config import JSSettings

    bound = tmp_path / "bound.yaml"
    redirected = tmp_path / "redirected.yaml"
    bound.write_text("max_turns: 5\n", encoding="utf-8")
    os.chmod(bound, 0o600)
    settings = JSSettings.from_file(bound, allow_hermes_merge=False)
    monkeypatch.setenv("JS_CONFIG_PATH", str(redirected))
    settings.max_turns = 9

    settings.save()

    assert yaml.safe_load(bound.read_text(encoding="utf-8"))["max_turns"] == 9
    assert not redirected.exists()
