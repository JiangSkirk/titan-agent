"""B1A config tests: ModelProviderConfig credential_ref and api_key_env changes."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from js.config import JSSettings, ModelConfig, ModelProviderConfig
from js.security.provider_credentials import (
    fake_keychain_store,
)


class TestModelProviderConfigCredentialRef:
    def test_provider_and_search_refs_cannot_be_injected_from_environment(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        monkeypatch.setenv(
            "JS_PROVIDERS",
            json.dumps(
                [
                    {
                        "name": "env-provider",
                        "base_url": "https://provider.example/v1",
                        "api_key": "environment-secret",
                    }
                ]
            ),
        )
        monkeypatch.setenv(
            "JS_SEARCH_CREDENTIAL_REF",
            json.dumps(
                {
                    "ref_id": "a" * 32,
                    "product_id": "js-agent",
                    "kind": "search_provider",
                }
            ),
        )
        monkeypatch.setenv("JS_MAX_TURNS", "17")

        settings = JSSettings(
            workspace=tmp_path / "workspace",
            state_dir=tmp_path / "state",
        )

        assert settings.providers == []
        assert settings.search_credential_ref is None
        assert settings.max_turns == 17

    def test_credential_ref_field_exists(self) -> None:
        cfg = ModelProviderConfig(
            name="test",
            base_url="https://test.example/v1",
            credential_ref={
                "ref_id": "a" * 32,
                "product_id": "js-agent",
                "kind": "model_provider",
            },
        )
        assert cfg.credential_ref is not None
        assert cfg.credential_ref.ref_id == "a" * 32

    def test_credential_ref_defaults_to_none(self) -> None:
        cfg = ModelProviderConfig(
            name="test",
            base_url="https://test.example/v1",
        )
        assert cfg.credential_ref is None

    def test_api_key_env_no_longer_resolved(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """B1A: api_key_env must NOT be resolved into api_key."""
        monkeypatch.setenv("TEST_PROVIDER_KEY", "env-secret-key-12345")
        cfg = ModelProviderConfig(
            name="test",
            base_url="https://test.example/v1",
            api_key_env="TEST_PROVIDER_KEY",
        )
        assert cfg.api_key is None
        assert cfg.api_key_env == "TEST_PROVIDER_KEY"

    def test_api_key_not_persisted_to_disk(self, tmp_path: Path) -> None:
        """Config save must not write api_key to YAML."""
        cfg = ModelProviderConfig(
            name="test",
            base_url="https://test.example/v1",
            api_key="sk-super-secret-12345",
            default_model="model-a",
            models=[ModelConfig(id="model-a", provider="test")],
        )
        settings = JSSettings(
            workspace=tmp_path / "workspace",
            state_dir=tmp_path / "state",
            providers=[cfg],
        )
        config_path = tmp_path / "config.yaml"
        settings.save(config_path)
        raw = config_path.read_text()
        assert "sk-super-secret-12345" not in raw

    def test_api_key_env_not_persisted_to_disk(self, tmp_path: Path) -> None:
        """Config save must not write api_key_env to YAML."""
        cfg = ModelProviderConfig(
            name="test",
            base_url="https://test.example/v1",
            api_key_env="TEST_KEY_ENV",
            default_model="model-a",
            models=[ModelConfig(id="model-a", provider="test")],
        )
        settings = JSSettings(
            workspace=tmp_path / "workspace",
            state_dir=tmp_path / "state",
            providers=[cfg],
        )
        config_path = tmp_path / "config.yaml"
        settings.save(config_path)
        raw = config_path.read_text()
        data = yaml.safe_load(raw)
        provider_data = data["providers"][0]
        assert "api_key_env" not in provider_data
        assert "TEST_KEY_ENV" not in raw

    def test_credential_ref_is_persisted_to_disk(self, tmp_path: Path) -> None:
        """Config save must persist credential_ref to YAML."""
        cfg = ModelProviderConfig(
            name="test",
            base_url="https://test.example/v1",
            credential_ref={
                "ref_id": "a" * 32,
                "product_id": "js-agent",
                "kind": "model_provider",
            },
            default_model="model-a",
            models=[ModelConfig(id="model-a", provider="test")],
        )
        settings = JSSettings(
            workspace=tmp_path / "workspace",
            state_dir=tmp_path / "state",
            providers=[cfg],
        )
        config_path = tmp_path / "config.yaml"
        settings.save(config_path)
        raw = config_path.read_text()
        data = yaml.safe_load(raw)
        provider_data = data["providers"][0]
        assert provider_data["credential_ref"]["ref_id"] == "a" * 32
        assert "api_key" not in provider_data
        assert "api_key_env" not in provider_data

    def test_config_load_with_credential_ref(self, tmp_path: Path) -> None:
        """Config loaded from disk should have credential_ref but not api_key."""
        config_path = tmp_path / "config.yaml"
        config_path.write_text(yaml.dump({
            "workspace": str(tmp_path / "workspace"),
            "state_dir": str(tmp_path / "state"),
            "providers": [{
                "name": "test",
                "base_url": "https://test.example/v1",
                "credential_ref": {
                    "ref_id": "a" * 32,
                    "product_id": "js-agent",
                    "kind": "model_provider",
                },
                "default_model": "model-a",
                "models": [{"id": "model-a", "provider": "test"}],
            }],
        }))
        settings = JSSettings.from_file(config_path)
        assert len(settings.providers) == 1
        provider = settings.providers[0]
        assert provider.credential_ref is not None
        assert provider.credential_ref.ref_id == "a" * 32
        assert provider.api_key is None

    def test_provider_with_credential_ref_hydrates_from_keychain(self, tmp_path: Path) -> None:
        """Provider with credential_ref should hydrate api_key from Keychain."""
        from js.models.provider_manager import hydrate_provider_credentials

        store, _ = fake_keychain_store()
        ref = store.put_verified("js-agent", "model_provider", "sk-hydrated-key-12345")
        provider = ModelProviderConfig(
            name="test",
            base_url="https://test.example/v1",
            credential_ref=ref.model_dump(),
        )
        providers = [provider]
        hydrate_provider_credentials(providers, store, product_id="js-agent")
        assert providers[0].api_key == "sk-hydrated-key-12345"

    def test_provider_without_ref_does_not_hydrate(self, tmp_path: Path) -> None:
        """Provider without credential_ref should not attempt hydration."""
        from js.models.provider_manager import hydrate_provider_credentials

        store, _ = fake_keychain_store()
        provider = ModelProviderConfig(
            name="test",
            base_url="https://test.example/v1",
        )
        providers = [provider]
        hydrate_provider_credentials(providers, store, product_id="js-agent")
        assert providers[0].api_key is None

    def test_legacy_api_key_in_config_requires_migration(self, tmp_path: Path) -> None:
        """A persisted plaintext key must never become runtime authority."""
        config_path = tmp_path / "config.yaml"
        config_path.write_text(yaml.dump({
            "workspace": str(tmp_path / "workspace"),
            "state_dir": str(tmp_path / "state"),
            "providers": [{
                "name": "test",
                "base_url": "https://test.example/v1",
                "api_key": "sk-legacy-key-12345",
                "default_model": "model-a",
                "models": [{"id": "model-a", "provider": "test"}],
            }],
        }))
        with pytest.raises(ValueError, match="credential migration"):
            JSSettings.from_file(config_path)

    def test_provider_manager_uses_keychain(self, tmp_path: Path) -> None:
        """ProviderManager should store and retrieve keys via Keychain."""
        from js.models.provider_manager import ProviderManager

        store, _ = fake_keychain_store()
        state_dir = tmp_path / "state"
        manager = ProviderManager(state_dir, store, product_id="js-agent")

        provider = ModelProviderConfig(
            name="test-provider",
            base_url="https://test.example/v1",
            api_key="sk-dynamic-key-12345",
            default_model="model-a",
            models=[ModelConfig(id="model-a", provider="test-provider")],
        )
        manager.add(provider)

        # Key should not be in providers.json
        raw = (state_dir / "providers.json").read_text()
        assert "sk-dynamic-key-12345" not in raw

        # Key should be retrievable via Keychain
        reloaded = ProviderManager(state_dir, store, product_id="js-agent")
        result = reloaded.get("test-provider")
        assert result is not None
        assert result.api_key == "sk-dynamic-key-12345"
        assert result.credential_ref is not None

    def test_provider_manager_clears_key(self, tmp_path: Path) -> None:
        """ProviderManager update_api_key('') should clear the key."""
        from js.models.provider_manager import ProviderManager

        store, _ = fake_keychain_store()
        state_dir = tmp_path / "state"
        manager = ProviderManager(state_dir, store, product_id="js-agent")

        provider = ModelProviderConfig(
            name="test-provider",
            base_url="https://test.example/v1",
            api_key="sk-dynamic-key-12345",
            default_model="model-a",
            models=[ModelConfig(id="model-a", provider="test-provider")],
        )
        manager.add(provider)
        assert manager.update_api_key("test-provider", "") is True

        reloaded = ProviderManager(state_dir, store, product_id="js-agent")
        result = reloaded.get("test-provider")
        assert result is not None
        assert result.api_key in {None, ""}
