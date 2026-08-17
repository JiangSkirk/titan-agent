"""Production startup boundaries for provider credential authority."""

from __future__ import annotations

from pathlib import Path

import pytest

from js.agent import JSAgent
from js.config import JSSettings, ModelProviderConfig
from js.security.provider_credentials import CredentialError, fake_keychain_store


def test_agent_rejects_runtime_plaintext_provider_without_store(tmp_path: Path) -> None:
    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        providers=[
            ModelProviderConfig(
                name="raw",
                base_url="https://provider.example/v1",
                api_key="runtime-plaintext",
            )
        ],
    )

    with pytest.raises(CredentialError, match="runtime_plaintext"):
        JSAgent(settings)


@pytest.mark.asyncio
async def test_agent_accepts_opaque_ref_with_explicit_fake_store(tmp_path: Path) -> None:
    store, _backend = fake_keychain_store()
    ref = store.put_verified("js-agent", "model_provider", "keychain-secret")
    settings = JSSettings(
        workspace=tmp_path / "workspace",
        state_dir=tmp_path / "state",
        providers=[
            ModelProviderConfig(
                name="opaque",
                base_url="https://provider.example/v1",
                credential_ref=ref,
            )
        ],
    )
    object.__setattr__(settings, "_credential_store", store)

    agent = JSAgent(settings)
    try:
        assert agent.settings.providers[0].api_key == "keychain-secret"
    finally:
        await agent.close()
