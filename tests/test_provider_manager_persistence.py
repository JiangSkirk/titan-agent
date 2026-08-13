from __future__ import annotations

import json
from pathlib import Path

import pytest

from js.config import ModelConfig, ModelProviderConfig
from js.models.provider_manager import ProviderManager, ProviderManagerError
from js.provider_credential_types import ProviderCredentialRefV1
from js.security.provider_credentials import (
    CredentialStoreFailed,
    FakeKeychainBackend,
    ProviderCredentialStore,
    fake_keychain_store,
)


def _provider(name: str, *, api_key: str = "") -> ModelProviderConfig:
    return ModelProviderConfig(
        name=name,
        base_url=f"https://{name}.example/v1",
        api_key=api_key,
        default_model="model-a",
        models=[ModelConfig(id="model-a", name="Model A", provider=name)],
    )


def _make_manager(state_dir: Path, store=None):
    if store is None:
        store, _ = fake_keychain_store()
    return ProviderManager(state_dir, store, product_id="js-agent"), store


def _put_static_secret(
    store: ProviderCredentialStore,
    secret: str,
) -> ProviderCredentialRefV1:
    return store.put_verified("js-agent", "model_provider", secret)


def _provider_store_document(state_dir: Path) -> dict[str, object]:
    return json.loads((state_dir / "providers.json").read_text(encoding="utf-8"))


def test_stale_provider_manager_instance_merges_instead_of_losing_updates(
    tmp_path: Path,
) -> None:
    store, _ = fake_keychain_store()
    first = ProviderManager(tmp_path / "state", store, product_id="js-agent")
    stale = ProviderManager(tmp_path / "state", store, product_id="js-agent")

    first.add(_provider("first"))
    stale.add(_provider("second"))

    reloaded = ProviderManager(tmp_path / "state", store, product_id="js-agent")
    assert {provider.name for provider in reloaded.get_all()} == {"first", "second"}


def test_provider_save_is_atomic_and_does_not_publish_partial_state(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    store, _ = fake_keychain_store()
    manager = ProviderManager(tmp_path / "state", store, product_id="js-agent")
    manager.add(_provider("stable"))
    before = (tmp_path / "state" / "providers.json").read_bytes()

    def fail_write(*_args: object, **_kwargs: object) -> None:
        raise ProviderManagerError("simulated replace failure")

    monkeypatch.setattr(manager, "_atomic_write_unlocked", fail_write, raising=False)

    with pytest.raises(ProviderManagerError):
        manager.add(_provider("partial"))

    assert (tmp_path / "state" / "providers.json").read_bytes() == before
    assert [provider.name for provider in manager.get_all()] == ["stable"]


def test_provider_api_key_is_encrypted_and_can_be_cleared(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    store, _ = fake_keychain_store()
    manager = ProviderManager(state_dir, store, product_id="js-agent")
    manager.add(_provider("secret-provider", api_key="provider-super-secret"))

    serialized = (state_dir / "providers.json").read_text(encoding="utf-8")
    assert "provider-super-secret" not in serialized
    assert ProviderManager(state_dir, store, product_id="js-agent").get(
        "secret-provider"
    ).api_key == "provider-super-secret"

    assert manager.update_api_key("secret-provider", "") is True
    assert ProviderManager(state_dir, store, product_id="js-agent").get(
        "secret-provider"
    ).api_key in {None, ""}


def test_legacy_nonempty_provider_store_requires_explicit_migration(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    legacy = _provider("legacy").model_dump(
        mode="json",
        exclude={"api_key", "api_key_env", "credential_ref"},
    )
    (state_dir / "providers.json").write_text(
        json.dumps({"providers": [legacy]}),
        encoding="utf-8",
    )
    store, _ = fake_keychain_store()

    with pytest.raises(ProviderManagerError, match="migration"):
        ProviderManager(state_dir, store, product_id="js-agent")

    assert (state_dir / "providers.json").exists()
    assert list(state_dir.glob("providers.corrupt-*.json")) == []


def test_stale_remove_deletes_current_persisted_reference(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    store, _ = fake_keychain_store()
    writer = ProviderManager(state_dir, store, product_id="js-agent")
    stale = ProviderManager(state_dir, store, product_id="js-agent")
    writer.add(_provider("later", api_key="later-secret"))
    persisted = json.loads((state_dir / "providers.json").read_text(encoding="utf-8"))
    ref = ProviderCredentialRefV1.model_validate(
        persisted["providers"][0]["credential_ref"]
    )

    assert stale.remove("later") is True
    assert ProviderManager(state_dir, store, product_id="js-agent").get("later") is None
    assert store.get(ref) is None


class _FailDeleteOnceBackend(FakeKeychainBackend):
    fail_next_delete = False

    def delete(self, service: str, account: str) -> bool:
        if self.fail_next_delete:
            self.fail_next_delete = False
            raise CredentialStoreFailed("injected keychain delete failure")
        return super().delete(service, account)


def test_failed_publish_and_failed_cleanup_recover_unpublished_keychain_item(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    backend = _FailDeleteOnceBackend()
    store = ProviderCredentialStore(backend, "js-agent")
    manager = ProviderManager(state_dir, store, product_id="js-agent")
    manager.add(_provider("stable", api_key="old-secret"))
    before = json.loads((state_dir / "providers.json").read_text(encoding="utf-8"))
    old_ref = before["providers"][0]["credential_ref"]
    original_write = manager._atomic_write_unlocked
    writes = 0

    def fail_second_write(*args, **kwargs) -> None:
        nonlocal writes
        writes += 1
        if writes == 2:
            backend.fail_next_delete = True
            raise ProviderManagerError("injected final publication failure")
        original_write(*args, **kwargs)

    monkeypatch.setattr(manager, "_atomic_write_unlocked", fail_second_write)
    with pytest.raises(ProviderManagerError):
        manager.update_api_key("stable", "unpublished-secret")

    persisted = json.loads((state_dir / "providers.json").read_text(encoding="utf-8"))
    assert persisted["providers"][0]["credential_ref"] == old_ref
    assert persisted["staging_refs"]
    assert len(backend._store) == 2  # noqa: SLF001 - in-memory test backend only

    with pytest.raises(ProviderManagerError, match="cleanup"):
        ProviderManager(state_dir, store, product_id="js-agent")

    restarted = ProviderManager(state_dir, store, product_id="js-agent")
    assert restarted.get("stable").api_key == "old-secret"  # type: ignore[union-attr]
    assert len(backend._store) == 1  # noqa: SLF001 - in-memory test backend only
    recovered = json.loads((state_dir / "providers.json").read_text(encoding="utf-8"))
    assert recovered["staging_refs"] == []


def test_dynamic_remove_delete_failure_keeps_pending_until_restart(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    backend = _FailDeleteOnceBackend()
    store = ProviderCredentialStore(backend, "js-agent")
    manager = ProviderManager(state_dir, store, product_id="js-agent")
    manager.add(_provider("remove-me", api_key="retire-on-restart"))
    document = _provider_store_document(state_dir)
    ref = ProviderCredentialRefV1.model_validate(
        document["providers"][0]["credential_ref"]  # type: ignore[index]
    )

    backend.fail_next_delete = True
    with pytest.raises(ProviderManagerError, match="cleanup requires recovery"):
        manager.remove("remove-me")

    published = _provider_store_document(state_dir)
    assert published["providers"] == []
    assert published["pending_delete"] == [ref.model_dump(mode="json")]
    assert store.require(ref, expected_kind="model_provider") == "retire-on-restart"

    restarted = ProviderManager(state_dir, store, product_id="js-agent")
    assert restarted.get("remove-me") is None
    assert store.get(ref, expected_kind="model_provider") is None
    recovered = _provider_store_document(state_dir)
    assert recovered["pending_delete"] == []


def test_dynamic_remove_final_journal_failure_is_idempotent_after_key_deleted(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    store, _backend = fake_keychain_store()
    manager = ProviderManager(state_dir, store, product_id="js-agent")
    manager.add(_provider("remove-me", api_key="delete-before-final-publish"))
    document = _provider_store_document(state_dir)
    ref = ProviderCredentialRefV1.model_validate(
        document["providers"][0]["credential_ref"]  # type: ignore[index]
    )
    original_write = manager._atomic_write_unlocked
    writes = 0

    def fail_final_write(
        providers: list[ModelProviderConfig],
        pending_delete: list[ProviderCredentialRefV1] | None = None,
        staging_refs: list[ProviderCredentialRefV1] | None = None,
    ) -> None:
        nonlocal writes
        writes += 1
        if writes == 2:
            raise ProviderManagerError("injected final journal publication failure")
        original_write(providers, pending_delete, staging_refs)

    monkeypatch.setattr(manager, "_atomic_write_unlocked", fail_final_write)
    with pytest.raises(ProviderManagerError, match="cleanup requires recovery"):
        manager.remove("remove-me")

    published = _provider_store_document(state_dir)
    assert published["providers"] == []
    assert published["pending_delete"] == [ref.model_dump(mode="json")]
    assert store.get(ref, expected_kind="model_provider") is None

    restarted = ProviderManager(state_dir, store, product_id="js-agent")
    assert restarted.get("remove-me") is None
    assert store.get(ref, expected_kind="model_provider") is None
    recovered = _provider_store_document(state_dir)
    assert recovered["pending_delete"] == []


def test_static_credential_rotation_commits_new_ref_and_restart_hydrates_it(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    store, _backend = fake_keychain_store()
    old_ref = _put_static_secret(store, "old-static-secret")
    manager = ProviderManager(
        state_dir,
        store,
        product_id="js-agent",
        protected_refs=[old_ref],
    )

    new_ref = manager.begin_static_credential_transition(
        old_ref=old_ref,
        new_secret="new-static-secret",
    )
    assert new_ref is not None
    manager.resolve_static_credential_transition(
        old_ref=old_ref,
        new_ref=new_ref,
        published_ref=new_ref,
    )

    assert store.get(old_ref, expected_kind="model_provider") is None
    assert store.require(new_ref, expected_kind="model_provider") == "new-static-secret"
    document = _provider_store_document(state_dir)
    assert document["pending_delete"] == []
    assert document["staging_refs"] == []
    restarted = ProviderManager(
        state_dir,
        store,
        product_id="js-agent",
        protected_refs=[new_ref],
    )
    static = _provider("static")
    static.credential_ref = new_ref
    from js.models.provider_manager import hydrate_static_provider_api_keys

    hydrate_static_provider_api_keys([static], store)
    assert static.api_key == "new-static-secret"
    assert restarted.get_all() == []


def test_static_rotation_crash_after_external_publish_converges_on_restart(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    store, _backend = fake_keychain_store()
    old_ref = _put_static_secret(store, "old-static-secret")
    manager = ProviderManager(
        state_dir,
        store,
        product_id="js-agent",
        protected_refs=[old_ref],
    )
    new_ref = manager.begin_static_credential_transition(
        old_ref=old_ref,
        new_secret="new-static-secret",
    )
    assert new_ref is not None

    restarted = ProviderManager(
        state_dir,
        store,
        product_id="js-agent",
        protected_refs=[new_ref],
    )

    assert restarted.get_all() == []
    assert store.get(old_ref, expected_kind="model_provider") is None
    assert store.require(new_ref, expected_kind="model_provider") == "new-static-secret"
    document = _provider_store_document(state_dir)
    assert document["pending_delete"] == []
    assert document["staging_refs"] == []


def test_static_rotation_crash_before_external_publish_keeps_old_ref(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    store, _backend = fake_keychain_store()
    old_ref = _put_static_secret(store, "old-static-secret")
    manager = ProviderManager(
        state_dir,
        store,
        product_id="js-agent",
        protected_refs=[old_ref],
    )
    new_ref = manager.begin_static_credential_transition(
        old_ref=old_ref,
        new_secret="unpublished-static-secret",
    )
    assert new_ref is not None

    restarted = ProviderManager(
        state_dir,
        store,
        product_id="js-agent",
        protected_refs=[old_ref],
    )

    assert restarted.get_all() == []
    assert store.require(old_ref, expected_kind="model_provider") == "old-static-secret"
    assert store.get(new_ref, expected_kind="model_provider") is None


def test_static_delete_crash_after_external_publish_deletes_old_ref(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    store, _backend = fake_keychain_store()
    old_ref = _put_static_secret(store, "old-static-secret")
    manager = ProviderManager(
        state_dir,
        store,
        product_id="js-agent",
        protected_refs=[old_ref],
    )
    assert (
        manager.begin_static_credential_transition(
            old_ref=old_ref,
            new_secret=None,
        )
        is None
    )

    restarted = ProviderManager(
        state_dir,
        store,
        product_id="js-agent",
        protected_refs=[],
    )

    assert restarted.get_all() == []
    assert store.get(old_ref, expected_kind="model_provider") is None


def test_discard_rejects_non_staging_and_protected_refs(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    store, _backend = fake_keychain_store()
    protected_ref = _put_static_secret(store, "protected-static-secret")
    unrelated_ref = _put_static_secret(store, "unrelated-static-secret")
    manager = ProviderManager(
        state_dir,
        store,
        product_id="js-agent",
        protected_refs=[protected_ref],
    )

    with pytest.raises(ProviderManagerError, match="staging intent"):
        manager.discard_staged_credential(protected_ref)
    with pytest.raises(ProviderManagerError, match="staging intent"):
        manager.discard_staged_credential(unrelated_ref)

    assert store.require(protected_ref, expected_kind="model_provider") == (
        "protected-static-secret"
    )
    assert store.require(unrelated_ref, expected_kind="model_provider") == (
        "unrelated-static-secret"
    )


def test_legacy_split_transition_cannot_delete_an_outstanding_staged_ref(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    store, _backend = fake_keychain_store()
    old_ref = _put_static_secret(store, "old-static-secret")
    manager = ProviderManager(
        state_dir,
        store,
        product_id="js-agent",
        protected_refs=[old_ref],
    )
    new_ref = manager.stage_credential("new-static-secret")

    with pytest.raises(ProviderManagerError, match="restart"):
        manager.prepare_retire_credential(old_ref)

    assert store.require(old_ref, expected_kind="model_provider") == "old-static-secret"
    assert store.require(new_ref, expected_kind="model_provider") == "new-static-secret"
    document = _provider_store_document(state_dir)
    assert document["pending_delete"] == []
    assert document["staging_refs"] == [new_ref.model_dump(mode="json")]


def test_reserved_static_provider_name_cannot_be_added_dynamically(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    store, _backend = fake_keychain_store()
    manager = ProviderManager(
        state_dir,
        store,
        product_id="js-agent",
        reserved_names={"static-provider"},
    )

    with pytest.raises(ProviderManagerError, match="reserved"):
        manager.add(_provider("static-provider", api_key="shadow-secret"))

    assert manager.get_all() == []
    assert not (state_dir / "providers.json").exists()


def test_existing_dynamic_provider_shadowing_reserved_static_name_fails_closed(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    store, _backend = fake_keychain_store()
    legacy_manager = ProviderManager(state_dir, store, product_id="js-agent")
    legacy_manager.add(_provider("static-provider", api_key="shadow-secret"))
    before = (state_dir / "providers.json").read_bytes()

    with pytest.raises(ProviderManagerError, match="reserved"):
        ProviderManager(
            state_dir,
            store,
            product_id="js-agent",
            reserved_names={"static-provider"},
        )

    assert (state_dir / "providers.json").read_bytes() == before
    assert legacy_manager.get("static-provider") is not None
