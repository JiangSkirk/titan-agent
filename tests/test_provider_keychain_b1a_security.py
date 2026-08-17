"""Security regression tests for the B1A provider credential boundary.

These tests use only temporary directories and the in-memory Keychain backend.
They never access the developer's real Keychain or user configuration.
"""

from __future__ import annotations

import hmac
import importlib
import json
import logging
from pathlib import Path

import pytest
from pydantic import ValidationError

from js.config import JSSettings, ModelConfig, ModelProviderConfig
from js.models.provider_manager import (
    ProviderManager,
    ProviderManagerError,
    hydrate_provider_credentials,
)
from js.models.providers import OpenAICompatibleProvider
from js.security.provider_credentials import (
    CredentialAccessDenied,
    CredentialBackendUnavailable,
    CredentialError,
    CredentialLocked,
    CredentialStoreFailed,
    FakeKeychainBackend,
    MacOSKeychainBackend,
    ProviderCredentialRefV1,
    ProviderCredentialStore,
    fake_keychain_store,
)


def _provider(name: str, key: str) -> ModelProviderConfig:
    return ModelProviderConfig(
        name=name,
        base_url="https://provider.example/v1",
        api_key=key,
        default_model="model-a",
        models=[ModelConfig(id="model-a", provider=name)],
    )


def _persisted_ref(state_dir: Path, name: str) -> dict[str, str]:
    payload = json.loads((state_dir / "providers.json").read_text(encoding="utf-8"))
    provider = next(item for item in payload["providers"] if item["name"] == name)
    return dict(provider["credential_ref"])


def test_credential_ref_is_strict_closed_and_frozen() -> None:
    with pytest.raises(ValidationError):
        ProviderCredentialRefV1(
            ref_id="a" * 32,
            product_id="js-agent",
            kind="model_provider",
            unexpected="must-not-be-ignored",
        )
    with pytest.raises(ValidationError):
        ProviderCredentialRefV1(
            ref_id="not-hex-not-hex-not-hex-not-hex-",
            product_id="js-agent",
            kind="model_provider",
        )
    with pytest.raises(ValidationError):
        ProviderCredentialRefV1(
            ref_id="a" * 32,
            product_id="evil-product",
            kind="model_provider",
        )
    ref = ProviderCredentialRefV1(
        ref_id="a" * 32,
        product_id="js-agent",
        kind="model_provider",
    )
    with pytest.raises(ValidationError):
        ref.kind = "search_provider"  # type: ignore[misc]


def test_personal_hydration_rejects_complete_work_ref_before_backend_read() -> None:
    backend = FakeKeychainBackend()
    work_store = ProviderCredentialStore(backend, "js-work")
    work_ref = work_store.put_verified("js-work", "model_provider", "work-secret")
    provider = ModelProviderConfig(
        name="copied-work-ref",
        base_url="https://provider.example/v1",
        credential_ref=work_ref.model_dump(),
    )

    with pytest.raises(CredentialError):
        hydrate_provider_credentials([provider], work_store, product_id="js-agent")
    assert provider.api_key is None


def test_model_hydration_rejects_search_ref() -> None:
    store, _ = fake_keychain_store()
    search_ref = store.put_verified("js-agent", "search_provider", "search-secret")
    provider = ModelProviderConfig(
        name="wrong-kind",
        base_url="https://provider.example/v1",
        credential_ref=search_ref.model_dump(),
    )

    with pytest.raises(CredentialError):
        hydrate_provider_credentials([provider], store, product_id="js-agent")
    assert provider.api_key is None


def test_provider_manager_publish_failure_preserves_old_ref_and_key(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    store, _ = fake_keychain_store()
    state_dir = tmp_path / "state"
    manager = ProviderManager(state_dir, store, product_id="js-agent")
    manager.add(_provider("stable", "old-secret"))
    old_ref = _persisted_ref(state_dir, "stable")

    def fail_publish(*_args: object, **_kwargs: object) -> None:
        raise ProviderManagerError("injected publish failure")

    monkeypatch.setattr(manager, "_atomic_write_unlocked", fail_publish)
    with pytest.raises(ProviderManagerError):
        manager.update_api_key("stable", "new-secret")

    assert _persisted_ref(state_dir, "stable") == old_ref
    restarted = ProviderManager(state_dir, store, product_id="js-agent")
    loaded = restarted.get("stable")
    assert loaded is not None
    assert loaded.api_key == "old-secret"


def test_adding_unrelated_provider_does_not_rotate_existing_ref(tmp_path: Path) -> None:
    store, _ = fake_keychain_store()
    state_dir = tmp_path / "state"
    manager = ProviderManager(state_dir, store, product_id="js-agent")
    manager.add(_provider("first", "first-secret"))
    first_ref = _persisted_ref(state_dir, "first")

    manager.add(_provider("second", "second-secret"))

    assert _persisted_ref(state_dir, "first") == first_ref
    restarted = ProviderManager(state_dir, store, product_id="js-agent")
    assert restarted.get("first").api_key == "first-secret"  # type: ignore[union-attr]
    assert restarted.get("second").api_key == "second-secret"  # type: ignore[union-attr]


def test_provider_manager_without_credential_store_rejects_secret(tmp_path: Path) -> None:
    manager = ProviderManager(tmp_path / "state", None, product_id="js-agent")
    with pytest.raises(ProviderManagerError):
        manager.add(_provider("unsafe", "must-not-be-dropped"))
    assert not (tmp_path / "state" / "providers.json").exists()


def test_file_loaded_plaintext_provider_key_is_not_runtime_authority(tmp_path: Path) -> None:
    config = tmp_path / "config.yaml"
    config.write_text(
        "\n".join(
            [
                f"workspace: {tmp_path / 'workspace'}",
                f"state_dir: {tmp_path / 'state'}",
                "providers:",
                "  - name: legacy",
                "    base_url: https://provider.example/v1",
                "    api_key: plaintext-must-migrate",
                "    default_model: model-a",
                "    models:",
                "      - id: model-a",
                "        provider: legacy",
            ]
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="credential migration"):
        JSSettings.from_file(config)


@pytest.mark.asyncio
async def test_provider_initialization_log_never_discloses_key_fingerprint(
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import js.models.providers as providers_module

    secret = "B1AL-secret-material-tail"
    test_logger = logging.getLogger("test.b1a.provider-init")
    monkeypatch.setattr("js.models.providers.logger", test_logger)
    config = _provider("safe-log", secret)
    config.transport_type = "anthropic"

    def fail_transport(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError(f"transport rejected credential {secret}")

    monkeypatch.setattr(providers_module, "_transport_available", True)
    monkeypatch.setattr(providers_module, "get_transport", fail_transport, raising=False)
    monkeypatch.setattr(
        providers_module,
        "ChatCompletionsTransport",
        lambda: object(),
        raising=False,
    )

    with caplog.at_level(logging.INFO, logger=test_logger.name):
        provider = OpenAICompatibleProvider(config)
    await provider.close()

    assert "<configured>" in caplog.text
    assert secret not in caplog.text
    assert secret[:4] not in caplog.text
    assert secret[-4:] not in caplog.text
    assert "exception=RuntimeError" in caplog.text


class _FakeObjC:
    NULL = object()


class _FakeSecurity:
    kSecClass = "class"  # noqa: N815 - mirrors Security.framework
    kSecClassGenericPassword = "generic"  # noqa: N815 - mirrors Security.framework
    kSecAttrService = "service"  # noqa: N815 - mirrors Security.framework
    kSecAttrAccount = "account"  # noqa: N815 - mirrors Security.framework
    kSecValueData = "data"  # noqa: N815 - mirrors Security.framework
    kSecAttrAccessible = "accessible"  # noqa: N815 - mirrors Security.framework
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly = "device-only"  # noqa: N815
    kSecAttrSynchronizable = "sync"  # noqa: N815 - mirrors Security.framework
    kSecMatchLimit = "limit"  # noqa: N815 - mirrors Security.framework
    kSecMatchLimitOne = "one"  # noqa: N815 - mirrors Security.framework
    kSecReturnData = "return-data"  # noqa: N815 - mirrors Security.framework
    errSecSuccess = 0  # noqa: N815 - mirrors Security.framework
    errSecDuplicateItem = -25299  # noqa: N815 - mirrors Security.framework
    errSecItemNotFound = -25300  # noqa: N815 - mirrors Security.framework
    errSecAuthFailed = -25293  # noqa: N815 - mirrors Security.framework
    errSecInteractionNotAllowed = -25308  # noqa: N815 - mirrors Security.framework
    errSecNotAvailable = -25291  # noqa: N815 - mirrors Security.framework
    errSecNoAccessForItem = -25243  # noqa: N815 - mirrors Security.framework
    errSecInteractionRequired = -25315  # noqa: N815 - mirrors Security.framework
    errSecServiceNotAvailable = -67585  # noqa: N815 - mirrors Security.framework

    def __init__(self) -> None:
        self.items: dict[tuple[str, str], bytes] = {}
        self.add_shape: object | None = None
        self.copy_shape: object | None = None
        self.last_add_out: object | None = None
        self.last_copy_out: object | None = None
        self.add_queries: list[dict[str, object]] = []
        self.update_calls: list[
            tuple[dict[str, object], dict[str, object]]
        ] = []
        self.copy_queries: list[dict[str, object]] = []
        self.delete_queries: list[dict[str, object]] = []

    def SecItemAdd(self, query: dict[str, object], out: object) -> object:  # noqa: N802
        self.last_add_out = out
        self.add_queries.append(dict(query))
        if self.add_shape is not None:
            return self.add_shape
        key = (str(query[self.kSecAttrService]), str(query[self.kSecAttrAccount]))
        if key in self.items:
            return self.errSecDuplicateItem, out
        self.items[key] = bytes(query[self.kSecValueData])  # type: ignore[arg-type]
        return self.errSecSuccess, out

    def SecItemUpdate(  # noqa: N802
        self,
        query: dict[str, object],
        updates: dict[str, object],
    ) -> int:
        self.update_calls.append((dict(query), dict(updates)))
        key = (str(query[self.kSecAttrService]), str(query[self.kSecAttrAccount]))
        self.items[key] = bytes(updates[self.kSecValueData])  # type: ignore[arg-type]
        return self.errSecSuccess

    def SecItemCopyMatching(  # noqa: N802
        self,
        query: dict[str, object],
        out: object,
    ) -> object:
        self.last_copy_out = out
        self.copy_queries.append(dict(query))
        if self.copy_shape is not None:
            return self.copy_shape
        key = (str(query[self.kSecAttrService]), str(query[self.kSecAttrAccount]))
        if key not in self.items:
            return self.errSecItemNotFound, None
        return self.errSecSuccess, self.items[key]

    def SecItemDelete(self, query: dict[str, object]) -> int:  # noqa: N802
        self.delete_queries.append(dict(query))
        key = (str(query[self.kSecAttrService]), str(query[self.kSecAttrAccount]))
        if key not in self.items:
            return self.errSecItemNotFound
        del self.items[key]
        return self.errSecSuccess


def test_pyobjc_bridge_uses_exact_out_parameter_contract() -> None:
    security = _FakeSecurity()
    backend = MacOSKeychainBackend(security, _FakeObjC)

    backend.store("service", "account", b"secret")
    assert backend.retrieve("service", "account") == b"secret"
    assert security.last_add_out is _FakeObjC.NULL
    assert security.last_copy_out is None


def test_pyobjc_duplicate_item_updates_same_non_synchronizable_account() -> None:
    security = _FakeSecurity()
    backend = MacOSKeychainBackend(security, _FakeObjC)

    backend.store("fixed-service", "fixed-account", b"old-secret")
    backend.store("fixed-service", "fixed-account", b"new-secret")

    assert backend.retrieve("fixed-service", "fixed-account") == b"new-secret"
    assert len(security.update_calls) == 1
    selector, updates = security.update_calls[0]
    assert selector == {
        security.kSecClass: security.kSecClassGenericPassword,
        security.kSecAttrService: "fixed-service",
        security.kSecAttrAccount: "fixed-account",
        security.kSecAttrSynchronizable: False,
    }
    assert updates == {
        security.kSecValueData: b"new-secret",
        security.kSecAttrAccessible: (
            security.kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ),
    }
    assert security.add_queries[-1][security.kSecAttrAccessible] == (
        security.kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    )
    assert security.add_queries[-1][security.kSecAttrSynchronizable] is False
    assert security.copy_queries[-1][security.kSecMatchLimit] == (
        security.kSecMatchLimitOne
    )
    assert security.copy_queries[-1][security.kSecAttrSynchronizable] is False


def test_store_uses_fixed_service_and_versioned_product_kind_ref_account(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = FakeKeychainBackend()
    store = ProviderCredentialStore(backend, "js-work")
    ref = ProviderCredentialRefV1(
        ref_id="4" * 32,
        product_id="js-work",
        kind="search_provider",
    )
    compared: list[tuple[bytes, bytes]] = []
    real_compare = hmac.compare_digest

    def recording_compare(left: bytes, right: bytes) -> bool:
        compared.append((left, right))
        return real_compare(left, right)

    monkeypatch.setattr(hmac, "compare_digest", recording_compare)
    store.put_ref_verified(ref, "schema-secret")

    expected_key = (
        "com.titan.js-agent.provider-credentials.v1",
        "v1:js-work:search_provider:" + "4" * 32,
    )
    assert backend._store == {expected_key: b"schema-secret"}  # noqa: SLF001
    assert compared == [(b"schema-secret", b"schema-secret")]


def test_pyobjc_import_missing_is_deterministic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    imported: list[str] = []

    def missing_bridge(name: str) -> object:
        imported.append(name)
        if name == "objc":
            return _FakeObjC
        raise ImportError("deterministic missing Security bridge")

    monkeypatch.setattr(importlib, "import_module", missing_bridge)
    with pytest.raises(
        CredentialBackendUnavailable,
        match="keychain_backend_unavailable",
    ):
        MacOSKeychainBackend()
    assert imported == ["objc", "Security"]


def test_pyobjc_bridge_rejects_scalar_for_out_parameter_call() -> None:
    security = _FakeSecurity()
    security.add_shape = security.errSecSuccess
    backend = MacOSKeychainBackend(security, _FakeObjC)

    with pytest.raises(CredentialStoreFailed, match="bridge"):
        backend.store("service", "account", b"secret")


def test_pyobjc_bridge_rejects_scalar_copy_and_tuple_status_calls() -> None:
    security = _FakeSecurity()
    backend = MacOSKeychainBackend(security, _FakeObjC)
    security.copy_shape = security.errSecSuccess
    with pytest.raises(CredentialStoreFailed, match="bridge"):
        backend.retrieve("service", "account")

    security.copy_shape = None
    security.items[("service", "account")] = b"secret"
    original_delete = security.SecItemDelete
    security.SecItemDelete = lambda _query: (security.errSecSuccess, None)  # type: ignore[method-assign]
    with pytest.raises(CredentialStoreFailed, match="bridge"):
        backend.delete("service", "account")
    security.SecItemDelete = original_delete  # type: ignore[method-assign]


@pytest.mark.parametrize("invalid_result", [None, b"", b"x" * 8193, object()])
def test_pyobjc_bridge_rejects_invalid_keychain_data(invalid_result: object) -> None:
    security = _FakeSecurity()
    security.copy_shape = (security.errSecSuccess, invalid_result)
    backend = MacOSKeychainBackend(security, _FakeObjC)

    with pytest.raises(CredentialStoreFailed, match="data"):
        backend.retrieve("service", "account")


@pytest.mark.parametrize(
    ("status_name", "expected_error", "message"),
    [
        ("errSecNoAccessForItem", CredentialAccessDenied, "keychain_access_denied"),
        ("errSecInteractionRequired", CredentialLocked, "keychain_locked"),
        (
            "errSecServiceNotAvailable",
            CredentialBackendUnavailable,
            "keychain_backend_unavailable",
        ),
        ("unknown", CredentialStoreFailed, "keychain_operation_failed"),
    ],
)
def test_pyobjc_status_errors_are_closed_and_never_echo_numeric_status(
    status_name: str,
    expected_error: type[CredentialError],
    message: str,
) -> None:
    security = _FakeSecurity()
    status = getattr(security, status_name, -999_999)
    security.copy_shape = (status, None)
    backend = MacOSKeychainBackend(security, _FakeObjC)

    with pytest.raises(expected_error) as captured:
        backend.retrieve("private-service", "private-account")

    assert str(captured.value) == message
    assert str(status) not in str(captured.value)
    assert "private" not in str(captured.value)
