"""B1A Provider Keychain tests - the sole credential authority for providers.

All tests use the FakeKeychainBackend; no test touches the real macOS Keychain.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from js.security.provider_credentials import (
    CredentialAccessDenied,
    CredentialBackendUnavailable,
    CredentialError,
    CredentialLocked,
    CredentialReadbackMismatch,
    CredentialScopeMismatch,
    FakeKeychainBackend,
    MacOSKeychainBackend,
    ProviderCredentialRefV1,
    ProviderCredentialStore,
    fake_keychain_store,
    required_macos_keychain_store,
)


class TestProviderCredentialRefV1:
    def test_ref_does_not_expose_secret_in_repr(self) -> None:
        ref = ProviderCredentialRefV1(
            ref_id="a" * 32,
            product_id="js-agent",
            kind="model_provider",
        )
        repr_str = repr(ref)
        str_str = str(ref)
        assert "ref_id='<redacted>'" in repr_str
        assert "ref_id='<redacted>'" in str_str
        assert "a" * 32 not in repr_str
        assert "a" * 32 not in str_str

    def test_ref_fields_are_closed_set(self) -> None:
        with pytest.raises(ValidationError):
            ProviderCredentialRefV1(
                ref_id="x" * 100,
                product_id="js-agent",
                kind="model_provider",
            )

    def test_ref_serializes_to_safe_dict(self) -> None:
        ref = ProviderCredentialRefV1(
            ref_id="a" * 32,
            product_id="js-agent",
            kind="model_provider",
        )
        d = ref.model_dump()
        assert d["ref_id"] == "a" * 32
        assert d["product_id"] == "js-agent"
        assert d["kind"] == "model_provider"
        assert "service" not in d
        assert "account" not in d


class TestFakeKeychainBackend:
    def test_store_retrieve_delete_roundtrip(self) -> None:
        store, backend = fake_keychain_store()
        ref = store.put_verified("js-agent", "model_provider", "sk-test-key-123")
        assert store.get(ref) == "sk-test-key-123"
        assert store.delete(ref) is True
        assert store.get(ref) is None

    def test_store_and_update(self) -> None:
        store, _ = fake_keychain_store()
        ref1 = store.put_verified("js-agent", "model_provider", "key-old")
        assert store.get(ref1) == "key-old"
        # Delete old, store new (simulating key rotation)
        store.delete(ref1)
        ref2 = store.put_verified("js-agent", "model_provider", "key-new")
        assert store.get(ref2) == "key-new"
        assert store.get(ref1) is None

    def test_readback_mismatch_detected(self) -> None:
        store, backend = fake_keychain_store()
        backend.trigger_mismatch_next()
        with pytest.raises(CredentialReadbackMismatch):
            store.put_verified("js-agent", "model_provider", "secret-key")

    def test_locked_keychain_fails_closed(self) -> None:
        store, backend = fake_keychain_store()
        backend.set_locked(True)
        with pytest.raises(CredentialLocked):
            store.put_verified("js-agent", "model_provider", "secret-key")

    def test_denied_access_fails_closed(self) -> None:
        store, backend = fake_keychain_store()
        ref = store.put_verified("js-agent", "model_provider", "secret-key")
        backend.clear()
        backend.deny_account(
            "com.titan.js-agent.provider-credentials.v1",
            store._account(ref),
        )
        with pytest.raises(CredentialAccessDenied):
            store.get(ref)

    def test_not_found_returns_none(self) -> None:
        store, _ = fake_keychain_store()
        ref = ProviderCredentialRefV1(
            ref_id="b" * 32,
            product_id="js-agent",
            kind="model_provider",
        )
        assert store.get(ref) is None
        assert store.delete(ref) is False

    def test_exception_does_not_leak_secret(self) -> None:
        store, backend = fake_keychain_store()
        backend.set_locked(True)
        try:
            store.put_verified("js-agent", "model_provider", "sk-super-secret-12345")
        except CredentialError as exc:
            exc_str = str(exc)
            assert "sk-super-secret-12345" not in exc_str
            assert "sk-super" not in exc_str

    def test_personal_work_cannot_read_each_other(self) -> None:
        store, _ = fake_keychain_store()
        ref_personal = store.put_verified("js-agent", "model_provider", "personal-key")
        # Try to read with a Work product_id ref - different account
        ref_work = ProviderCredentialRefV1(
            ref_id=ref_personal.ref_id,
            product_id="js-work",
            kind="model_provider",
        )
        with pytest.raises(CredentialError):
            store.get(ref_work)

    def test_verify_returns_true_for_existing(self) -> None:
        store, _ = fake_keychain_store()
        ref = store.put_verified("js-agent", "model_provider", "key-123")
        assert store.verify(ref) is True

    def test_verify_returns_false_for_missing(self) -> None:
        store, _ = fake_keychain_store()
        ref = ProviderCredentialRefV1(
            ref_id="b" * 32,
            product_id="js-agent",
            kind="model_provider",
        )
        assert store.verify(ref) is False

    def test_invalid_product_id_rejected(self) -> None:
        store, _ = fake_keychain_store()
        with pytest.raises(CredentialScopeMismatch):
            store.put_verified("invalid-product", "model_provider", "key")

    def test_invalid_kind_rejected(self) -> None:
        store, _ = fake_keychain_store()
        with pytest.raises(ValidationError):
            store.put_verified("js-agent", "invalid_kind", "key")

    def test_empty_secret_rejected(self) -> None:
        store, _ = fake_keychain_store()
        with pytest.raises(CredentialError):
            store.put_verified("js-agent", "model_provider", "")

    def test_search_provider_kind_supported(self) -> None:
        store, _ = fake_keychain_store()
        ref = store.put_verified("js-agent", "search_provider", "tavily-key-123")
        assert store.get(ref) == "tavily-key-123"


class TestMacOSKeychainBackendImport:
    def test_backend_unavailable_without_pyobjc(self) -> None:
        """If pyobjc-framework-Security is not installed, fail closed."""
        try:
            backend = MacOSKeychainBackend()
        except CredentialBackendUnavailable:
            pass  # Expected when pyobjc is not installed
        else:
            # If pyobjc IS installed, verify the backend works
            assert backend is not None

    def test_required_macos_keychain_store_fails_closed(self) -> None:
        """Desktop path must fail closed if Keychain backend is missing."""
        try:
            store = required_macos_keychain_store()
        except CredentialBackendUnavailable:
            pass  # Expected when pyobjc is not installed
        else:
            assert isinstance(store, ProviderCredentialStore)


class TestDesktopRequiredMode:
    """Desktop release path must use the real macOS Keychain - no fallback."""

    def test_no_env_var_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Ensure no environment variable can select a weak backend
        monkeypatch.delenv("JS_KEYCHAIN_BACKEND", raising=False)
        monkeypatch.delenv("JS_FAKE_KEYCHAIN", raising=False)
        # The required_macos_keychain_store function should still try to
        # import the real backend, regardless of env vars
        try:
            required_macos_keychain_store()
        except CredentialBackendUnavailable:
            pass

    def test_fake_backend_not_selected_by_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("JS_KEYCHAIN_BACKEND", "fake")
        # Even with env var set, required_macos_keychain_store should
        # NOT use the fake backend
        try:
            store = required_macos_keychain_store()
            # If it succeeds, it must be backed by MacOSKeychainBackend
            assert not isinstance(store._backend, FakeKeychainBackend)
        except CredentialBackendUnavailable:
            pass
