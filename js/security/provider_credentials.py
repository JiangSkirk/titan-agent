"""macOS Keychain authority for Provider credentials.

Only opaque, product-scoped references are persisted.  Secret values never
appear in references, exception messages, logs, subprocess arguments, or
environment variables.  Tests inject :class:`FakeKeychainBackend`; desktop
production constructs :class:`MacOSKeychainBackend` explicitly.
"""

from __future__ import annotations

import hmac
import importlib
import secrets as crypto_secrets
import threading
from typing import Any, Protocol, runtime_checkable

from js.provider_credential_types import (
    CredentialKind,
    ProductId,
    ProviderCredentialRefV1,
)

_KEYCHAIN_SERVICE = "com.titan.js-agent.provider-credentials.v1"
_ACCOUNT_VERSION = "v1"
_MAX_SECRET_BYTES = 8192


class CredentialError(RuntimeError):
    """Closed provider-credential failure with no sensitive context."""


class CredentialStoreError(CredentialError):
    """The Keychain operation failed."""


class CredentialReadbackMismatchError(CredentialError):
    """A write did not round-trip exactly."""


class CredentialNotFoundError(CredentialError):
    """A required Keychain item does not exist."""


class CredentialAccessDeniedError(CredentialError):
    """macOS denied access to the Keychain item."""


class CredentialLockedError(CredentialError):
    """The user's Keychain is locked."""


class CredentialBackendUnavailableError(CredentialError):
    """The required macOS Keychain bridge is unavailable."""


class CredentialScopeMismatchError(CredentialError):
    """A reference does not belong to this product or purpose."""


# Keep the public spellings stable while concrete exception classes follow the
# repository's ``*Error`` naming convention.
CredentialStoreFailed = CredentialStoreError
CredentialReadbackMismatch = CredentialReadbackMismatchError
CredentialNotFound = CredentialNotFoundError
CredentialAccessDenied = CredentialAccessDeniedError
CredentialLocked = CredentialLockedError
CredentialBackendUnavailable = CredentialBackendUnavailableError
CredentialScopeMismatch = CredentialScopeMismatchError


@runtime_checkable
class KeychainBackend(Protocol):
    """Minimal backend used by the product-scoped authority."""

    def store(self, service: str, account: str, secret: bytes) -> None: ...

    def retrieve(self, service: str, account: str) -> bytes | None: ...

    def delete(self, service: str, account: str) -> bool: ...


class FakeKeychainBackend:
    """Thread-safe in-memory backend for tests only."""

    def __init__(self) -> None:
        self._store: dict[tuple[str, str], bytes] = {}
        self._lock = threading.RLock()
        self._locked = False
        self._denied_accounts: set[tuple[str, str]] = set()
        self._mismatch_next = False

    def __deepcopy__(self, memo: dict[int, Any]) -> FakeKeychainBackend:
        return self

    def store(self, service: str, account: str, secret: bytes) -> None:
        with self._lock:
            self._check_access(service, account)
            self._store[(service, account)] = bytes(secret)

    def retrieve(self, service: str, account: str) -> bytes | None:
        with self._lock:
            self._check_access(service, account)
            if self._mismatch_next:
                self._mismatch_next = False
                existing = self._store.get((service, account), b"")
                return crypto_secrets.token_bytes(len(existing))
            return self._store.get((service, account))

    def delete(self, service: str, account: str) -> bool:
        with self._lock:
            self._check_access(service, account)
            return self._store.pop((service, account), None) is not None

    def _check_access(self, service: str, account: str) -> None:
        if self._locked:
            raise CredentialLocked("keychain_locked")
        if (service, account) in self._denied_accounts:
            raise CredentialAccessDenied("keychain_access_denied")

    def set_locked(self, locked: bool) -> None:
        with self._lock:
            self._locked = locked

    def deny_account(self, service: str, account: str) -> None:
        with self._lock:
            self._denied_accounts.add((service, account))

    def trigger_mismatch_next(self) -> None:
        with self._lock:
            self._mismatch_next = True

    def clear(self) -> None:
        with self._lock:
            self._store.clear()
            self._denied_accounts.clear()
            self._locked = False
            self._mismatch_next = False


class MacOSKeychainBackend:
    """Security.framework Generic Password backend via PyObjC.

    ``Security`` and ``objc`` may be injected only by unit tests.  Production
    imports the real bridges and fails closed when they are unavailable.
    """

    def __init__(self, security: Any | None = None, objc_module: Any | None = None) -> None:
        if security is None or objc_module is None:
            try:
                objc = importlib.import_module("objc")
                security_bridge = importlib.import_module("Security")
            except ImportError as exc:
                raise CredentialBackendUnavailable("keychain_backend_unavailable") from exc
            security = security_bridge
            objc_module = objc
        self._security = security
        self._objc = objc_module

    @staticmethod
    def _out_result(raw: Any) -> tuple[int, Any | None]:
        if (
            isinstance(raw, tuple)
            and len(raw) == 2
            and type(raw[0]) is int
        ):
            return raw[0], raw[1]
        raise CredentialStoreFailed("keychain_bridge_invalid_result")

    @staticmethod
    def _status_result(raw: Any) -> int:
        if type(raw) is int:
            return raw
        raise CredentialStoreFailed("keychain_bridge_invalid_result")

    def store(self, service: str, account: str, secret: bytes) -> None:
        security = self._security
        query: dict[Any, Any] = {
            security.kSecClass: security.kSecClassGenericPassword,
            security.kSecAttrService: service,
            security.kSecAttrAccount: account,
            security.kSecValueData: bytes(secret),
            security.kSecAttrAccessible: security.kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            security.kSecAttrSynchronizable: False,
        }
        status, _ = self._out_result(
            security.SecItemAdd(query, self._objc.NULL)
        )
        if status == security.errSecDuplicateItem:
            selector = {
                security.kSecClass: security.kSecClassGenericPassword,
                security.kSecAttrService: service,
                security.kSecAttrAccount: account,
                security.kSecAttrSynchronizable: False,
            }
            updates = {
                security.kSecValueData: bytes(secret),
                security.kSecAttrAccessible: security.kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            }
            status = self._status_result(security.SecItemUpdate(selector, updates))
        self._check_status(status)

    def retrieve(self, service: str, account: str) -> bytes | None:
        security = self._security
        query: dict[Any, Any] = {
            security.kSecClass: security.kSecClassGenericPassword,
            security.kSecAttrService: service,
            security.kSecAttrAccount: account,
            security.kSecMatchLimit: security.kSecMatchLimitOne,
            security.kSecReturnData: True,
            security.kSecAttrSynchronizable: False,
        }
        status, result = self._out_result(
            security.SecItemCopyMatching(query, None)
        )
        if status == security.errSecItemNotFound:
            return None
        self._check_status(status)
        if result is None:
            raise CredentialStoreFailed("keychain_data_invalid")
        try:
            raw = bytes(result)
            if not raw or len(raw) > _MAX_SECRET_BYTES:
                raise ValueError
            return raw
        except (TypeError, ValueError, OverflowError):
            raise CredentialStoreFailed("keychain_data_invalid") from None

    def delete(self, service: str, account: str) -> bool:
        security = self._security
        query: dict[Any, Any] = {
            security.kSecClass: security.kSecClassGenericPassword,
            security.kSecAttrService: service,
            security.kSecAttrAccount: account,
            security.kSecAttrSynchronizable: False,
        }
        status = self._status_result(security.SecItemDelete(query))
        if status == security.errSecItemNotFound:
            return False
        self._check_status(status)
        return True

    def _check_status(self, status: int) -> None:
        security = self._security
        if status == security.errSecSuccess:
            return
        denied_names = (
            "errSecAuthFailed",
            "errSecNoAccessForItem",
            "errSecMissingEntitlement",
            "errSecRestrictedAPI",
            "errSecUserCanceled",
        )
        locked_names = (
            "errSecInteractionNotAllowed",
            "errSecInteractionRequired",
            "errSecInDarkWake",
        )
        unavailable_names = (
            "errSecNotAvailable",
            "errSecServiceNotAvailable",
            "errSecNoDefaultKeychain",
            "errSecNoStorageModule",
            "errSecUnimplemented",
        )
        if any(status == getattr(security, name, object()) for name in denied_names):
            raise CredentialAccessDenied("keychain_access_denied")
        if any(status == getattr(security, name, object()) for name in locked_names):
            raise CredentialLocked("keychain_locked")
        if any(status == getattr(security, name, object()) for name in unavailable_names):
            raise CredentialBackendUnavailable("keychain_backend_unavailable")
        raise CredentialStoreFailed("keychain_operation_failed")


class ProviderCredentialStore:
    """Product-scoped authority over Provider credentials."""

    def __init__(self, backend: KeychainBackend, product_id: ProductId = "js-agent") -> None:
        self._backend = backend
        self._product_id: ProductId = product_id

    def __deepcopy__(self, memo: dict[int, Any]) -> ProviderCredentialStore:
        return self

    @property
    def product_id(self) -> ProductId:
        return self._product_id

    def for_product(self, product_id: ProductId) -> ProviderCredentialStore:
        return ProviderCredentialStore(self._backend, product_id)

    @staticmethod
    def _account(ref: ProviderCredentialRefV1) -> str:
        return f"{_ACCOUNT_VERSION}:{ref.product_id}:{ref.kind}:{ref.ref_id}"

    def _validate_scope(
        self,
        ref: ProviderCredentialRefV1,
        *,
        expected_kind: CredentialKind | None = None,
    ) -> None:
        if ref.product_id != self._product_id:
            raise CredentialScopeMismatch("credential_product_mismatch")
        if expected_kind is not None and ref.kind != expected_kind:
            raise CredentialScopeMismatch("credential_kind_mismatch")

    def put_verified(
        self,
        product_id: ProductId,
        kind: CredentialKind,
        secret: str,
    ) -> ProviderCredentialRefV1:
        """Allocate a reference, write it, and read it back exactly."""
        if product_id != self._product_id:
            raise CredentialScopeMismatch("credential_product_mismatch")
        ref = self.allocate_ref(kind)
        self.put_ref_verified(ref, secret)
        return ref

    def allocate_ref(self, kind: CredentialKind) -> ProviderCredentialRefV1:
        """Allocate a non-secret reference before a caller journals intent."""
        return ProviderCredentialRefV1(
            ref_id=crypto_secrets.token_hex(16),
            product_id=self._product_id,
            kind=kind,
        )

    def put_ref_verified(
        self,
        ref: ProviderCredentialRefV1,
        secret: str,
    ) -> None:
        """Write an already-journaled reference and verify exact readback."""
        self._validate_scope(ref)
        if not isinstance(secret, str) or not secret:
            raise CredentialError("credential_secret_invalid")
        secret_bytes = secret.encode("utf-8")
        if len(secret_bytes) > _MAX_SECRET_BYTES:
            raise CredentialError("credential_secret_invalid")
        account = self._account(ref)
        try:
            self._backend.store(_KEYCHAIN_SERVICE, account, secret_bytes)
            readback = self._backend.retrieve(_KEYCHAIN_SERVICE, account)
            if readback is None or not hmac.compare_digest(readback, secret_bytes):
                raise CredentialReadbackMismatch("keychain_readback_mismatch")
        except CredentialError:
            try:
                self._backend.delete(_KEYCHAIN_SERVICE, account)
            except Exception:
                pass
            raise
        except Exception:
            try:
                self._backend.delete(_KEYCHAIN_SERVICE, account)
            except Exception:
                pass
            raise CredentialStoreFailed("keychain_store_failed") from None

    def get(
        self,
        ref: ProviderCredentialRefV1,
        *,
        expected_kind: CredentialKind | None = None,
    ) -> str | None:
        self._validate_scope(ref, expected_kind=expected_kind)
        try:
            raw = self._backend.retrieve(_KEYCHAIN_SERVICE, self._account(ref))
        except CredentialError:
            raise
        except Exception:
            raise CredentialStoreFailed("keychain_retrieve_failed") from None
        if raw is None:
            return None
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            raise CredentialStoreFailed("keychain_data_invalid") from None

    def require(
        self,
        ref: ProviderCredentialRefV1,
        *,
        expected_kind: CredentialKind,
    ) -> str:
        value = self.get(ref, expected_kind=expected_kind)
        if value is None:
            raise CredentialNotFound("keychain_item_missing")
        return value

    def delete(
        self,
        ref: ProviderCredentialRefV1,
        *,
        expected_kind: CredentialKind | None = None,
    ) -> bool:
        self._validate_scope(ref, expected_kind=expected_kind)
        try:
            return self._backend.delete(_KEYCHAIN_SERVICE, self._account(ref))
        except CredentialError:
            raise
        except Exception:
            raise CredentialStoreFailed("keychain_delete_failed") from None

    def verify(self, ref: ProviderCredentialRefV1) -> bool:
        return self.get(ref) is not None


def required_macos_keychain_store(
    product_id: ProductId = "js-agent",
) -> ProviderCredentialStore:
    return ProviderCredentialStore(MacOSKeychainBackend(), product_id)


def fake_keychain_store(
    product_id: ProductId = "js-agent",
    *,
    backend: FakeKeychainBackend | None = None,
) -> tuple[ProviderCredentialStore, FakeKeychainBackend]:
    resolved = backend or FakeKeychainBackend()
    return ProviderCredentialStore(resolved, product_id), resolved
