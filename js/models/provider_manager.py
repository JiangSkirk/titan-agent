"""Dynamic provider management with persistent storage."""

from __future__ import annotations

import importlib
import json
import os
import stat
import tempfile
import threading
import time
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from js.config import ModelProviderConfig
from js.provider_credential_types import ProductId, ProviderCredentialRefV1
from js.security.provider_credentials import (
    CredentialError,
    ProviderCredentialStore,
)
from js.utils.log import get_logger

logger = get_logger("js.models.provider_manager")


def _secret_key_name(provider_name: str) -> str:
    """Generate the legacy SecretManager key name for a provider's API key.

    Used only during B1A migration; new credentials go through the Keychain.
    """
    return f"provider_apikey_{provider_name}"


def static_provider_secret_key_name(provider_name: str) -> str:
    """Return the legacy secret name used by file-configured providers.

    Used only during B1A migration.
    """
    return f"static_provider_apikey_{provider_name}"


def hydrate_provider_credentials(
    providers: list[ModelProviderConfig],
    credential_store: ProviderCredentialStore,
    product_id: ProductId = "js-agent",
) -> None:
    """Restore API keys from the Keychain before router construction.

    B1A: replaces the old ``hydrate_static_provider_api_keys`` which used
    SecretManager.  Providers with a ``credential_ref`` are hydrated from
    the Keychain; providers without a ref are left unchanged.
    """
    if credential_store.product_id != product_id:
        raise CredentialError("credential_store_product_mismatch")
    for provider in providers:
        if provider.api_key:
            raise CredentialError("plaintext_provider_credential_not_allowed")
        if provider.credential_ref is None:
            continue
        try:
            ref = ProviderCredentialRefV1.model_validate(provider.credential_ref)
            secret = credential_store.require(ref, expected_kind="model_provider")
        except CredentialError:
            raise
        except Exception:
            raise CredentialError("credential_reference_invalid") from None
        provider.api_key = secret


def hydrate_static_provider_api_keys(
    providers: list[ModelProviderConfig],
    credential_store: ProviderCredentialStore | Any,
) -> None:
    """Compatibility name for the Keychain-only hydration path."""
    if not isinstance(credential_store, ProviderCredentialStore):
        raise CredentialError("provider_credential_store_required")
    hydrate_provider_credentials(
        providers,
        credential_store,
        product_id=credential_store.product_id,
    )


class ProviderManagerError(Exception):
    """Raised when provider management operations fail."""


class ProviderManager:
    """Manages dynamically-added model providers persisted to disk.

    B1A credentials are stored in the Keychain via
    ``ProviderCredentialStore``.  Non-empty legacy stores are never interpreted
    as credentialless providers; B5 must migrate them explicitly first.
    """

    _MAX_PROVIDER_FILE_BYTES = 10 * 1024 * 1024
    _MAX_PROVIDERS = 1000
    _STORE_SCHEMA = "ProviderStoreV2"

    def __init__(
        self,
        state_dir: Path,
        credential_store: ProviderCredentialStore | None = None,
        *,
        product_id: ProductId = "js-agent",
        protected_refs: Iterable[ProviderCredentialRefV1] = (),
        reserved_names: Iterable[str] = (),
    ) -> None:
        unresolved_state = Path(state_dir).expanduser()
        unresolved_state.mkdir(parents=True, exist_ok=True)
        self.state_dir = unresolved_state.resolve(strict=True)
        self._providers: list[ModelProviderConfig] = []
        self._path = self.state_dir / "providers.json"
        self._lock_path = self.state_dir / "providers.lock"
        self._thread_lock = threading.RLock()
        self._credential_store = credential_store
        self._product_id = product_id
        self._mutations_require_restart = False
        try:
            resolved_reserved_names = frozenset(reserved_names)
        except TypeError:
            raise ProviderManagerError("Provider reserved names are invalid") from None
        if any(
            not isinstance(name, str) or not name
            for name in resolved_reserved_names
        ):
            raise ProviderManagerError("Provider reserved names are invalid")
        self._reserved_names = resolved_reserved_names
        if credential_store is not None and credential_store.product_id != product_id:
            raise ProviderManagerError("Provider credential store product mismatch")
        self._protected_refs = {
            self._validated_model_ref(ref) for ref in protected_refs
        }
        self._load()

    def _load(self) -> None:
        try:
            with self._locked():
                providers, pending_delete, staging_refs = self._read_document_unlocked()
                self._reject_reserved_providers(providers)
                self._recover_credential_intents_unlocked(
                    providers,
                    pending_delete,
                    staging_refs,
                )
                for provider in providers:
                    self._hydrate_single(provider)
                self._providers = providers
        except CredentialError as exc:
            raise ProviderManagerError("Provider credential hydration failed") from exc

    def _save(self) -> None:
        snapshot = self.get_all()

        def replace_all(
            _current: list[ModelProviderConfig],
        ) -> tuple[list[ModelProviderConfig], bool]:
            return ([provider.model_copy(deep=True) for provider in snapshot], True)

        self._transaction(replace_all)

    @contextmanager
    def _locked(self) -> Iterator[None]:
        flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            lock_fd = os.open(self._lock_path, flags, 0o600)
        except OSError as exc:
            raise ProviderManagerError("Provider store lock is unavailable") from exc
        try:
            metadata = os.fstat(lock_fd)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ProviderManagerError("Provider store lock is unsafe")
            os.fchmod(lock_fd, 0o600)
            with self._thread_lock:
                self._acquire_file_lock(lock_fd)
                try:
                    yield
                finally:
                    self._release_file_lock(lock_fd)
        finally:
            os.close(lock_fd)

    @staticmethod
    def _acquire_file_lock(lock_fd: int) -> None:
        if os.name == "nt":
            msvcrt: Any = importlib.import_module("msvcrt")
            if os.fstat(lock_fd).st_size == 0:
                os.write(lock_fd, b"\0")
            os.lseek(lock_fd, 0, os.SEEK_SET)
            msvcrt.locking(lock_fd, msvcrt.LK_LOCK, 1)
            return
        fcntl: Any = importlib.import_module("fcntl")
        fcntl.flock(lock_fd, fcntl.LOCK_EX)

    @staticmethod
    def _release_file_lock(lock_fd: int) -> None:
        if os.name == "nt":
            msvcrt: Any = importlib.import_module("msvcrt")
            os.lseek(lock_fd, 0, os.SEEK_SET)
            msvcrt.locking(lock_fd, msvcrt.LK_UNLCK, 1)
            return
        fcntl: Any = importlib.import_module("fcntl")
        fcntl.flock(lock_fd, fcntl.LOCK_UN)

    def _read_document_unlocked(
        self,
    ) -> tuple[
        list[ModelProviderConfig],
        list[ProviderCredentialRefV1],
        list[ProviderCredentialRefV1],
    ]:
        raw = self._read_provider_bytes_unlocked()
        if raw is None:
            return [], [], []
        try:
            data = json.loads(raw.decode("utf-8"))
            if not isinstance(data, dict):
                raise ValueError("provider store schema is invalid")
            allowed_keys = {
                "schema",
                "product_id",
                "providers",
                "pending_delete",
                "staging_refs",
            }
            if set(data) - allowed_keys:
                raise ValueError("provider store schema is invalid")
            schema = data.get("schema")
            provider_data = data.get("providers")
            if schema is None and isinstance(provider_data, list) and provider_data:
                raise ProviderManagerError("Provider store migration is required")
            if schema not in {None, self._STORE_SCHEMA}:
                raise ValueError("provider store schema is invalid")
            stored_product = data.get("product_id", self._product_id)
            if stored_product != self._product_id:
                raise ValueError("provider store product mismatch")
            if not isinstance(provider_data, list):
                raise ValueError("provider store schema is invalid")
            if len(provider_data) > self._MAX_PROVIDERS:
                raise ValueError("provider store exceeds the provider limit")
            loaded: list[ModelProviderConfig] = []
            seen: set[str] = set()
            for item in provider_data:
                if not isinstance(item, dict):
                    raise ValueError("provider entry is invalid")
                payload = dict(item)
                name = payload.get("name", "")
                if not isinstance(name, str) or not name or name in seen:
                    raise ValueError("provider name is invalid or duplicated")
                seen.add(name)
                # B1A: never deserialize api_key from disk; hydrate from Keychain
                payload.pop("api_key", None)
                payload.pop("api_key_env", None)
                config = ModelProviderConfig(**payload)
                loaded.append(config)
            pending_raw = data.get("pending_delete", [])
            if not isinstance(pending_raw, list) or len(pending_raw) > self._MAX_PROVIDERS:
                raise ValueError("provider pending-delete schema is invalid")
            pending = [ProviderCredentialRefV1.model_validate(item) for item in pending_raw]
            for ref in pending:
                if ref.product_id != self._product_id or ref.kind != "model_provider":
                    raise ValueError("provider pending-delete scope is invalid")
            staging_raw = data.get("staging_refs", [])
            if not isinstance(staging_raw, list) or len(staging_raw) > self._MAX_PROVIDERS:
                raise ValueError("provider staging schema is invalid")
            staging = [ProviderCredentialRefV1.model_validate(item) for item in staging_raw]
            for ref in staging:
                if ref.product_id != self._product_id or ref.kind != "model_provider":
                    raise ValueError("provider staging scope is invalid")
            if len(set(pending)) != len(pending) or len(set(staging)) != len(staging):
                raise ValueError("provider credential intents are duplicated")
            return loaded, pending, staging
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
            self._quarantine_corrupt_unlocked()
            logger.error("Corrupt provider store quarantined", exc_info=True)
            return [], [], []

    def _read_unlocked(self) -> list[ModelProviderConfig]:
        providers, pending_delete, staging_refs = self._read_document_unlocked()
        self._reject_reserved_providers(providers)
        self._recover_credential_intents_unlocked(
            providers,
            pending_delete,
            staging_refs,
        )
        for provider in providers:
            self._hydrate_single(provider)
        return providers

    def _hydrate_single(self, config: ModelProviderConfig) -> None:
        """Hydrate one exact product/model reference, failing closed."""
        if config.credential_ref is None:
            return
        if self._credential_store is None:
            raise CredentialError("provider_credential_store_required")
        try:
            ref = ProviderCredentialRefV1.model_validate(config.credential_ref)
            config.api_key = self._credential_store.require(
                ref,
                expected_kind="model_provider",
            )
        except CredentialError:
            raise
        except Exception:
            raise CredentialError("credential_reference_invalid") from None

    def _read_provider_bytes_unlocked(self) -> bytes | None:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            file_fd = os.open(self._path, flags)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise ProviderManagerError("Provider store is unavailable") from exc
        try:
            before = os.fstat(file_fd)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise ProviderManagerError("Provider store is unsafe")
            if before.st_size > self._MAX_PROVIDER_FILE_BYTES:
                raise ProviderManagerError("Provider store exceeds the size limit")
            chunks: list[bytes] = []
            bytes_read = 0
            while True:
                chunk = os.read(
                    file_fd,
                    min(
                        1024 * 1024,
                        self._MAX_PROVIDER_FILE_BYTES + 1 - bytes_read,
                    ),
                )
                if not chunk:
                    break
                chunks.append(chunk)
                bytes_read += len(chunk)
                if bytes_read > self._MAX_PROVIDER_FILE_BYTES:
                    raise ProviderManagerError("Provider store exceeds the size limit")
            after = os.fstat(file_fd)
        finally:
            os.close(file_fd)
        before_fingerprint = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        after_fingerprint = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if before_fingerprint != after_fingerprint or bytes_read != before.st_size:
            raise ProviderManagerError("Provider store changed while being read")
        return b"".join(chunks)

    def _quarantine_corrupt_unlocked(self) -> None:
        if not self._path.exists():
            return
        backup = self.state_dir / f"providers.corrupt-{time.time_ns()}.json"
        try:
            os.replace(self._path, backup)
            self._fsync_directory()
        except OSError:
            logger.error("Could not quarantine corrupt provider store", exc_info=True)

    def _atomic_write_unlocked(
        self,
        providers: list[ModelProviderConfig],
        pending_delete: list[ProviderCredentialRefV1] | None = None,
        staging_refs: list[ProviderCredentialRefV1] | None = None,
    ) -> None:
        # B1A: persist credential_ref but never api_key or api_key_env
        data = {
            "schema": self._STORE_SCHEMA,
            "product_id": self._product_id,
            "providers": [
                provider.model_dump(
                    mode="json",
                    exclude={"api_key", "api_key_env"},
                )
                for provider in providers
            ],
            "pending_delete": [
                ref.model_dump(mode="json") for ref in (pending_delete or [])
            ],
            "staging_refs": [
                ref.model_dump(mode="json") for ref in (staging_refs or [])
            ],
        }
        payload = (json.dumps(data, indent=2, sort_keys=True) + "\n").encode("utf-8")
        temp_path: Path | None = None
        try:
            temp_fd, raw_temp_path = tempfile.mkstemp(
                prefix=".providers-",
                suffix=".tmp",
                dir=self.state_dir,
            )
            temp_path = Path(raw_temp_path)
            os.fchmod(temp_fd, 0o600)
            with os.fdopen(temp_fd, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_path, self._path)
            temp_path = None
            self._fsync_directory()
        except OSError as exc:
            raise ProviderManagerError("Failed to publish provider store atomically") from exc
        finally:
            if temp_path is not None:
                try:
                    temp_path.unlink()
                except FileNotFoundError:
                    pass
                except OSError:
                    logger.warning("Could not remove provider store staging file")

    def _fsync_directory(self) -> None:
        directory_fd = os.open(self.state_dir, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

    def _validated_model_ref(
        self,
        value: ProviderCredentialRefV1 | dict[str, Any],
    ) -> ProviderCredentialRefV1:
        try:
            ref = ProviderCredentialRefV1.model_validate(value)
        except Exception:
            raise ProviderManagerError("Provider credential reference is invalid") from None
        if ref.product_id != self._product_id or ref.kind != "model_provider":
            raise ProviderManagerError("Provider credential reference scope is invalid")
        return ref

    def _referenced_refs(
        self,
        providers: list[ModelProviderConfig],
    ) -> set[ProviderCredentialRefV1]:
        referenced = set(self._protected_refs)
        for provider in providers:
            if provider.credential_ref is not None:
                referenced.add(self._validated_model_ref(provider.credential_ref))
        return referenced

    def _recover_credential_intents_unlocked(
        self,
        providers: list[ModelProviderConfig],
        pending_delete: list[ProviderCredentialRefV1],
        staging_refs: list[ProviderCredentialRefV1],
    ) -> None:
        """Converge crash intents without deleting any referenced credential."""
        if not pending_delete and not staging_refs:
            return
        referenced = self._referenced_refs(providers)
        if self._credential_store is None:
            raise ProviderManagerError("Provider credential cleanup requires a store")
        try:
            for ref in set(staging_refs + pending_delete):
                if ref in referenced:
                    self._credential_store.require(
                        ref,
                        expected_kind="model_provider",
                    )
            for ref in staging_refs:
                if ref not in referenced:
                    self._credential_store.delete(ref, expected_kind="model_provider")
            for ref in pending_delete:
                if ref not in referenced:
                    self._credential_store.delete(ref, expected_kind="model_provider")
            self._atomic_write_unlocked(providers, [], [])
        except (CredentialError, ProviderManagerError) as exc:
            raise ProviderManagerError("Provider credential cleanup requires recovery") from exc

    def _transaction(
        self,
        mutation: Callable[
            [list[ModelProviderConfig]],
            tuple[list[ModelProviderConfig], bool],
        ],
    ) -> bool:
        with self._locked():
            self._ensure_mutations_allowed()
            current = self._read_unlocked()
            working = [provider.model_copy(deep=True) for provider in current]
            updated, result = mutation(working)
            if len(updated) > self._MAX_PROVIDERS:
                raise ProviderManagerError("Provider limit exceeded")
            self._reject_reserved_providers(updated)
            current_by_name = {provider.name: provider for provider in current}
            updated_by_name = {provider.name: provider for provider in updated}
            if len(updated_by_name) != len(updated):
                raise ProviderManagerError("Provider names must be unique")
            staged_values: list[tuple[ProviderCredentialRefV1, str]] = []
            pending_delete: list[ProviderCredentialRefV1] = []
            for provider in updated:
                previous = current_by_name.get(provider.name)
                previous_ref = self._model_ref(previous) if previous is not None else None
                unchanged = (
                    previous is not None
                    and previous_ref is not None
                    and provider.api_key == previous.api_key
                    and provider.credential_ref == previous.credential_ref
                )
                if unchanged:
                    continue
                if provider.api_key:
                    if self._credential_store is None:
                        raise ProviderManagerError("Provider credential store is required")
                    new_ref = self._credential_store.allocate_ref("model_provider")
                    staged_values.append((new_ref, provider.api_key))
                    provider.credential_ref = new_ref
                else:
                    provider.credential_ref = None
                if previous_ref is not None:
                    pending_delete.append(previous_ref)

            for name, previous in current_by_name.items():
                if name not in updated_by_name:
                    previous_ref = self._model_ref(previous)
                    if previous_ref is not None:
                        pending_delete.append(previous_ref)

            pending_delete = list(dict.fromkeys(pending_delete))
            try:
                if staged_values:
                    self._atomic_write_unlocked(
                        current,
                        [],
                        [ref for ref, _secret in staged_values],
                    )
                    assert self._credential_store is not None
                    for ref, secret in staged_values:
                        self._credential_store.put_ref_verified(ref, secret)
                self._atomic_write_unlocked(updated, pending_delete, [])
            except (CredentialError, ProviderManagerError) as exc:
                raise ProviderManagerError("Provider transaction failed") from exc
            try:
                self._delete_pending_unlocked(pending_delete)
                self._atomic_write_unlocked(updated, [], [])
            except Exception as exc:
                raise ProviderManagerError(
                    "Provider credential cleanup requires recovery"
                ) from exc
            self._providers = [provider.model_copy(deep=True) for provider in updated]
            return result

    def _model_ref(
        self,
        provider: ModelProviderConfig | None,
    ) -> ProviderCredentialRefV1 | None:
        if provider is None or provider.credential_ref is None:
            return None
        return self._validated_model_ref(provider.credential_ref)

    def _delete_pending_unlocked(
        self,
        refs: list[ProviderCredentialRefV1],
    ) -> None:
        if not refs:
            return
        if self._credential_store is None:
            raise ProviderManagerError("Provider credential store is required")
        for ref in refs:
            self._credential_store.delete(ref, expected_kind="model_provider")

    def get_all(self) -> list[ModelProviderConfig]:
        with self._thread_lock:
            return [provider.model_copy(deep=True) for provider in self._providers]

    def get(self, name: str) -> ModelProviderConfig | None:
        with self._thread_lock:
            for provider in self._providers:
                if provider.name == name:
                    return provider.model_copy(deep=True)
        return None

    @property
    def reserved_names(self) -> frozenset[str]:
        """Names owned by static config and unavailable to dynamic providers."""
        return self._reserved_names

    def _reject_reserved_providers(
        self,
        providers: Iterable[ModelProviderConfig],
    ) -> None:
        if any(provider.name in self._reserved_names for provider in providers):
            raise ProviderManagerError("Dynamic provider name is reserved")

    def add(self, config: ModelProviderConfig) -> None:
        if not isinstance(config, ModelProviderConfig):
            raise TypeError("config must be a ModelProviderConfig")
        candidate = config.model_copy(deep=True)
        if candidate.name in self._reserved_names:
            raise ProviderManagerError("Dynamic provider name is reserved")

        def add_provider(
            current: list[ModelProviderConfig],
        ) -> tuple[list[ModelProviderConfig], bool]:
            current = [provider for provider in current if provider.name != candidate.name]
            current.append(candidate.model_copy(deep=True))
            return current, True

        self._transaction(add_provider)

    def remove(self, name: str) -> bool:
        def remove_provider(
            current: list[ModelProviderConfig],
        ) -> tuple[list[ModelProviderConfig], bool]:
            updated = [provider for provider in current if provider.name != name]
            return updated, len(updated) < len(current)

        return self._transaction(remove_provider)

    def update_api_key(self, name: str, api_key: str) -> bool:
        """Update the API key for an existing dynamic provider."""

        def update_provider(
            current: list[ModelProviderConfig],
        ) -> tuple[list[ModelProviderConfig], bool]:
            for provider in current:
                if provider.name == name:
                    provider.api_key = api_key
                    return current, True
            return current, False

        return self._transaction(update_provider)

    def _ensure_mutations_allowed(self) -> None:
        if self._mutations_require_restart:
            raise ProviderManagerError("Provider mutations require restart")

    def assert_mutations_allowed(self) -> None:
        """Public fail-closed guard for mutations with external side effects."""
        with self._thread_lock:
            self._ensure_mutations_allowed()

    def require_restart_before_mutation(self) -> None:
        """Fail closed after an external-config publication becomes ambiguous."""
        with self._thread_lock:
            self._mutations_require_restart = True

    def begin_static_credential_transition(
        self,
        *,
        old_ref: ProviderCredentialRefV1 | None,
        new_secret: str | None,
    ) -> ProviderCredentialRefV1 | None:
        """Journal one external static-config transition under the store lock.

        Both sides of a rotation are recorded before the new Keychain item is
        written.  A restart can therefore use the external config's protected
        reference as the sole authority and converge without guessing.
        """
        if self._credential_store is None:
            raise ProviderManagerError("Provider credential store is required")
        resolved_old = self._validated_model_ref(old_ref) if old_ref is not None else None
        resolved_secret = new_secret if new_secret else None
        if resolved_old is None and resolved_secret is None:
            raise ProviderManagerError("Static credential transition is empty")
        with self._locked():
            self._ensure_mutations_allowed()
            providers, pending, staging = self._read_document_unlocked()
            if pending or staging:
                self._mutations_require_restart = True
                raise ProviderManagerError("Provider mutations require restart")
            if resolved_old is not None:
                if resolved_old not in self._protected_refs:
                    raise ProviderManagerError(
                        "Static credential is not protected by external config"
                    )
                self._credential_store.require(
                    resolved_old,
                    expected_kind="model_provider",
                )
            new_ref = (
                self._credential_store.allocate_ref("model_provider")
                if resolved_secret is not None
                else None
            )
            pending_refs = [resolved_old] if resolved_old is not None else []
            staging_refs = [new_ref] if new_ref is not None else []
            self._atomic_write_unlocked(providers, pending_refs, staging_refs)
            if new_ref is not None:
                assert resolved_secret is not None
                try:
                    self._credential_store.put_ref_verified(new_ref, resolved_secret)
                except CredentialError as exc:
                    raise ProviderManagerError(
                        "Provider credential staging failed"
                    ) from exc
            return new_ref

    def resolve_static_credential_transition(
        self,
        *,
        old_ref: ProviderCredentialRefV1 | None,
        new_ref: ProviderCredentialRefV1 | None,
        published_ref: ProviderCredentialRefV1 | None,
    ) -> None:
        """Converge an exact transition to the external config's published ref."""
        resolved_old = self._validated_model_ref(old_ref) if old_ref is not None else None
        resolved_new = self._validated_model_ref(new_ref) if new_ref is not None else None
        resolved_published = (
            self._validated_model_ref(published_ref)
            if published_ref is not None
            else None
        )
        expected_pending = {resolved_old} if resolved_old is not None else set()
        expected_staging = {resolved_new} if resolved_new is not None else set()
        if not expected_pending and not expected_staging:
            raise ProviderManagerError("Static credential transition is empty")
        if resolved_published not in {None, resolved_old, resolved_new}:
            raise ProviderManagerError("Published credential is outside the transition")
        with self._locked():
            self._ensure_mutations_allowed()
            providers, pending, staging = self._read_document_unlocked()
            if set(pending) != expected_pending or len(pending) != len(expected_pending):
                raise ProviderManagerError(
                    "Provider credential retirement intent does not match"
                )
            if set(staging) != expected_staging or len(staging) != len(expected_staging):
                raise ProviderManagerError("Provider credential staging intent does not match")
            if self._credential_store is None:
                raise ProviderManagerError("Provider credential store is required")
            if resolved_published is not None:
                self._credential_store.require(
                    resolved_published,
                    expected_kind="model_provider",
                )
            if resolved_old is not None:
                self._protected_refs.discard(resolved_old)
            if resolved_new is not None:
                self._protected_refs.discard(resolved_new)
            if resolved_published is not None:
                self._protected_refs.add(resolved_published)
            self._recover_credential_intents_unlocked(providers, pending, staging)

    def stage_credential(self, api_key: str) -> ProviderCredentialRefV1:
        """Journal and create a credential for an external atomic publish."""
        ref = self.begin_static_credential_transition(
            old_ref=None,
            new_secret=api_key,
        )
        if ref is None:  # pragma: no cover - guarded by non-empty api_key validation
            raise ProviderManagerError("Provider credential staging failed")
        return ref

    def commit_staged_credential(self, ref: ProviderCredentialRefV1) -> None:
        """Mark a staged reference as protected by a published static config."""
        self.resolve_static_credential_transition(
            old_ref=None,
            new_ref=ref,
            published_ref=ref,
        )

    def discard_staged_credential(self, ref: ProviderCredentialRefV1) -> None:
        """Delete an unpublished staging reference."""
        if self._credential_store is None:
            raise ProviderManagerError("Provider credential store is required")
        resolved = self._validated_model_ref(ref)
        with self._locked():
            self._ensure_mutations_allowed()
            providers, pending, staging = self._read_document_unlocked()
            if pending or staging != [resolved]:
                raise ProviderManagerError("Provider credential staging intent is missing")
            if resolved in self._referenced_refs(providers):
                raise ProviderManagerError("Provider credential staging ref is protected")
            try:
                self._credential_store.delete(resolved, expected_kind="model_provider")
                self._atomic_write_unlocked(providers, [], [])
            except CredentialError as exc:
                raise ProviderManagerError("Provider credential staging cleanup failed") from exc

    def prepare_retire_credential(self, ref: ProviderCredentialRefV1) -> None:
        """Journal retirement before an external config removes its reference."""
        self.begin_static_credential_transition(old_ref=ref, new_secret=None)

    def cancel_retire_credential(self, ref: ProviderCredentialRefV1) -> None:
        """Cancel retirement after an external publication rollback."""
        self.resolve_static_credential_transition(
            old_ref=ref,
            new_ref=None,
            published_ref=ref,
        )

    def finalize_retire_credential(self, ref: ProviderCredentialRefV1) -> None:
        """Delete a journaled ref after the external config publication."""
        self.resolve_static_credential_transition(
            old_ref=ref,
            new_ref=None,
            published_ref=None,
        )

    def retire_credential(self, ref: ProviderCredentialRefV1) -> None:
        """Compatibility wrapper for callers without a two-phase publication."""
        self.prepare_retire_credential(ref)
        self.finalize_retire_credential(ref)

    @staticmethod
    async def discover_models(
        base_url: str, api_key: str | None = None, *, allow_private: bool = False
    ) -> dict[str, Any]:
        """Query an OpenAI-compatible endpoint for available models.

        Returns {"models": [...]} on success or {"error": "..."} on failure.
        Each model dict includes id, name, and context_window when available.

        SSRF policy: loopback is allowed ONLY when the literal hostname is
        ``localhost`` / ``127.0.0.1`` / ``::1`` — a domain that merely *resolves*
        to loopback (e.g. ``127.0.0.1.nip.io``, ``127.1``, ``2130706433``) is
        treated as remote and rejected by default, defeating DNS rebinding.
        Private-network (RFC1918) hosts require ``allow_private=True`` (driven by
        ``security.allow_private_model_providers``).  Link-local / metadata /
        reserved / multicast destinations are ALWAYS rejected.
        """
        import httpx

        from js.security.net_guard import (
            OutboundURLError,
            PinnedTransport,
            resolve_and_validate_provider_endpoint,
        )

        try:
            validated_ips = resolve_and_validate_provider_endpoint(
                base_url,
                allow_private=allow_private,
            )
        except OutboundURLError as exc:
            return {"error": f"目标地址被安全策略拒绝: {exc}"}

        headers: dict[str, str] = {}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        try:
            async with httpx.AsyncClient(
                transport=PinnedTransport(
                    validated_ips[0],
                    verify=True,
                    trust_env=False,
                ),
                timeout=30.0,
                trust_env=False,
                follow_redirects=False,
            ) as client:
                # Enhanced LM Studio metadata must use the same DNS-validated,
                # IP-pinned transport as the authoritative /v1/models call.
                context_overrides: dict[str, int] = {}
                if "127.0.0.1:1234" in base_url or "localhost:1234" in base_url:
                    try:
                        root = base_url.rstrip("/").rsplit("/v1", 1)[0]
                        metadata = await client.get(
                            f"{root}/api/v0/models",
                            timeout=httpx.Timeout(5.0),
                        )
                        if metadata.status_code == 200:
                            for item in metadata.json().get("data", []):
                                context = item.get("max_context_length") or item.get(
                                    "loaded_context_length"
                                )
                                if item.get("id") and context:
                                    context_overrides[item["id"]] = int(context)
                    except Exception:
                        pass

                resp = await client.get(f"{base_url.rstrip('/')}/models", headers=headers)
                resp.raise_for_status()
                data = resp.json()
                models = data.get("data", [])
                result_models = []
                for m in models:
                    model_id = m.get("id", "")
                    if not model_id:
                        continue
                    # Priority: v0 API context > v1 API context_length > name inference
                    ctx = context_overrides.get(model_id)
                    if ctx is None:
                        ctx = m.get("context_length") or m.get("max_context_length")
                    if ctx is None:
                        from js.models.discovery import LocalModelDiscovery

                        ctx = LocalModelDiscovery._infer_context_window(model_id)
                    result_models.append(
                        {
                            "id": model_id,
                            "name": m.get("name", model_id.split("/")[-1]),
                            "context_window": int(ctx),
                        }
                    )
                return {"models": result_models}
        except httpx.ConnectTimeout:
            return {"error": "连接超时，请检查网络或 IP 地址是否正确"}
        except httpx.ConnectError as e:
            from js.models.capability import sanitize_provider_error

            return {
                "error": sanitize_provider_error(
                    f"无法连接到该地址: {e}",
                    api_key=api_key,
                )
            }
        except httpx.HTTPStatusError as e:
            return {"error": f"服务端返回错误: HTTP {e.response.status_code}"}
        except Exception as e:
            from js.models.capability import sanitize_provider_error

            return {
                "error": sanitize_provider_error(
                    f"发现失败: {e}",
                    api_key=api_key,
                )
            }
