"""Crash-recoverable migration of persisted Provider secrets to Keychain.

The journal contains only closed metadata and opaque credential references. It
never contains a secret, secret digest, Keychain account, or absolute path.
Every new credential follows this order::

    allocate opaque ref -> durable prepared intent -> Keychain write/readback
    -> durable verified intent -> atomic config publication -> source cleanup

All filesystem operations that protect this ordering are descriptor-relative.
Tests inject an in-memory Keychain; this module never selects a real backend.
"""

from __future__ import annotations

import hashlib
import hmac
import importlib
import os
import re
import stat
import sys
import tempfile
import threading
from collections.abc import Iterator, MutableMapping
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, cast

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from js.provider_credential_types import (
    CredentialKind,
    ProductId,
    ProviderCredentialRefV1,
)
from js.security.provider_credentials import CredentialError, ProviderCredentialStore
from js.security.secrets import SecretManager

_JOURNAL_NAME = ".provider-credential-migration-v1.json"
_LOCK_NAME = ".provider-credential-migration-v1.lock"
_JOURNAL_SCHEMA = "ProviderCredentialMigrationV1"
_SEARCH_ENTRY_NAME = "search"
_MAX_JOURNAL_BYTES = 64 * 1024
_MAX_CONFIG_BYTES = 10 * 1024 * 1024
_MAX_LEGACY_DB_BYTES = 64 * 1024 * 1024
_MAX_ENTRIES = 256
_MAX_CONFIG_NODES = 100_000
_MAX_CONFIG_DEPTH = 64
_PROVIDER_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_LOCK_ROOT_NAME = "js-agent-provider-migration-locks"
_LOCK_ROOT_MODE = 0o700
_EXTERNAL_LOCKS_GUARD = threading.Lock()
_EXTERNAL_PROCESS_LOCKS: dict[str, threading.RLock] = {}
_EXTERNAL_ROOT_PROCESS_LOCK = threading.RLock()
_EXTERNAL_THREAD_STATE = threading.local()
_RENAME_SWAP = 0x00000002


def _external_process_lock(domain: str) -> threading.RLock:
    with _EXTERNAL_LOCKS_GUARD:
        return _EXTERNAL_PROCESS_LOCKS.setdefault(domain, threading.RLock())


class MigrationError(RuntimeError):
    """Closed migration failure without paths or secret material."""


class MigrationJournalCorruptError(MigrationError):
    """The journal bytes do not satisfy the closed schema."""


class MigrationJournalUnsafeError(MigrationError):
    """A migration filesystem object is unsafe."""


class CredentialMigrationError(MigrationError):
    """The migration could not safely reach a durable state."""


class SourceClearedButKeychainMissingError(MigrationError):
    """The durable reference exists but the Keychain value is absent."""


MigrationJournalCorrupt = MigrationJournalCorruptError
MigrationJournalUnsafe = MigrationJournalUnsafeError
CredentialMigrationFailed = CredentialMigrationError
SourceClearedButKeychainMissing = SourceClearedButKeychainMissingError

MigrationPhase = Literal[
    "prepared",
    "keychain_verified",
    "config_published",
    "legacy_store_cleared",
]
MigrationSource = Literal["yaml", "toml", "legacy_store", "search_config"]
ConfigSource = Literal["yaml", "toml"]
_PHASE_ORDER: tuple[MigrationPhase, ...] = (
    "prepared",
    "keychain_verified",
    "config_published",
    "legacy_store_cleared",
)


class MigrationEntryV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    provider_name: str = Field(min_length=1, max_length=128)
    phase: MigrationPhase
    kind: CredentialKind
    product_id: ProductId
    ref: ProviderCredentialRefV1
    source: MigrationSource

    def model_post_init(self, _context: Any) -> None:
        if _PROVIDER_NAME.fullmatch(self.provider_name) is None:
            raise ValueError("provider name is invalid")
        if self.ref.product_id != self.product_id or self.ref.kind != self.kind:
            raise ValueError("credential reference scope is invalid")
        if self.kind == "search_provider":
            if self.provider_name != _SEARCH_ENTRY_NAME or self.source != "search_config":
                raise ValueError("search migration metadata is invalid")
        elif self.source == "search_config":
            raise ValueError("model migration metadata is invalid")


class _JournalV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["ProviderCredentialMigrationV1"] = (
        "ProviderCredentialMigrationV1"
    )
    entries: tuple[MigrationEntryV1, ...]


class _PathSafetyError(RuntimeError):
    """Internal marker; callers replace it with a closed public error."""


def _directory_flags() -> int:
    required = ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK")
    if not all(hasattr(os, flag) for flag in required):
        raise _PathSafetyError("secure directory operations are unavailable")
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK


def _file_read_flags() -> int:
    required = ("O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK")
    if not all(hasattr(os, flag) for flag in required):
        raise _PathSafetyError("secure file operations are unavailable")
    return os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK


def _absolute_lexical_path(path: Path | str) -> Path:
    try:
        raw = os.path.expanduser(os.fspath(path))
        if not raw or "\0" in raw:
            raise ValueError
        return Path(os.path.abspath(raw))
    except (TypeError, ValueError, OSError):
        raise _PathSafetyError("path is invalid") from None


def _open_directory_chain(
    path: Path | str,
    *,
    create: bool,
    private_final: bool,
    tighten_final: bool = True,
) -> tuple[Path, int]:
    """Open every component with ``O_NOFOLLOW`` and return the final dirfd."""
    absolute = _absolute_lexical_path(path)
    parts = absolute.parts
    if not parts or parts[0] != os.sep or len(parts) == 1 and private_final:
        raise _PathSafetyError("directory path is invalid")
    fd = -1
    try:
        fd = os.open(os.sep, _directory_flags())
        for index, component in enumerate(parts[1:], start=1):
            if component in {"", ".", ".."}:
                raise _PathSafetyError("directory component is invalid")
            try:
                child_fd = os.open(component, _directory_flags(), dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(component, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
                child_fd = os.open(component, _directory_flags(), dir_fd=fd)
            metadata = os.fstat(child_fd)
            if not stat.S_ISDIR(metadata.st_mode) or metadata.st_nlink < 1:
                os.close(child_fd)
                raise _PathSafetyError("directory component is unsafe")
            if index == len(parts) - 1 and private_final:
                if metadata.st_uid != os.getuid():
                    os.close(child_fd)
                    raise _PathSafetyError("private directory owner is unsafe")
                if tighten_final:
                    os.fchmod(child_fd, 0o700)
                elif stat.S_IMODE(metadata.st_mode) != 0o700:
                    os.close(child_fd)
                    raise _PathSafetyError("private directory mode is unsafe")
            os.close(fd)
            fd = child_fd
        return absolute, fd
    except (OSError, _PathSafetyError):
        if fd >= 0:
            os.close(fd)
        raise


def _assert_directory_identity(path: Path, expected: tuple[int, int]) -> None:
    reopened = -1
    try:
        _absolute, reopened = _open_directory_chain(
            path,
            create=False,
            private_final=False,
        )
        metadata = os.fstat(reopened)
        if (metadata.st_dev, metadata.st_ino) != expected:
            raise _PathSafetyError("directory identity changed")
    finally:
        if reopened >= 0:
            os.close(reopened)


def _read_exact_regular_file(fd: int, expected_size: int, maximum: int) -> bytes:
    if expected_size < 0 or expected_size > maximum:
        raise _PathSafetyError("file size is unsafe")
    chunks: list[bytes] = []
    remaining = expected_size
    while remaining:
        try:
            chunk = os.read(fd, min(remaining, 64 * 1024))
        except InterruptedError:
            continue
        if not chunk:
            raise _PathSafetyError("file changed while read")
        chunks.append(chunk)
        remaining -= len(chunk)
    try:
        extra = os.read(fd, 1)
    except InterruptedError:
        extra = os.read(fd, 1)
    if extra:
        raise _PathSafetyError("file changed while read")
    return b"".join(chunks)


def _write_all(fd: int, payload: bytes) -> None:
    view = memoryview(payload)
    written = 0
    while written < len(view):
        try:
            count = os.write(fd, view[written:])
        except InterruptedError:
            continue
        if count <= 0:
            raise OSError("short write")
        written += count


def _entry_key(kind: CredentialKind, provider_name: str) -> str:
    return f"{kind}:{provider_name}"


def _same_inode(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _mode_is_writable_by_current_user(metadata: os.stat_result) -> bool:
    mode = stat.S_IMODE(metadata.st_mode)
    uid = os.getuid()
    if uid == 0:
        return True
    if metadata.st_uid == uid:
        return bool(mode & stat.S_IWUSR)
    if metadata.st_gid in {os.getgid(), *os.getgroups()}:
        return bool(mode & stat.S_IWGRP)
    return bool(mode & stat.S_IWOTH)


def _stable_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _rename_swap(dir_fd: int, left: str, right: str) -> None:
    """Atomically exchange two names or fail closed on unsupported platforms."""
    if sys.platform != "darwin":
        raise CredentialMigrationFailed("atomic configuration swap is unavailable")
    try:
        ctypes = importlib.import_module("ctypes")
        libc = ctypes.CDLL(None, use_errno=True)
        renameatx_np = libc.renameatx_np
        renameatx_np.argtypes = (
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        )
        renameatx_np.restype = ctypes.c_int
        result = renameatx_np(
            dir_fd,
            os.fsencode(left),
            dir_fd,
            os.fsencode(right),
            _RENAME_SWAP,
        )
        if result != 0:
            error_number = ctypes.get_errno()
            raise OSError(error_number, os.strerror(error_number))
    except OSError:
        raise
    except Exception:
        raise CredentialMigrationFailed("atomic configuration swap is unavailable") from None


class _ClosedSafeLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: _ClosedSafeLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str) or key in result:
            raise ValueError("configuration mapping keys are invalid")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_ClosedSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _validate_config_tree(root: Any) -> None:
    count = 0
    stack: list[tuple[Any, int]] = [(root, 0)]
    while stack:
        value, depth = stack.pop()
        count += 1
        if count > _MAX_CONFIG_NODES or depth > _MAX_CONFIG_DEPTH:
            raise ValueError("configuration structure exceeds limits")
        if isinstance(value, dict):
            for key, child in value.items():
                if not isinstance(key, str):
                    raise ValueError("configuration mapping keys are invalid")
                stack.append((child, depth + 1))
        elif isinstance(value, list):
            stack.extend((child, depth + 1) for child in value)
        elif value is not None and type(value) not in {str, int, float, bool}:
            raise ValueError("configuration value type is invalid")


def _source_kind(path: Path) -> ConfigSource:
    if path.suffix.lower() in {".yaml", ".yml"}:
        return "yaml"
    if path.suffix.lower() == ".toml":
        return "toml"
    raise CredentialMigrationFailed("unsupported provider configuration format")


def _parse_config(raw: bytes, source: ConfigSource) -> dict[str, Any]:
    try:
        text = raw.decode("utf-8")
        if source == "yaml":
            loaded = yaml.load(text, Loader=_ClosedSafeLoader) or {}  # noqa: S506
        else:
            tomllib = importlib.import_module("tomllib")
            loaded = tomllib.loads(text)
        _validate_config_tree(loaded)
    except Exception:
        raise CredentialMigrationFailed("provider configuration is invalid") from None
    if not isinstance(loaded, dict):
        raise CredentialMigrationFailed("provider configuration is invalid")
    return cast("dict[str, Any]", loaded)


@dataclass
class _ConfigSnapshot:
    path: Path
    parent_path: Path
    parent_fd: int
    parent_identity: tuple[int, int]
    name: str
    source: ConfigSource
    identity: tuple[int, int, int, int, int]
    data: dict[str, Any]

    def close(self) -> None:
        if self.parent_fd >= 0:
            os.close(self.parent_fd)
            self.parent_fd = -1

    def assert_current(self) -> None:
        try:
            _assert_directory_identity(self.parent_path, self.parent_identity)
            metadata = os.stat(self.name, dir_fd=self.parent_fd, follow_symlinks=False)
        except (OSError, _PathSafetyError):
            raise CredentialMigrationFailed("provider configuration changed") from None
        if not stat.S_ISREG(metadata.st_mode) or _stable_identity(metadata) != self.identity:
            raise CredentialMigrationFailed("provider configuration changed")

    def refresh_after_publish(self, data: dict[str, Any], expected_raw: bytes) -> None:
        fd = -1
        try:
            fd = os.open(self.name, _file_read_flags(), dir_fd=self.parent_fd)
            metadata = os.fstat(fd)
            named = os.stat(self.name, dir_fd=self.parent_fd, follow_symlinks=False)
            if not _same_inode(metadata, named):
                raise _PathSafetyError("published configuration changed")
            actual = _read_exact_regular_file(fd, metadata.st_size, _MAX_CONFIG_BYTES)
            after = os.fstat(fd)
            if _stable_identity(metadata) != _stable_identity(after):
                raise _PathSafetyError("published configuration changed")
        except (OSError, _PathSafetyError):
            raise CredentialMigrationFailed("provider configuration publication failed") from None
        finally:
            if fd >= 0:
                os.close(fd)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or not hmac.compare_digest(actual, expected_raw)
        ):
            raise CredentialMigrationFailed("provider configuration publication failed")
        self.identity = _stable_identity(metadata)
        self.data = data


@contextmanager
def _config_snapshot(path: Path | str) -> Iterator[_ConfigSnapshot]:
    try:
        absolute = _absolute_lexical_path(path)
        source = _source_kind(absolute)
        parent_path, parent_fd = _open_directory_chain(
            absolute.parent,
            create=False,
            private_final=False,
        )
    except (OSError, _PathSafetyError):
        raise CredentialMigrationFailed("provider configuration is unavailable") from None
    snapshot: _ConfigSnapshot | None = None
    file_fd = -1
    try:
        parent_meta = os.fstat(parent_fd)
        parent_identity = (parent_meta.st_dev, parent_meta.st_ino)
        _assert_directory_identity(parent_path, parent_identity)
        file_fd = os.open(absolute.name, _file_read_flags(), dir_fd=parent_fd)
        before = os.fstat(file_fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) & 0o077
            or before.st_size > _MAX_CONFIG_BYTES
        ):
            raise _PathSafetyError("provider configuration is unsafe")
        named = os.stat(absolute.name, dir_fd=parent_fd, follow_symlinks=False)
        if not _same_inode(before, named):
            raise _PathSafetyError("provider configuration changed")
        raw = _read_exact_regular_file(file_fd, before.st_size, _MAX_CONFIG_BYTES)
        after = os.fstat(file_fd)
        if _stable_identity(before) != _stable_identity(after):
            raise _PathSafetyError("provider configuration changed")
        data = _parse_config(raw, source)
        snapshot = _ConfigSnapshot(
            path=absolute,
            parent_path=parent_path,
            parent_fd=parent_fd,
            parent_identity=parent_identity,
            name=absolute.name,
            source=source,
            identity=_stable_identity(after),
            data=data,
        )
        parent_fd = -1
        snapshot.assert_current()
        yield snapshot
    except CredentialMigrationError:
        raise
    except (OSError, _PathSafetyError):
        raise CredentialMigrationFailed("provider configuration is unavailable") from None
    finally:
        if file_fd >= 0:
            os.close(file_fd)
        if snapshot is not None:
            snapshot.close()
        elif parent_fd >= 0:
            os.close(parent_fd)


def inspect_provider_config(path: Path | str) -> dict[str, Any]:
    """Safely parse a provider config without constructing or touching state.

    This is the supported pre-construction API for callers that need to
    validate a custom ``state_dir`` before creating a migrator.
    """
    with _config_snapshot(path) as snapshot:
        snapshot.assert_current()
        return snapshot.data


def _preflight_legacy_store(
    state_dir: Path | str,
    providers: Any,
) -> None:
    """Read-only integrity check for an existing legacy secret database."""
    state_fd = -1
    database_fd = -1
    key_fd = -1
    material_lock_fd = -1
    connection: Any | None = None
    fernet_cipher: Any | None = None
    try:
        _state_path, state_fd = _open_directory_chain(
            state_dir,
            create=False,
            private_final=True,
            tighten_final=False,
        )
        try:
            material_lock_fd = os.open(
                ".secret_material.lock",
                _file_read_flags(),
                dir_fd=state_fd,
            )
        except FileNotFoundError:
            pass
        if material_lock_fd >= 0:
            lock_meta = os.fstat(material_lock_fd)
            lock_named = os.stat(
                ".secret_material.lock",
                dir_fd=state_fd,
                follow_symlinks=False,
            )
            if (
                not stat.S_ISREG(lock_meta.st_mode)
                or lock_meta.st_uid != os.getuid()
                or lock_meta.st_nlink != 1
                or stat.S_IMODE(lock_meta.st_mode) & 0o077
                or not _same_inode(lock_meta, lock_named)
            ):
                raise _PathSafetyError("legacy credential lock is unsafe")

        try:
            key_fd = os.open(".secret_key", _file_read_flags(), dir_fd=state_fd)
        except FileNotFoundError:
            pass
        if key_fd >= 0:
            key_before = os.fstat(key_fd)
            key_named = os.stat(".secret_key", dir_fd=state_fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(key_before.st_mode)
                or key_before.st_uid != os.getuid()
                or key_before.st_nlink != 1
                or stat.S_IMODE(key_before.st_mode) & 0o077
                or key_before.st_size > 4096
                or not _same_inode(key_before, key_named)
            ):
                raise _PathSafetyError("legacy credential key is unsafe")
            key_material = _read_exact_regular_file(key_fd, key_before.st_size, 4096)
            key_after = os.fstat(key_fd)
            if _stable_identity(key_before) != _stable_identity(key_after):
                raise _PathSafetyError("legacy credential key changed")
            fernet = importlib.import_module("cryptography.fernet")
            fernet_cipher = fernet.Fernet(key_material)

        try:
            database_fd = os.open("secrets.db", _file_read_flags(), dir_fd=state_fd)
        except FileNotFoundError:
            return
        before = os.fstat(database_fd)
        named = os.stat("secrets.db", dir_fd=state_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
            # SecretManager historically created the private, user-owned DB
            # as 0644. Accept that exact upgrade form read-only; the migrator
            # tightens it to 0600 before any credential operation.
            or stat.S_IMODE(before.st_mode) not in {0o600, 0o644}
            or before.st_size > _MAX_LEGACY_DB_BYTES
            or not _same_inode(before, named)
        ):
            raise _PathSafetyError("legacy credential store is unsafe")
        sqlite3 = importlib.import_module("sqlite3")
        connection = sqlite3.connect(
            f"file:/dev/fd/{database_fd}?mode=ro&immutable=1",
            uri=True,
            timeout=0,
        )
        rows = connection.execute("PRAGMA quick_check").fetchall()
        after = os.fstat(database_fd)
        named_after = os.stat("secrets.db", dir_fd=state_fd, follow_symlinks=False)
        if (
            rows != [("ok",)]
            or _stable_identity(before) != _stable_identity(after)
            or not _same_inode(after, named_after)
        ):
            raise _PathSafetyError("legacy credential store is invalid")
        table = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'secrets'"
        ).fetchone()
        if table is not None:
            if not isinstance(providers, list):
                raise _PathSafetyError("legacy credential providers are invalid")
            for provider in providers:
                if not isinstance(provider, dict):
                    raise _PathSafetyError("legacy credential providers are invalid")
                name = provider.get("name")
                inline = provider.get("api_key")
                if not isinstance(name, str) or (
                    inline is not None and not isinstance(inline, str)
                ):
                    raise _PathSafetyError("legacy credential providers are invalid")
                row = connection.execute(
                    "SELECT value_encrypted FROM secrets WHERE name = ?",
                    (f"static_provider_apikey_{name}",),
                ).fetchone()
                if row is None:
                    continue
                if (
                    len(row) != 1
                    or not isinstance(row[0], bytes)
                    or fernet_cipher is None
                ):
                    raise _PathSafetyError("legacy credential value is invalid")
                legacy = fernet_cipher.decrypt(row[0]).decode("utf-8")
                if inline and not hmac.compare_digest(inline, legacy):
                    raise _PathSafetyError("legacy credential sources disagree")
    except FileNotFoundError:
        return
    except Exception:
        raise CredentialMigrationFailed("legacy credential store is unavailable") from None
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass
        if database_fd >= 0:
            os.close(database_fd)
        if key_fd >= 0:
            os.close(key_fd)
        if material_lock_fd >= 0:
            os.close(material_lock_fd)
        if state_fd >= 0:
            os.close(state_fd)


def _tighten_legacy_store(state_dir: Path | str) -> None:
    """Descriptor-safely converge an existing legacy database to mode 0600."""
    state_fd = -1
    database_fd = -1
    try:
        _state_path, state_fd = _open_directory_chain(
            state_dir,
            create=False,
            private_final=True,
        )
        try:
            database_fd = os.open(
                "secrets.db",
                os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                dir_fd=state_fd,
            )
        except FileNotFoundError:
            return
        metadata = os.fstat(database_fd)
        named = os.stat("secrets.db", dir_fd=state_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) not in {0o600, 0o644}
            or not _same_inode(metadata, named)
        ):
            raise _PathSafetyError("legacy credential store is unsafe")
        os.fchmod(database_fd, 0o600)
        os.fsync(database_fd)
        os.fsync(state_fd)
    except (OSError, _PathSafetyError):
        raise CredentialMigrationFailed("legacy credential store is unavailable") from None
    finally:
        if database_fd >= 0:
            os.close(database_fd)
        if state_fd >= 0:
            os.close(state_fd)


def _external_lock_root() -> tuple[Path, int]:
    """Return a process-external private lock root outside product profiles."""
    override = os.getenv("JS_MIGRATION_LOCK_ROOT")
    # ``tempfile.gettempdir()`` is commonly returned through the system
    # ``/var`` symlink on macOS.  Canonicalising this OS-selected base once is
    # safe and lets the subsequent descriptor walk keep rejecting symlinks.
    root = (
        _absolute_lexical_path(override)
        if override
        else Path(os.path.realpath(tempfile.gettempdir()))
        / f"{_LOCK_ROOT_NAME}-{os.getuid()}"
    )
    try:
        path, fd = _open_directory_chain(root, create=True, private_final=True)
        metadata = os.fstat(fd)
        if (
            metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != _LOCK_ROOT_MODE
            or metadata.st_nlink < 1
        ):
            raise _PathSafetyError("external lock root is unsafe")
        return path, fd
    except (OSError, _PathSafetyError):
        raise MigrationJournalUnsafe("external migration lock root is unsafe") from None


def _stable_user_anchor() -> tuple[Path, int]:
    """Open a per-user inode whose directory entry this uid cannot replace."""
    try:
        pwd = importlib.import_module("pwd")
        home = _absolute_lexical_path(pwd.getpwuid(os.getuid()).pw_dir)
        if home == Path(home.anchor):
            raise _PathSafetyError("stable user anchor is unavailable")
        parent_path, parent_fd = _open_directory_chain(
            home.parent,
            create=False,
            private_final=False,
        )
        try:
            parent_meta = os.fstat(parent_fd)
            if _mode_is_writable_by_current_user(parent_meta):
                raise _PathSafetyError("stable user anchor parent is replaceable")
        finally:
            os.close(parent_fd)
        anchor_path, anchor_fd = _open_directory_chain(
            home,
            create=False,
            private_final=False,
        )
        metadata = os.fstat(anchor_fd)
        if metadata.st_uid != os.getuid() or metadata.st_nlink < 1:
            os.close(anchor_fd)
            raise _PathSafetyError("stable user anchor is unsafe")
        return anchor_path, anchor_fd
    except (KeyError, OSError, _PathSafetyError):
        raise MigrationJournalUnsafe("stable migration anchor is unavailable") from None


@contextmanager
def _external_root_lease() -> Iterator[tuple[Path, int]]:
    """Hold the fixed external root inode across every named lock operation.

    Locking the directory itself prevents unlinking a live per-domain lock
    name from creating a second lock domain in another process.  The process
    RLock and thread-local depth make nested config/state transactions safe.
    """
    with _EXTERNAL_ROOT_PROCESS_LOCK:
        depth = getattr(_EXTERNAL_THREAD_STATE, "root_depth", 0)
        if depth:
            _EXTERNAL_THREAD_STATE.root_depth = depth + 1
            try:
                yield (
                    cast("Path", _EXTERNAL_THREAD_STATE.root_path),
                    cast("int", _EXTERNAL_THREAD_STATE.root_fd),
                )
            finally:
                _EXTERNAL_THREAD_STATE.root_depth -= 1
            return

        anchor_path, anchor_fd = _stable_user_anchor()
        anchor_meta = os.fstat(anchor_fd)
        anchor_identity = (anchor_meta.st_dev, anchor_meta.st_ino)
        try:
            MigrationReceiptV1._flock(anchor_fd, exclusive=True)
            _assert_directory_identity(anchor_path, anchor_identity)
        except (OSError, _PathSafetyError):
            os.close(anchor_fd)
            raise MigrationJournalUnsafe("stable migration anchor changed") from None
        try:
            root_path, root_fd = _external_lock_root()
            metadata = os.fstat(root_fd)
            identity = (metadata.st_dev, metadata.st_ino)
            MigrationReceiptV1._flock(root_fd, exclusive=True)
            _assert_directory_identity(root_path, identity)
        except (OSError, _PathSafetyError, MigrationError):
            try:
                MigrationReceiptV1._flock(anchor_fd, exclusive=False)
            finally:
                os.close(anchor_fd)
            try:
                if "root_fd" in locals():
                    os.close(root_fd)
            except OSError:
                pass
            raise MigrationJournalUnsafe("external migration lock root changed") from None
        _EXTERNAL_THREAD_STATE.root_depth = 1
        _EXTERNAL_THREAD_STATE.root_path = root_path
        _EXTERNAL_THREAD_STATE.root_fd = root_fd
        _EXTERNAL_THREAD_STATE.domains = {}
        try:
            yield root_path, root_fd
        except BaseException:
            raise
        else:
            try:
                _assert_directory_identity(root_path, identity)
                _assert_directory_identity(anchor_path, anchor_identity)
            except (OSError, _PathSafetyError):
                raise MigrationJournalUnsafe(
                    "external migration lock root changed"
                ) from None
        finally:
            _EXTERNAL_THREAD_STATE.root_depth = 0
            _EXTERNAL_THREAD_STATE.root_path = None
            _EXTERNAL_THREAD_STATE.root_fd = -1
            _EXTERNAL_THREAD_STATE.domains = {}
            try:
                MigrationReceiptV1._flock(root_fd, exclusive=False)
            finally:
                os.close(root_fd)
            try:
                MigrationReceiptV1._flock(anchor_fd, exclusive=False)
            finally:
                os.close(anchor_fd)


@contextmanager
def _named_external_lock(domain: str) -> Iterator[Path]:
    """Lock a stable inode and reject name unlink/replacement before release."""
    with _external_root_lease() as (root_path, root_fd), _external_process_lock(domain):
        name = f"{domain}.lock"
        held_domains = cast(
            "dict[str, tuple[int, Path, int]]",
            _EXTERNAL_THREAD_STATE.domains,
        )
        existing = held_domains.get(domain)
        if existing is not None:
            existing_fd, existing_path, depth = existing
            MigrationReceiptV1._validate_lock_fd(existing_fd, root_fd, name)
            held_domains[domain] = (existing_fd, existing_path, depth + 1)
            try:
                yield existing_path
                MigrationReceiptV1._validate_lock_fd(existing_fd, root_fd, name)
            finally:
                held_domains[domain] = (existing_fd, existing_path, depth)
            return

        fd = -1
        try:
            flags = (
                os.O_CREAT
                | os.O_RDWR
                | os.O_CLOEXEC
                | os.O_NOFOLLOW
                | os.O_NONBLOCK
            )
            fd = os.open(name, flags, 0o600, dir_fd=root_fd)
            MigrationReceiptV1._validate_lock_fd(fd, root_fd, name)
            MigrationReceiptV1._flock(fd, exclusive=True)
        except MigrationError:
            if fd >= 0:
                os.close(fd)
            raise
        except OSError:
            if fd >= 0:
                os.close(fd)
            raise MigrationJournalUnsafe("external migration lock is unavailable") from None

        lock_path = root_path / name
        held_domains[domain] = (fd, lock_path, 1)
        try:
            yield lock_path
        except BaseException:
            raise
        else:
            try:
                MigrationReceiptV1._validate_lock_fd(fd, root_fd, name)
            except OSError:
                raise MigrationJournalUnsafe("external migration lock changed") from None
        finally:
            held_domains.pop(domain, None)
            try:
                MigrationReceiptV1._flock(fd, exclusive=False)
            finally:
                os.close(fd)


@contextmanager
def provider_config_lease(path: Path | str) -> Iterator[None]:
    """Serialize cooperating readers/writers for one lexical config path."""
    absolute = _absolute_lexical_path(path)
    _source_kind(absolute)
    domain = "config-" + hashlib.sha256(os.fsencode(absolute)).hexdigest()
    with _named_external_lock(domain):
        yield


class MigrationReceiptV1:
    """Private dirfd-relative receipt with an inode-anchored owner lock."""

    def __init__(self, state_dir: Path) -> None:
        self._thread_lock = threading.RLock()
        try:
            path, anchor_fd = _open_directory_chain(
                state_dir,
                create=True,
                private_final=True,
            )
            metadata = os.fstat(anchor_fd)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or metadata.st_nlink < 1
            ):
                raise _PathSafetyError("migration state directory is unsafe")
            self._state_dir = path
            self._anchor_fd = anchor_fd
            self._anchor_identity = (metadata.st_dev, metadata.st_ino)
            domain = hashlib.sha256(os.fsencode(path)).hexdigest()[:32]
            self._external_domain = f"state-{domain}"
            self._assert_anchor_current()
        except (OSError, _PathSafetyError):
            try:
                os.close(anchor_fd)
            except (NameError, OSError):
                pass
            raise MigrationJournalUnsafe("migration state directory is unsafe") from None

    def __del__(self) -> None:
        for attribute in ("_anchor_fd",):
            fd = getattr(self, attribute, -1)
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
                setattr(self, attribute, -1)

    def _assert_anchor_current(self) -> None:
        try:
            metadata = os.fstat(self._anchor_fd)
            if (metadata.st_dev, metadata.st_ino) != self._anchor_identity:
                raise _PathSafetyError("migration state directory changed")
            _assert_directory_identity(self._state_dir, self._anchor_identity)
        except (OSError, _PathSafetyError):
            raise MigrationJournalUnsafe("migration state directory changed") from None

    @contextmanager
    def transaction(self) -> Iterator[tuple[int, dict[str, MigrationEntryV1]]]:
        """Hold one lock across a complete migration state machine."""
        with self._thread_lock, _named_external_lock(self._external_domain):
            try:
                dir_fd = os.dup(self._anchor_fd)
                os.set_inheritable(dir_fd, False)
            except OSError:
                try:
                    os.close(dir_fd)
                except (NameError, OSError):
                    pass
                raise MigrationJournalUnsafe(
                    "migration state directory is unavailable"
                ) from None
            lock_fd = -1
            try:
                flags = (
                    os.O_CREAT
                    | os.O_RDWR
                    | os.O_CLOEXEC
                    | os.O_NOFOLLOW
                    | os.O_NONBLOCK
                )
                self._assert_anchor_current()
                lock_fd = os.open(_LOCK_NAME, flags, 0o600, dir_fd=dir_fd)
                self._validate_lock_fd(lock_fd, dir_fd, _LOCK_NAME)
                self._flock(lock_fd, exclusive=True)
                try:
                    self._assert_anchor_current()
                    yield dir_fd, self._read_unlocked(dir_fd)
                finally:
                    self._flock(lock_fd, exclusive=False)
            except OSError:
                raise MigrationJournalUnsafe("migration lock is unavailable") from None
            finally:
                if lock_fd >= 0:
                    os.close(lock_fd)
                os.close(dir_fd)

    @property
    def external_lock_path(self) -> Path:
        root, fd = _external_lock_root()
        os.close(fd)
        return root / f"{self._external_domain}.lock"

    @staticmethod
    def _validate_lock_fd(fd: int, dir_fd: int, name: str) -> None:
        metadata = os.fstat(fd)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size > _MAX_JOURNAL_BYTES
        ):
            raise MigrationJournalUnsafe("migration lock is unsafe")
        named = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        if not _same_inode(metadata, named):
            raise MigrationJournalUnsafe("migration lock changed")

    @staticmethod
    def _flock(fd: int, *, exclusive: bool) -> None:
        fcntl = importlib.import_module("fcntl")
        operation = fcntl.LOCK_EX if exclusive else fcntl.LOCK_UN
        fcntl.flock(fd, operation)

    def _read_unlocked(self, dir_fd: int) -> dict[str, MigrationEntryV1]:
        self._assert_anchor_current()
        try:
            fd = os.open(_JOURNAL_NAME, _file_read_flags(), dir_fd=dir_fd)
        except FileNotFoundError:
            return {}
        except OSError:
            raise MigrationJournalUnsafe("migration journal is unavailable") from None
        try:
            before = os.fstat(fd)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != os.getuid()
                or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_size > _MAX_JOURNAL_BYTES
            ):
                raise MigrationJournalUnsafe("migration journal is unsafe")
            named = os.stat(_JOURNAL_NAME, dir_fd=dir_fd, follow_symlinks=False)
            if not _same_inode(before, named):
                raise MigrationJournalUnsafe("migration journal changed")
            raw = _read_exact_regular_file(fd, before.st_size, _MAX_JOURNAL_BYTES)
            after = os.fstat(fd)
            if _stable_identity(before) != _stable_identity(after):
                raise MigrationJournalUnsafe("migration journal changed while read")
        except _PathSafetyError:
            raise MigrationJournalUnsafe("migration journal changed while read") from None
        finally:
            os.close(fd)
        try:
            document = _JournalV1.model_validate_json(raw, strict=True)
        except (ValidationError, ValueError):
            raise MigrationJournalCorrupt("migration journal schema is invalid") from None
        if len(document.entries) > _MAX_ENTRIES:
            raise MigrationJournalCorrupt("migration journal has too many entries")
        entries: dict[str, MigrationEntryV1] = {}
        for entry in document.entries:
            key = _entry_key(entry.kind, entry.provider_name)
            if key in entries:
                raise MigrationJournalCorrupt("migration journal has duplicate entries")
            entries[key] = entry
        return entries

    def _write_unlocked(
        self,
        dir_fd: int,
        entries: MutableMapping[str, MigrationEntryV1],
    ) -> None:
        self._assert_anchor_current()
        if len(entries) > _MAX_ENTRIES:
            raise MigrationJournalCorrupt("migration journal has too many entries")
        if not entries:
            self._clear_unlocked(dir_fd)
            return
        document = _JournalV1(entries=tuple(entries[name] for name in sorted(entries)))
        raw = document.model_dump_json().encode("utf-8") + b"\n"
        if len(raw) > _MAX_JOURNAL_BYTES:
            raise MigrationJournalCorrupt("migration journal exceeds size limit")
        temp_name = (
            f".provider-credential-migration-{os.getpid()}-{os.urandom(8).hex()}.tmp"
        )
        flags = (
            os.O_CREAT
            | os.O_EXCL
            | os.O_WRONLY
            | os.O_CLOEXEC
            | os.O_NOFOLLOW
            | os.O_NONBLOCK
        )
        fd = -1
        try:
            fd = os.open(temp_name, flags, 0o600, dir_fd=dir_fd)
            _write_all(fd, raw)
            os.fsync(fd)
            os.close(fd)
            fd = -1
            self._assert_anchor_current()
            try:
                existing = os.stat(_JOURNAL_NAME, dir_fd=dir_fd, follow_symlinks=False)
            except FileNotFoundError:
                existing = None
            if existing is not None and (
                not stat.S_ISREG(existing.st_mode)
                or existing.st_uid != os.getuid()
                or existing.st_nlink != 1
                or stat.S_IMODE(existing.st_mode) != 0o600
            ):
                raise MigrationJournalUnsafe("migration journal is unsafe")
            os.replace(temp_name, _JOURNAL_NAME, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
            os.fsync(dir_fd)
        except MigrationJournalUnsafe:
            raise
        except OSError:
            raise MigrationJournalUnsafe("migration journal publication failed") from None
        finally:
            if fd >= 0:
                os.close(fd)
            try:
                os.unlink(temp_name, dir_fd=dir_fd)
            except FileNotFoundError:
                pass
            except OSError:
                pass

    def _clear_unlocked(self, dir_fd: int) -> None:
        self._assert_anchor_current()
        try:
            metadata = os.stat(_JOURNAL_NAME, dir_fd=dir_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        except OSError:
            raise MigrationJournalUnsafe("migration journal cleanup failed") from None
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise MigrationJournalUnsafe("migration journal is unsafe")
        try:
            os.unlink(_JOURNAL_NAME, dir_fd=dir_fd)
            os.fsync(dir_fd)
        except OSError:
            raise MigrationJournalUnsafe("migration journal cleanup failed") from None

    def recover(self) -> dict[str, MigrationEntryV1] | None:
        with self.transaction() as (_dir_fd, entries):
            return entries or None

    def get_pending(self) -> list[MigrationEntryV1]:
        return list((self.recover() or {}).values())

    def begin_migration(
        self,
        provider_name: str,
        kind: str,
        product_id: ProductId,
        *,
        ref_id: str,
    ) -> None:
        if kind not in {"model_provider", "search_provider"}:
            raise MigrationError("migration scope is invalid")
        credential_kind = cast("CredentialKind", kind)
        source: MigrationSource = (
            "search_config" if credential_kind == "search_provider" else "legacy_store"
        )
        try:
            ref = ProviderCredentialRefV1(
                ref_id=ref_id,
                product_id=product_id,
                kind=credential_kind,
            )
            entry = MigrationEntryV1(
                provider_name=provider_name,
                phase="prepared",
                kind=credential_kind,
                product_id=product_id,
                ref=ref,
                source=source,
            )
        except ValidationError:
            raise MigrationError("migration scope is invalid") from None
        with self.transaction() as (dir_fd, entries):
            key = _entry_key(credential_kind, provider_name)
            if key in entries and entries[key] != entry:
                raise CredentialMigrationFailed("migration entry already exists")
            entries[key] = entry
            self._write_unlocked(dir_fd, entries)

    def update_phase(self, provider_name: str, phase: str, ref_id: str = "") -> None:
        if phase not in _PHASE_ORDER:
            raise MigrationError("migration phase is invalid")
        with self.transaction() as (dir_fd, entries):
            key = _entry_key("model_provider", provider_name)
            current = entries.get(key)
            if current is None:
                raise MigrationError("migration entry is missing")
            if ref_id and ref_id != current.ref.ref_id:
                raise CredentialMigrationFailed("migration reference is immutable")
            current_index = _PHASE_ORDER.index(current.phase)
            next_index = _PHASE_ORDER.index(phase)
            if next_index not in {current_index, current_index + 1}:
                raise CredentialMigrationFailed("migration phase transition is invalid")
            entries[key] = current.model_copy(update={"phase": phase})
            self._write_unlocked(dir_fd, entries)

    def complete_migration(self, provider_name: str) -> None:
        with self.transaction() as (dir_fd, entries):
            key = _entry_key("model_provider", provider_name)
            current = entries.get(key)
            if current is None:
                return
            if current.phase != "legacy_store_cleared":
                raise CredentialMigrationFailed("migration is not complete")
            entries.pop(key)
            self._write_unlocked(dir_fd, entries)


@dataclass
class _StaticPlan:
    name: str
    provider: dict[str, Any]
    legacy_name: str
    legacy_value: str | None
    inline_value: str | None
    existing_ref: ProviderCredentialRefV1 | None
    entry: MigrationEntryV1 | None
    ref: ProviderCredentialRefV1 | None
    source: ConfigSource
    needs_cleanup: bool

    @property
    def secret(self) -> str | None:
        return self.inline_value or self.legacy_value


class ProviderCredentialMigrator:
    """Migrate provider credentials through durable, crash-safe intents."""

    def __init__(
        self,
        state_dir: Path,
        credential_store: ProviderCredentialStore,
        *,
        product_id: ProductId = "js-agent",
        secret_manager: SecretManager | None = None,
    ) -> None:
        if credential_store.product_id != product_id:
            raise CredentialMigrationFailed("migration credential scope mismatch")
        self._store = credential_store
        self._product_id = product_id
        self._receipt = MigrationReceiptV1(state_dir)
        try:
            self._secret_manager = secret_manager or SecretManager(state_dir)
            _tighten_legacy_store(state_dir)
        except Exception:
            raise CredentialMigrationFailed("legacy credential store is unavailable") from None

    @property
    def receipt(self) -> MigrationReceiptV1:
        return self._receipt

    @staticmethod
    def inspect_config(path: Path | str) -> dict[str, Any]:
        """Public safe inspection API; it does not create a state directory."""
        return inspect_provider_config(path)

    @staticmethod
    def migrate_paths_preflight(
        config_path: Path | str,
        *,
        state_dir: Path | str,
        product_id: ProductId,
    ) -> dict[str, Any]:
        """Validate config and state paths without creating migration state."""
        del product_id
        absolute = _absolute_lexical_path(config_path)
        _source_kind(absolute)
        if absolute.is_symlink():
            raise CredentialMigrationFailed("provider configuration is unsafe")
        if not absolute.exists():
            raise CredentialMigrationFailed("provider configuration is unavailable")
        data = inspect_provider_config(absolute)
        state = _absolute_lexical_path(state_dir)
        try:
            try:
                _path, fd = _open_directory_chain(
                    state,
                    create=False,
                    private_final=True,
                    tighten_final=False,
                )
                os.close(fd)
            except FileNotFoundError:
                # Validate the complete existing prefix without creating the
                # future private state directory or any of its parents.
                candidate = state.parent
                while True:
                    try:
                        _path, fd = _open_directory_chain(
                            candidate,
                            create=False,
                            private_final=False,
                        )
                        os.close(fd)
                        break
                    except FileNotFoundError:
                        if candidate == Path(candidate.anchor):
                            raise
                        candidate = candidate.parent
        except (OSError, _PathSafetyError):
            raise CredentialMigrationFailed("migration state path is unsafe") from None
        _preflight_legacy_store(state, data.get("providers", []))
        return data

    @staticmethod
    def config_lease(path: Path | str) -> AbstractContextManager[None]:
        return provider_config_lease(path)

    def migrate_static_config(self, config_path: Path) -> bool:
        """Migrate every static model-provider credential in one config."""
        with (
            provider_config_lease(config_path),
            self._receipt.transaction() as (dir_fd, entries),
            _config_snapshot(config_path) as snapshot,
        ):
            plans = self._preflight_static(snapshot, entries)
            changed = self._prepare_static_entries(
                snapshot,
                dir_fd,
                entries,
                plans,
            )
            self._verify_static_keychain(snapshot, dir_fd, entries, plans)
            changed = self._publish_static_config(
                snapshot,
                dir_fd,
                entries,
                plans,
                changed=changed,
            )
            self._cleanup_static_sources(snapshot, dir_fd, entries, plans)
            return changed

    def _preflight_static(
        self,
        snapshot: _ConfigSnapshot,
        entries: dict[str, MigrationEntryV1],
    ) -> list[_StaticPlan]:
        providers = snapshot.data.get("providers", [])
        if not isinstance(providers, list):
            raise CredentialMigrationFailed("provider configuration is invalid")
        plans: list[_StaticPlan] = []
        seen: set[str] = set()
        for raw_provider in providers:
            if not isinstance(raw_provider, dict):
                raise CredentialMigrationFailed("provider configuration is invalid")
            name = raw_provider.get("name")
            if not isinstance(name, str) or _PROVIDER_NAME.fullmatch(name) is None:
                raise CredentialMigrationFailed("provider configuration is invalid")
            if name in seen:
                raise CredentialMigrationFailed("provider configuration is invalid")
            seen.add(name)
            inline_raw = raw_provider.get("api_key")
            if inline_raw is not None and not isinstance(inline_raw, str):
                raise CredentialMigrationFailed("provider configuration is invalid")
            inline_value = inline_raw or None
            legacy_name = f"static_provider_apikey_{name}"
            legacy_value = self._secret_manager.retrieve(legacy_name)
            if (
                inline_value is not None
                and legacy_value is not None
                and not hmac.compare_digest(inline_value, legacy_value)
            ):
                raise CredentialMigrationFailed("migration sources disagree")
            existing_ref = self._parse_ref(raw_provider.get("credential_ref"))
            key = _entry_key("model_provider", name)
            entry = entries.get(key)
            if entry is not None:
                if entry.product_id != self._product_id or entry.kind != "model_provider":
                    raise CredentialMigrationFailed("migration scope mismatch")
                if entry.source not in {snapshot.source, "legacy_store"}:
                    raise CredentialMigrationFailed("migration source mismatch")
                if existing_ref is not None and existing_ref != entry.ref:
                    raise CredentialMigrationFailed("migration reference mismatch")
                if entry.phase in {"config_published", "legacy_store_cleared"} and (
                    existing_ref != entry.ref
                ):
                    raise CredentialMigrationFailed("migration reference mismatch")
            ref = existing_ref or (entry.ref if entry is not None else None)
            keychain_value: str | None = None
            if ref is not None:
                keychain_value = self._get_ref(ref)
                if keychain_value is None and (entry is None or entry.phase != "prepared"):
                    raise SourceClearedButKeychainMissing(
                        "published credential is missing from Keychain"
                    )
                for candidate in (inline_value, legacy_value):
                    if (
                        candidate is not None
                        and keychain_value is not None
                        and not hmac.compare_digest(candidate, keychain_value)
                    ):
                        raise CredentialMigrationFailed("migration sources disagree")
            needs_cleanup = (
                "api_key" in raw_provider
                or "api_key_env" in raw_provider
                or legacy_value is not None
            )
            plans.append(
                _StaticPlan(
                    name=name,
                    provider=raw_provider,
                    legacy_name=legacy_name,
                    legacy_value=legacy_value,
                    inline_value=inline_value,
                    existing_ref=existing_ref,
                    entry=entry,
                    ref=ref,
                    source=snapshot.source,
                    needs_cleanup=needs_cleanup,
                )
            )
        for entry in entries.values():
            if entry.kind == "model_provider" and entry.provider_name not in seen:
                raise CredentialMigrationFailed("migration entry has no provider")
        snapshot.assert_current()
        return plans

    def _prepare_static_entries(
        self,
        snapshot: _ConfigSnapshot,
        dir_fd: int,
        entries: dict[str, MigrationEntryV1],
        plans: list[_StaticPlan],
    ) -> bool:
        journal_changed = False
        config_changed = False
        for plan in plans:
            if plan.ref is None and plan.secret is not None:
                plan.ref = self._store.allocate_ref("model_provider")
            requires_entry = plan.ref is not None and (
                plan.entry is not None or plan.secret is not None or plan.needs_cleanup
            )
            if requires_entry and plan.entry is None:
                if plan.ref is None:
                    raise CredentialMigrationFailed("migration reference is missing")
                plan.entry = MigrationEntryV1(
                    provider_name=plan.name,
                    phase="prepared",
                    kind="model_provider",
                    product_id=self._product_id,
                    ref=plan.ref,
                    source=plan.source,
                )
                entries[_entry_key("model_provider", plan.name)] = plan.entry
                journal_changed = True
            if plan.ref is not None and plan.existing_ref != plan.ref:
                config_changed = True
            if "api_key" in plan.provider or "api_key_env" in plan.provider:
                config_changed = True
        snapshot.assert_current()
        if journal_changed:
            self._receipt._write_unlocked(dir_fd, entries)
        return config_changed

    def _verify_static_keychain(
        self,
        snapshot: _ConfigSnapshot,
        dir_fd: int,
        entries: dict[str, MigrationEntryV1],
        plans: list[_StaticPlan],
    ) -> None:
        for plan in plans:
            entry = plan.entry
            ref = plan.ref
            if entry is None or ref is None:
                continue
            if entry.ref != ref:
                raise CredentialMigrationFailed("migration reference mismatch")
            if entry.phase == "prepared":
                existing = self._get_ref(ref)
                if existing is None:
                    if plan.secret is None:
                        raise SourceClearedButKeychainMissing(
                            "prepared credential source is unavailable"
                        )
                    snapshot.assert_current()
                    self._receipt._assert_anchor_current()
                    self._store.put_ref_verified(ref, plan.secret)
                    existing = self._require_ref(ref)
                if plan.secret is not None and not hmac.compare_digest(existing, plan.secret):
                    raise CredentialMigrationFailed("migration sources disagree")
                entry = entry.model_copy(update={"phase": "keychain_verified"})
                plan.entry = entry
                entries[_entry_key("model_provider", plan.name)] = entry
                self._receipt._write_unlocked(dir_fd, entries)
            else:
                self._require_ref(ref)

    def _publish_static_config(
        self,
        snapshot: _ConfigSnapshot,
        dir_fd: int,
        entries: dict[str, MigrationEntryV1],
        plans: list[_StaticPlan],
        *,
        changed: bool,
    ) -> bool:
        for plan in plans:
            if plan.ref is not None:
                encoded_ref = plan.ref.model_dump(mode="json")
                if plan.provider.get("credential_ref") != encoded_ref:
                    plan.provider["credential_ref"] = encoded_ref
                    changed = True
            if "api_key" in plan.provider or "api_key_env" in plan.provider:
                plan.provider.pop("api_key", None)
                plan.provider.pop("api_key_env", None)
                changed = True
        snapshot.assert_current()
        if changed:
            self._publish_config(snapshot, snapshot.source, snapshot.data)
        for plan in plans:
            if plan.entry is None:
                continue
            entry = plan.entry
            if entry.phase == "prepared":
                raise CredentialMigrationFailed("migration phase is invalid")
            if entry.phase == "keychain_verified":
                entry = entry.model_copy(update={"phase": "config_published"})
                plan.entry = entry
                entries[_entry_key("model_provider", plan.name)] = entry
                self._receipt._write_unlocked(dir_fd, entries)
        return changed

    def _cleanup_static_sources(
        self,
        snapshot: _ConfigSnapshot,
        dir_fd: int,
        entries: dict[str, MigrationEntryV1],
        plans: list[_StaticPlan],
    ) -> None:
        for plan in plans:
            entry = plan.entry
            ref = plan.ref
            if entry is None or ref is None:
                continue
            snapshot.assert_current()
            persisted = self._find_model_ref(snapshot.data, plan.name)
            if persisted != ref:
                raise CredentialMigrationFailed("migration reference mismatch")
            self._require_ref(ref)
            if entry.phase == "config_published":
                if self._secret_manager.retrieve(plan.legacy_name) is not None:
                    try:
                        self._secret_manager.delete(plan.legacy_name)
                    except Exception:
                        # The durable config and journal already identify the
                        # Keychain authority. Keep the config_published intent
                        # for restart, but never expose storage-driver details.
                        raise CredentialMigrationFailed(
                            "legacy credential cleanup failed"
                        ) from None
                    if self._secret_manager.retrieve(plan.legacy_name) is not None:
                        raise CredentialMigrationFailed("legacy credential cleanup failed")
                entry = entry.model_copy(update={"phase": "legacy_store_cleared"})
                plan.entry = entry
                entries[_entry_key("model_provider", plan.name)] = entry
                self._receipt._write_unlocked(dir_fd, entries)
            if entry.phase != "legacy_store_cleared":
                raise CredentialMigrationFailed("migration phase is invalid")
            entries.pop(_entry_key("model_provider", plan.name), None)
            self._receipt._write_unlocked(dir_fd, entries)

    def stage_search_credential(self, secret: str) -> ProviderCredentialRefV1:
        """Durably stage a search credential before a caller saves its ref.

        Callers must atomically save the returned reference and then call
        :meth:`commit_search_credential`. A crash or save failure is resolved
        by :meth:`recover_search_credential` on restart.
        """
        with self._receipt.transaction() as (dir_fd, entries):
            key = _entry_key("search_provider", _SEARCH_ENTRY_NAME)
            if key in entries:
                raise CredentialMigrationFailed("search credential migration is pending")
            ref = self._store.allocate_ref("search_provider")
            entry = MigrationEntryV1(
                provider_name=_SEARCH_ENTRY_NAME,
                phase="prepared",
                kind="search_provider",
                product_id=self._product_id,
                ref=ref,
                source="search_config",
            )
            entries[key] = entry
            self._receipt._write_unlocked(dir_fd, entries)
            self._receipt._assert_anchor_current()
            self._store.put_ref_verified(ref, secret)
            self._require_ref(ref, kind="search_provider")
            entries[key] = entry.model_copy(update={"phase": "keychain_verified"})
            self._receipt._write_unlocked(dir_fd, entries)
            return ref

    def _commit_search_credential_unleased(
        self,
        ref: ProviderCredentialRefV1,
        *,
        config_path: Path | str,
    ) -> None:
        with (
            self._receipt.transaction() as (dir_fd, entries),
            _config_snapshot(config_path) as snapshot,
        ):
            persisted = self._parse_search_ref(snapshot.data.get("search_credential_ref"))
            if persisted != ref:
                raise CredentialMigrationFailed("search credential reference mismatch")
            key = _entry_key("search_provider", _SEARCH_ENTRY_NAME)
            entry = entries.get(key)
            if entry is None or entry.ref != ref:
                raise CredentialMigrationFailed("search migration entry is missing")
            self._require_ref(ref, kind="search_provider")
            snapshot.assert_current()
            if entry.phase == "prepared":
                entry = entry.model_copy(update={"phase": "keychain_verified"})
                entries[key] = entry
                self._receipt._write_unlocked(dir_fd, entries)
            if entry.phase != "keychain_verified":
                raise CredentialMigrationFailed("search migration phase is invalid")
            entry = entry.model_copy(update={"phase": "config_published"})
            entries[key] = entry
            self._receipt._write_unlocked(dir_fd, entries)
            entry = entry.model_copy(update={"phase": "legacy_store_cleared"})
            entries[key] = entry
            self._receipt._write_unlocked(dir_fd, entries)
            entries.pop(key)
            self._receipt._write_unlocked(dir_fd, entries)

    def _recover_search_credential_unleased(
        self,
        config_path: Path | str,
    ) -> ProviderCredentialRefV1 | None:
        with (
            self._receipt.transaction() as (dir_fd, entries),
            _config_snapshot(config_path) as snapshot,
        ):
            persisted = self._parse_search_ref(snapshot.data.get("search_credential_ref"))
            if persisted is not None:
                self._require_ref(persisted, kind="search_provider")
            key = _entry_key("search_provider", _SEARCH_ENTRY_NAME)
            entry = entries.get(key)
            if entry is None:
                return persisted
            snapshot.assert_current()
            if entry.phase in {"config_published", "legacy_store_cleared"} and (
                persisted != entry.ref
            ):
                raise CredentialMigrationFailed("search credential reference mismatch")
            if persisted == entry.ref:
                self._require_ref(entry.ref, kind="search_provider")
                entries.pop(key)
                self._receipt._write_unlocked(dir_fd, entries)
                return persisted
            try:
                self._store.delete(entry.ref, expected_kind="search_provider")
            except CredentialError:
                raise CredentialMigrationFailed("search credential recovery failed") from None
            entries.pop(key)
            self._receipt._write_unlocked(dir_fd, entries)
            return persisted

    def configure_search_credential(
        self,
        secret: str,
        *,
        config_path: Path | str,
        save_config: Any,
    ) -> ProviderCredentialRefV1:
        """Stage, publish and commit one search ref under a single OS lease."""
        with provider_config_lease(config_path):
            # Descriptor-safe validation must precede the durable intent and
            # Keychain write; Path.exists() would follow a symlink and leave a
            # staged secret behind when publication later fails.
            inspect_provider_config(config_path)
            ref: ProviderCredentialRefV1 | None = None
            try:
                ref = self.stage_search_credential(secret)
                save_config(ref)
                self._commit_search_credential_unleased(ref, config_path=config_path)
            except Exception:
                try:
                    recovered = self._recover_search_credential_unleased(config_path)
                except MigrationError:
                    raise CredentialMigrationFailed(
                        "search credential recovery failed"
                    ) from None
                # A save may durably publish and then report an fsync error.
                # In that case recovery has verified both authorities and the
                # transaction is complete; returning success avoids a stale
                # in-memory ref being saved over the durable value later.
                if ref is not None and recovered == ref:
                    return ref
                raise
            if ref is None:  # pragma: no cover - defensive type invariant
                raise CredentialMigrationFailed("search migration reference is missing")
            return ref

    def commit_search_credential(
        self,
        ref: ProviderCredentialRefV1,
        *,
        config_path: Path | str,
    ) -> None:
        """Clear a staged intent only after the config durably holds ``ref``."""
        self._validate_search_ref(ref)
        with provider_config_lease(config_path):
            self._commit_search_credential_unleased(ref, config_path=config_path)

    def recover_search_credential(
        self,
        config_path: Path | str,
    ) -> ProviderCredentialRefV1 | None:
        """Converge a staged search intent against the authoritative config."""
        with provider_config_lease(config_path):
            return self._recover_search_credential_unleased(config_path)

    def migrate_static_provider(
        self,
        provider_name: str,
        old_secret_key: str,
        *,
        config_path: Path | None = None,
        config_provider_key: str = "api_key",
    ) -> ProviderCredentialRefV1 | None:
        """Compatibility wrapper; a real config path is mandatory."""
        del old_secret_key, config_provider_key
        if config_path is None:
            raise CredentialMigrationFailed("migration configuration is required")
        self.migrate_static_config(config_path)
        data = inspect_provider_config(config_path)
        return self._find_model_ref(data, provider_name)

    def migrate_dynamic_provider(
        self,
        provider_name: str,
        old_secret_key: str,
    ) -> ProviderCredentialRefV1 | None:
        """Dynamic migration remains deferred to the B5 store transaction."""
        del provider_name, old_secret_key
        raise CredentialMigrationFailed("dynamic provider migration requires store transaction")

    def verify_keychain_present(self, ref: ProviderCredentialRefV1) -> str:
        return self._require_ref(ref, kind=ref.kind)

    def _get_ref(self, ref: ProviderCredentialRefV1) -> str | None:
        try:
            return self._store.get(ref, expected_kind=ref.kind)
        except CredentialError:
            raise CredentialMigrationFailed("credential lookup failed") from None

    def _require_ref(
        self,
        ref: ProviderCredentialRefV1,
        *,
        kind: CredentialKind = "model_provider",
    ) -> str:
        try:
            return self._store.require(ref, expected_kind=kind)
        except CredentialError:
            raise SourceClearedButKeychainMissing(
                "published credential is missing from Keychain"
            ) from None

    def _parse_ref(self, raw: Any) -> ProviderCredentialRefV1 | None:
        if raw is None:
            return None
        try:
            ref = ProviderCredentialRefV1.model_validate(raw, strict=True)
        except ValidationError:
            raise CredentialMigrationFailed("credential reference is invalid") from None
        if ref.product_id != self._product_id or ref.kind != "model_provider":
            raise CredentialMigrationFailed("credential reference scope is invalid")
        return ref

    def _parse_search_ref(self, raw: Any) -> ProviderCredentialRefV1 | None:
        if raw is None:
            return None
        try:
            ref = ProviderCredentialRefV1.model_validate(raw, strict=True)
        except ValidationError:
            raise CredentialMigrationFailed("search credential reference is invalid") from None
        self._validate_search_ref(ref)
        return ref

    def _validate_search_ref(self, ref: ProviderCredentialRefV1) -> None:
        if ref.product_id != self._product_id or ref.kind != "search_provider":
            raise CredentialMigrationFailed("search credential reference scope is invalid")

    def _find_model_ref(
        self,
        data: dict[str, Any],
        provider_name: str,
    ) -> ProviderCredentialRefV1 | None:
        providers = data.get("providers", [])
        if not isinstance(providers, list):
            raise CredentialMigrationFailed("provider configuration is invalid")
        for item in providers:
            if isinstance(item, dict) and item.get("name") == provider_name:
                return self._parse_ref(item.get("credential_ref"))
        return None

    @staticmethod
    def _source_kind(path: Path) -> ConfigSource:
        return _source_kind(_absolute_lexical_path(path))

    @staticmethod
    def _read_config(path: Path, source: ConfigSource) -> dict[str, Any]:
        if _source_kind(_absolute_lexical_path(path)) != source:
            raise CredentialMigrationFailed("provider configuration format mismatch")
        return inspect_provider_config(path)

    @staticmethod
    def _publish_config(
        snapshot: _ConfigSnapshot,
        source: ConfigSource,
        data: dict[str, Any],
    ) -> None:
        try:
            if source == "yaml":
                raw = yaml.safe_dump(data, sort_keys=False).encode("utf-8")
            else:
                tomli_w = importlib.import_module("tomli_w")
                raw = tomli_w.dumps(data).encode("utf-8")
        except Exception:
            raise CredentialMigrationFailed(
                "provider configuration serialization failed"
            ) from None
        if len(raw) > _MAX_CONFIG_BYTES:
            raise CredentialMigrationFailed("provider configuration exceeds size limit")
        temp_name = f".{snapshot.name}.credential-migration-{os.urandom(8).hex()}.tmp"
        flags = (
            os.O_CREAT
            | os.O_EXCL
            | os.O_WRONLY
            | os.O_CLOEXEC
            | os.O_NOFOLLOW
            | os.O_NONBLOCK
        )
        fd = -1
        temp_identity: tuple[int, int, int, int, int] | None = None
        try:
            snapshot.assert_current()
            fd = os.open(temp_name, flags, 0o600, dir_fd=snapshot.parent_fd)
            _write_all(fd, raw)
            os.fsync(fd)
            temp_metadata = os.fstat(fd)
            temp_identity = _stable_identity(temp_metadata)
            os.close(fd)
            fd = -1
            # Atomically exchange target and candidate. The old target moves
            # to ``temp_name`` so its inode can be checked *after* the atomic
            # operation, closing the assert-then-replace lost-update window.
            snapshot.assert_current()
            _rename_swap(snapshot.parent_fd, temp_name, snapshot.name)
            installed = os.stat(
                snapshot.name,
                dir_fd=snapshot.parent_fd,
                follow_symlinks=False,
            )
            exchanged = os.stat(
                temp_name,
                dir_fd=snapshot.parent_fd,
                follow_symlinks=False,
            )
            if (installed.st_dev, installed.st_ino) != temp_identity[:2]:
                raise CredentialMigrationFailed(
                    "provider configuration publication failed"
                )
            if (exchanged.st_dev, exchanged.st_ino) != snapshot.identity[:2]:
                # The target changed after the last assertion. Swap back only
                # while both names still denote the exact inodes observed;
                # never delete or overwrite the unknown competing file.
                _rename_swap(snapshot.parent_fd, temp_name, snapshot.name)
                restored = os.stat(
                    snapshot.name,
                    dir_fd=snapshot.parent_fd,
                    follow_symlinks=False,
                )
                candidate = os.stat(
                    temp_name,
                    dir_fd=snapshot.parent_fd,
                    follow_symlinks=False,
                )
                if (
                    (restored.st_dev, restored.st_ino)
                    != (exchanged.st_dev, exchanged.st_ino)
                    or (candidate.st_dev, candidate.st_ino) != temp_identity[:2]
                ):
                    temp_identity = None
                    raise CredentialMigrationFailed(
                        "provider configuration rollback failed"
                    )
                os.fsync(snapshot.parent_fd)
                raise CredentialMigrationFailed("provider configuration changed")

            os.unlink(temp_name, dir_fd=snapshot.parent_fd)
            temp_identity = None
            os.fsync(snapshot.parent_fd)
            snapshot.refresh_after_publish(data, raw)
        except CredentialMigrationError:
            raise
        except OSError:
            raise CredentialMigrationFailed(
                "provider configuration publication failed"
            ) from None
        finally:
            if fd >= 0:
                os.close(fd)
            if temp_identity is not None:
                try:
                    candidate = os.stat(
                        temp_name,
                        dir_fd=snapshot.parent_fd,
                        follow_symlinks=False,
                    )
                    if (candidate.st_dev, candidate.st_ino) == temp_identity[:2]:
                        os.unlink(temp_name, dir_fd=snapshot.parent_fd)
                except (FileNotFoundError, OSError):
                    pass
