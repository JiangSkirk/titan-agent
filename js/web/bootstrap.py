"""First-run bootstrap admin key persistence."""

from __future__ import annotations

import os
import secrets
import sqlite3
import stat
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from js.config import JSSettings
from js.utils.db import _is_locked_or_busy
from js.utils.log import get_logger

logger = get_logger("js.web")

_BOOTSTRAP_LOCK_NAME = ".bootstrap_admin.lock"


def _peer_has_admin(state_dir: Path) -> bool:
    """Best-effort check that another process already minted an admin key."""
    from js.web.auth import AuthManager

    try:
        return AuthManager(state_dir).has_admin()
    except Exception:
        return False


@contextmanager
def _bootstrap_provision_lock(state_dir: Path) -> Iterator[None]:
    """Cross-process exclusive lock serializing first-start admin minting."""
    import importlib
    from typing import Any

    state_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(state_dir, 0o700)
    except OSError:
        pass
    lock_path = state_dir / _BOOTSTRAP_LOCK_NAME
    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        try:
            os.fchmod(lock_fd, 0o600)
        except OSError:
            pass
        if os.name == "nt":
            msvcrt: Any = importlib.import_module("msvcrt")
            if os.fstat(lock_fd).st_size == 0:
                os.write(lock_fd, b"\0")
            os.lseek(lock_fd, 0, os.SEEK_SET)
            msvcrt.locking(lock_fd, msvcrt.LK_LOCK, 1)
        else:
            fcntl: Any = importlib.import_module("fcntl")
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            if os.name == "nt":
                msvcrt = importlib.import_module("msvcrt")
                os.lseek(lock_fd, 0, os.SEEK_SET)
                msvcrt.locking(lock_fd, msvcrt.LK_UNLCK, 1)
            else:
                fcntl = importlib.import_module("fcntl")
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)


def _provision_bootstrap_admin_key(settings: JSSettings) -> str | None:
    """Ensure an admin key exists when auth is required; return new plaintext.

    Prevents the "first_run_completed=true but no admin key → site-wide 401"
    lockdown by self-healing on every startup: if auth is required and no admin
    key exists, one is minted and written to a 0600 file so a headless operator
    can recover it. The plaintext credential is never written to logs. Returns
    ``None`` when nothing was minted.

    Concurrent first-start is idempotent: a ``state_dir`` flock serializes
    minting; if a peer already minted after a SQLite lock race, return ``None``
    instead of aborting startup. DB-busy is retried — never mapped as a bare
    persist failure when an admin already exists.
    """
    if not settings.security.api_key_required:
        return None
    from js.web.auth import AuthManager

    key_file = settings.state_dir / "bootstrap_admin_key.txt"
    deadline = time.monotonic() + 10.0
    attempt = 0

    with _bootstrap_provision_lock(settings.state_dir):
        # Another process may have finished while we waited for the flock.
        if _peer_has_admin(settings.state_dir):
            return None

        while True:
            persisted = False

            def persist(plaintext: str) -> None:
                nonlocal persisted
                # Look up through js.web.server so existing monkeypatches on the
                # facade path still wrap the write used by first-run provisioning.
                from js.web import server as web_server

                persist_fn = getattr(
                    web_server, "_persist_bootstrap_admin_key", _persist_bootstrap_admin_key
                )
                persist_fn(key_file, plaintext)
                persisted = True

            try:
                key = AuthManager(settings.state_dir).ensure_bootstrap_admin_key(persist)
            except Exception as exc:
                if persisted:
                    try:
                        key_file.unlink()
                    except FileNotFoundError:
                        pass
                # Peer won the mint race (or finished while we retried).
                if _peer_has_admin(settings.state_dir):
                    return None
                locked = isinstance(exc, sqlite3.OperationalError) and _is_locked_or_busy(exc)
                if not locked or time.monotonic() >= deadline:
                    logger.warning(
                        "Could not persist bootstrap admin key; refusing to start "
                        "with an unrecoverable key",
                        error_type=type(exc).__name__,
                    )
                    raise RuntimeError(
                        "Could not persist bootstrap admin key; startup aborted"
                    ) from None
                time.sleep(min(0.05 * (2**attempt), 0.25))
                attempt += 1
                continue

            if not key:
                return None
            logger.warning(
                "Bootstrap admin key created for first run; saved to %s", key_file
            )
            return key


def _persist_bootstrap_admin_key(path: Path, key: str) -> None:
    """Atomically persist a bootstrap credential with private permissions."""
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    temp_path = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp")
    fd = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    installed = False
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = -1
            handle.write(key + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
        installed = True
        os.chmod(path, 0o600)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except Exception:
        if installed:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        raise
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass


def consume_bootstrap_admin_key_file(state_dir: Path) -> bool:
    """Delete the plaintext recovery file after a successful explicit login.

    Bootstrap minting leaves the file so a headless operator can still read
    it. The next ``/api/auth/session`` or ``/api/appshell/session`` exchange
    consumes it. Symlinks and non-regular files are left untouched.
    """
    path = Path(state_dir) / "bootstrap_admin_key.txt"
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        logger.warning(
            "Could not inspect bootstrap admin key file",
            error_type=type(exc).__name__,
        )
        return False
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        logger.warning("Refusing to consume a non-regular bootstrap admin key file")
        return False
    try:
        path.unlink()
    except FileNotFoundError:
        return False
    except OSError as exc:
        logger.warning(
            "Could not delete bootstrap admin key file after login",
            error_type=type(exc).__name__,
        )
        return False
    logger.warning("Consumed bootstrap admin key file after first login: %s", path)
    return True
