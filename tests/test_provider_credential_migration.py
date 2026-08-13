"""B1A migration tests using only tmp_path and an in-memory Keychain."""

from __future__ import annotations

import json
import multiprocessing
import os
import queue
import stat
import subprocess
import sys
import threading
import traceback
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml

from js.provider_credential_types import ProviderCredentialRefV1
from js.security.provider_credential_migration import (
    CredentialMigrationFailed,
    MigrationJournalCorrupt,
    MigrationJournalUnsafe,
    MigrationReceiptV1,
    ProviderCredentialMigrator,
    SourceClearedButKeychainMissing,
    inspect_provider_config,
)
from js.security.provider_credentials import (
    FakeKeychainBackend,
    ProviderCredentialStore,
    fake_keychain_store,
)
from js.security.secrets import SecretManager


def _cross_process_receipt_contender(
    state_path: str,
    events: Any,
) -> None:
    try:
        receipt = MigrationReceiptV1(Path(state_path))
        events.put("ready")
        with receipt.transaction():
            events.put("acquired")
    except BaseException as exc:  # pragma: no cover - surfaced through queue
        events.put(f"error:{type(exc).__name__}")


def _setup(
    tmp_path: Path,
) -> tuple[
    Path,
    ProviderCredentialStore,
    FakeKeychainBackend,
    SecretManager,
    ProviderCredentialMigrator,
]:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    store, backend = fake_keychain_store()
    secrets = SecretManager(state)
    migrator = ProviderCredentialMigrator(
        state,
        store,
        product_id="js-agent",
        secret_manager=secrets,
    )
    return state, store, backend, secrets, migrator


def _yaml_config(
    path: Path,
    *,
    api_key: str | None = None,
    ref: object | None = None,
) -> None:
    provider: dict[str, object] = {
        "name": "example",
        "base_url": "https://provider.example/v1",
        "api_key_env": "NO_LONGER_AUTHORITY",
        "models": [],
    }
    if api_key is not None:
        provider["api_key"] = api_key
    if ref is not None:
        provider["credential_ref"] = ref
    path.write_text(yaml.safe_dump({"providers": [provider]}), encoding="utf-8")
    os.chmod(path, 0o600)


def test_receipt_uses_private_regular_objects(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o755)
    receipt = MigrationReceiptV1(state)
    receipt.begin_migration(
        "example",
        "model_provider",
        "js-agent",
        ref_id="1" * 32,
    )

    assert stat.S_IMODE(state.stat().st_mode) == 0o700
    journal = state / ".provider-credential-migration-v1.json"
    lock = state / ".provider-credential-migration-v1.lock"
    for path in (journal, lock):
        metadata = path.stat()
        assert stat.S_ISREG(metadata.st_mode)
        assert stat.S_IMODE(metadata.st_mode) == 0o600
        assert metadata.st_uid == os.getuid()
        assert metadata.st_nlink == 1


def test_receipt_rejects_symlink_state_directory(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "state"
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(MigrationJournalUnsafe):
        MigrationReceiptV1(link)


def test_receipt_rejects_symlink_in_state_ancestor(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "ancestor"
    link.symlink_to(target, target_is_directory=True)

    with pytest.raises(MigrationJournalUnsafe):
        MigrationReceiptV1(link / "state")

    assert not (target / "state").exists()


def test_receipt_inode_anchor_rejects_directory_swap(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    receipt = MigrationReceiptV1(state)
    receipt.begin_migration(
        "example",
        "model_provider",
        "js-agent",
        ref_id="2" * 32,
    )

    moved = tmp_path / "moved-state"
    state.rename(moved)
    state.mkdir(mode=0o700)

    with pytest.raises(MigrationJournalUnsafe):
        receipt.recover()
    assert not (state / ".provider-credential-migration-v1.lock").exists()


def test_receipt_rejects_immediate_parent_swap(tmp_path: Path) -> None:
    profile = tmp_path / "profile"
    state = profile / "state"
    state.mkdir(parents=True, mode=0o700)
    receipt = MigrationReceiptV1(state)
    moved = tmp_path / "moved-profile"
    profile.rename(moved)
    (profile / "state").mkdir(parents=True, mode=0o700)

    with pytest.raises(MigrationJournalUnsafe):
        receipt.recover()


def test_live_domain_lock_name_unlink_cannot_split_lock_domain(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    first = MigrationReceiptV1(state)
    transaction = first.transaction()
    transaction.__enter__()
    external_lock = first.external_lock_path
    external_lock.unlink()
    second = MigrationReceiptV1(state)
    acquired = threading.Event()
    finished = threading.Event()

    def contender() -> None:
        try:
            with second.transaction():
                acquired.set()
        finally:
            finished.set()

    thread = threading.Thread(target=contender, daemon=True)
    try:
        thread.start()
        assert not acquired.wait(timeout=0.2)
    finally:
        with pytest.raises(MigrationJournalUnsafe, match="lock (?:is unsafe|changed)"):
            transaction.__exit__(None, None, None)
    assert finished.wait(timeout=2)
    assert acquired.is_set()


def test_external_lock_root_rename_cannot_split_cross_process_domain(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    lock_root = tmp_path / "external-locks"
    monkeypatch.setenv("JS_MIGRATION_LOCK_ROOT", str(lock_root))
    config = tmp_path / "config.yaml"
    _yaml_config(config)
    from js.security.provider_credential_migration import provider_config_lease

    lease = provider_config_lease(config)
    lease.__enter__()
    moved = tmp_path / "moved-external-locks"
    lock_root.rename(moved)
    lock_root.mkdir(mode=0o700)
    script = """
import os, sys
from pathlib import Path
os.environ['JS_MIGRATION_LOCK_ROOT'] = sys.argv[1]
from js.security.provider_credential_migration import provider_config_lease
with provider_config_lease(Path(sys.argv[2])):
    print('acquired', flush=True)
"""
    process = subprocess.Popen(  # noqa: S603
        [sys.executable, "-c", script, str(lock_root), str(config)],
        cwd=Path.cwd(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        with pytest.raises(subprocess.TimeoutExpired):
            process.communicate(timeout=0.3)
    finally:
        with pytest.raises(MigrationJournalUnsafe):
            lease.__exit__(None, None, None)
    stdout, stderr = process.communicate(timeout=5)
    assert process.returncode == 0, stderr
    assert stdout.strip() == "acquired"


def test_state_directory_swap_cannot_split_live_lock_domain(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    first = MigrationReceiptV1(state)
    first_transaction = first.transaction()
    first_transaction.__enter__()
    moved = tmp_path / "moved-state"
    state.rename(moved)
    state.mkdir(mode=0o700)
    second = MigrationReceiptV1(state)
    acquired = threading.Event()
    finished = threading.Event()
    errors: list[BaseException] = []

    def contender() -> None:
        try:
            with second.transaction():
                acquired.set()
        except BaseException as exc:  # test captures thread failures
            errors.append(exc)
        finally:
            finished.set()

    thread = threading.Thread(target=contender, daemon=True)
    try:
        thread.start()
        assert not acquired.wait(timeout=0.2)
    finally:
        first_transaction.__exit__(None, None, None)
    assert finished.wait(timeout=2)
    assert not errors
    assert acquired.is_set()


def test_state_directory_swap_remains_single_flight_across_processes(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    first = MigrationReceiptV1(state)
    first_transaction = first.transaction()
    first_transaction.__enter__()
    moved = tmp_path / "moved-state"
    state.rename(moved)
    state.mkdir(mode=0o700)
    context = multiprocessing.get_context("spawn")
    events = context.Queue()
    process = context.Process(
        target=_cross_process_receipt_contender,
        args=(str(state), events),
    )
    try:
        process.start()
        assert events.get(timeout=5) == "ready"
        with pytest.raises(queue.Empty):
            events.get(timeout=0.3)
    finally:
        first_transaction.__exit__(None, None, None)
    try:
        assert events.get(timeout=5) == "acquired"
        process.join(timeout=5)
        assert process.exitcode == 0
    finally:
        if process.is_alive():
            process.terminate()
            process.join(timeout=2)
        events.close()
        events.join_thread()


@pytest.mark.parametrize(
    ("object_name", "operation"),
    [
        (".provider-credential-migration-v1.json", "recover"),
        (".provider-credential-migration-v1.lock", "begin"),
    ],
)
def test_receipt_rejects_fifo_objects_with_nonblocking_open(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    object_name: str,
    operation: str,
) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    os.mkfifo(state / object_name, 0o600)
    original_open = os.open

    def guarded_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        if os.fspath(path) == object_name and not flags & os.O_NONBLOCK:
            raise AssertionError("migration metadata must be opened nonblocking")
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", guarded_open)
    receipt = MigrationReceiptV1(state)
    with pytest.raises(MigrationJournalUnsafe):
        if operation == "recover":
            receipt.recover()
        else:
            receipt.begin_migration(
                "example",
                "model_provider",
                "js-agent",
                ref_id="3" * 32,
            )


@pytest.mark.parametrize(
    ("object_name", "operation"),
    [
        (".provider-credential-migration-v1.json", "recover"),
        (".provider-credential-migration-v1.lock", "begin"),
    ],
)
def test_receipt_rejects_preexisting_bad_mode_metadata(
    tmp_path: Path,
    object_name: str,
    operation: str,
) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    target = state / object_name
    target.write_text(
        '{"schema_version":"ProviderCredentialMigrationV1","entries":[]}\n',
        encoding="utf-8",
    )
    os.chmod(target, 0o640)

    receipt = MigrationReceiptV1(state)
    with pytest.raises(MigrationJournalUnsafe):
        if operation == "recover":
            receipt.recover()
        else:
            receipt.begin_migration(
                "example",
                "model_provider",
                "js-agent",
                ref_id="b" * 32,
            )


@pytest.mark.parametrize(
    ("object_name", "operation"),
    [
        (".provider-credential-migration-v1.json", "recover"),
        (".provider-credential-migration-v1.lock", "begin"),
    ],
)
def test_receipt_rejects_preexisting_hardlinked_metadata(
    tmp_path: Path,
    object_name: str,
    operation: str,
) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    target = state / "attacker-controlled"
    target.write_text(
        '{"schema_version":"ProviderCredentialMigrationV1","entries":[]}\n',
        encoding="utf-8",
    )
    os.chmod(target, 0o600)
    os.link(target, state / object_name)
    assert target.stat().st_nlink == 2

    receipt = MigrationReceiptV1(state)
    with pytest.raises(MigrationJournalUnsafe):
        if operation == "recover":
            receipt.recover()
        else:
            receipt.begin_migration(
                "example",
                "model_provider",
                "js-agent",
                ref_id="c" * 32,
            )


def test_receipt_rejects_journal_over_64_kib(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    journal = state / ".provider-credential-migration-v1.json"
    journal.write_bytes(b"x" * (64 * 1024 + 1))
    os.chmod(journal, 0o600)

    with pytest.raises(MigrationJournalUnsafe):
        MigrationReceiptV1(state).recover()


def test_receipt_rejects_preexisting_lock_over_64_kib(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    lock = state / ".provider-credential-migration-v1.lock"
    lock.write_bytes(b"x" * (64 * 1024 + 1))
    os.chmod(lock, 0o600)

    receipt = MigrationReceiptV1(state)
    with pytest.raises(MigrationJournalUnsafe):
        receipt.begin_migration(
            "example",
            "model_provider",
            "js-agent",
            ref_id="e" * 32,
        )


@pytest.mark.parametrize(
    ("object_name", "operation"),
    [
        (".provider-credential-migration-v1.json", "recover"),
        (".provider-credential-migration-v1.lock", "begin"),
    ],
)
def test_receipt_rejects_bad_owner_via_targeted_fstat_mock(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    object_name: str,
    operation: str,
) -> None:
    """Exercise owner rejection without root, chown, or global fake metadata."""
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    target = state / object_name
    target.write_text(
        '{"schema_version":"ProviderCredentialMigrationV1","entries":[]}\n',
        encoding="utf-8",
    )
    os.chmod(target, 0o600)
    target_inode = target.stat().st_ino
    original_fstat = os.fstat

    def wrong_owner_only_for_target(fd: int) -> object:
        metadata = original_fstat(fd)
        if metadata.st_ino != target_inode:
            return metadata
        return SimpleNamespace(
            st_mode=metadata.st_mode,
            st_uid=os.getuid() + 1,
            st_nlink=metadata.st_nlink,
            st_dev=metadata.st_dev,
            st_ino=metadata.st_ino,
            st_size=metadata.st_size,
            st_mtime_ns=metadata.st_mtime_ns,
            st_ctime_ns=metadata.st_ctime_ns,
        )

    monkeypatch.setattr(os, "fstat", wrong_owner_only_for_target)
    receipt = MigrationReceiptV1(state)
    with pytest.raises(MigrationJournalUnsafe):
        if operation == "recover":
            receipt.recover()
        else:
            receipt.begin_migration(
                "example",
                "model_provider",
                "js-agent",
                ref_id="d" * 32,
            )


@pytest.mark.parametrize(
    "payload",
    [
        {"schema_version": "wrong", "entries": []},
        {"schema_version": "ProviderCredentialMigrationV1", "entries": [], "extra": 1},
        {
            "schema_version": "ProviderCredentialMigrationV1",
            "entries": [
                {
                    "provider_name": "dup",
                    "phase": "prepared",
                    "kind": "model_provider",
                    "product_id": "js-agent",
                    "ref": None,
                    "source": "legacy_store",
                },
                {
                    "provider_name": "dup",
                    "phase": "prepared",
                    "kind": "model_provider",
                    "product_id": "js-agent",
                    "ref": None,
                    "source": "legacy_store",
                },
            ],
        },
    ],
)
def test_receipt_rejects_non_closed_or_duplicate_journal(
    tmp_path: Path,
    payload: dict[str, object],
) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    journal = state / ".provider-credential-migration-v1.json"
    journal.write_text(json.dumps(payload), encoding="utf-8")
    os.chmod(journal, 0o600)
    receipt = MigrationReceiptV1(state)
    with pytest.raises(MigrationJournalCorrupt):
        receipt.recover()


def test_receipt_rejects_non_monotonic_phase_transition(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    receipt = MigrationReceiptV1(state)
    receipt.begin_migration(
        "example",
        "model_provider",
        "js-agent",
        ref_id="4" * 32,
    )

    with pytest.raises(CredentialMigrationFailed):
        receipt.update_phase("example", "config_published")
    pending = receipt.get_pending()
    assert len(pending) == 1
    assert pending[0].phase == "prepared"

    receipt.update_phase("example", "keychain_verified")
    with pytest.raises(CredentialMigrationFailed):
        receipt.update_phase("example", "prepared")
    with pytest.raises(CredentialMigrationFailed):
        receipt.update_phase("example", "keychain_verified", ref_id="5" * 32)


def test_inline_yaml_key_migrates_and_is_removed(tmp_path: Path) -> None:
    _state, store, _backend, _secrets, migrator = _setup(tmp_path)
    config = tmp_path / "config.yaml"
    _yaml_config(config, api_key="inline-secret")

    assert migrator.migrate_static_config(config) is True

    raw = config.read_text(encoding="utf-8")
    assert "inline-secret" not in raw
    assert "NO_LONGER_AUTHORITY" not in raw
    provider = yaml.safe_load(raw)["providers"][0]
    ref = provider["credential_ref"]
    parsed_ref = ProviderCredentialRefV1.model_validate(ref)
    assert store.get(parsed_ref, expected_kind="model_provider") == "inline-secret"
    assert migrator.receipt.recover() is None
    assert stat.S_IMODE(config.stat().st_mode) == 0o600


def test_legacy_secret_store_migrates_only_after_config_publish(tmp_path: Path) -> None:
    _state, store, _backend, secrets, migrator = _setup(tmp_path)
    config = tmp_path / "config.yaml"
    _yaml_config(config)
    secrets.store("static_provider_apikey_example", "legacy-secret")

    assert migrator.migrate_static_config(config) is True
    assert secrets.retrieve("static_provider_apikey_example") is None
    provider = yaml.safe_load(config.read_text(encoding="utf-8"))["providers"][0]
    ref = ProviderCredentialRefV1.model_validate(provider["credential_ref"])
    assert store.require(ref, expected_kind="model_provider") == "legacy-secret"


def test_inline_and_legacy_secret_conflict_is_zero_side_effect(tmp_path: Path) -> None:
    _state, _store, backend, secrets, migrator = _setup(tmp_path)
    config = tmp_path / "config.yaml"
    _yaml_config(config, api_key="inline-secret")
    original = config.read_bytes()
    secrets.store("static_provider_apikey_example", "different-legacy-secret")

    with pytest.raises(CredentialMigrationFailed, match="sources disagree"):
        migrator.migrate_static_config(config)

    assert config.read_bytes() == original
    assert secrets.retrieve("static_provider_apikey_example") == "different-legacy-secret"
    assert backend._store == {}  # noqa: SLF001 - fake backend assertion
    assert migrator.receipt.recover() is None


def test_first_journal_failure_cannot_create_keychain_orphan(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _state, _store, backend, _secrets, migrator = _setup(tmp_path)
    config = tmp_path / "config.yaml"
    _yaml_config(config, api_key="must-not-reach-keychain")

    def fail_journal(*_args: Any, **_kwargs: Any) -> None:
        raise MigrationJournalUnsafe("injected journal failure")

    monkeypatch.setattr(migrator.receipt, "_write_unlocked", fail_journal)
    with pytest.raises(MigrationJournalUnsafe):
        migrator.migrate_static_config(config)

    assert backend._store == {}  # noqa: SLF001 - fake backend assertion
    assert "must-not-reach-keychain" in config.read_text(encoding="utf-8")


def test_config_replacement_after_prepared_intent_is_rejected_before_keychain(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _state, _store, backend, _secrets, migrator = _setup(tmp_path)
    config = tmp_path / "config.yaml"
    _yaml_config(config, api_key="must-not-reach-keychain")
    original_write = migrator.receipt._write_unlocked
    replacement = yaml.safe_dump({"providers": []}).encode()
    replaced = False

    def replace_after_journal(*args: Any, **kwargs: Any) -> None:
        nonlocal replaced
        original_write(*args, **kwargs)
        if not replaced:
            replaced = True
            other = config.with_suffix(".replacement")
            other.write_bytes(replacement)
            os.chmod(other, 0o600)
            os.replace(other, config)

    monkeypatch.setattr(migrator.receipt, "_write_unlocked", replace_after_journal)
    with pytest.raises(CredentialMigrationFailed, match="changed"):
        migrator.migrate_static_config(config)

    assert backend._store == {}  # noqa: SLF001 - fake backend assertion
    assert config.read_bytes() == replacement


def test_config_parent_symlink_is_rejected_without_side_effect(tmp_path: Path) -> None:
    _state, _store, backend, _secrets, migrator = _setup(tmp_path)
    real_parent = tmp_path / "real-config"
    real_parent.mkdir()
    config = real_parent / "config.yaml"
    _yaml_config(config, api_key="must-not-reach-keychain")
    linked_parent = tmp_path / "linked-config"
    linked_parent.symlink_to(real_parent, target_is_directory=True)

    with pytest.raises(CredentialMigrationFailed):
        migrator.migrate_static_config(linked_parent / "config.yaml")

    assert backend._store == {}  # noqa: SLF001 - fake backend assertion
    assert "must-not-reach-keychain" in config.read_text(encoding="utf-8")


def test_public_inspection_rejects_symlink_parent_without_creating_state(
    tmp_path: Path,
) -> None:
    real_parent = tmp_path / "real-config"
    real_parent.mkdir()
    config = real_parent / "config.yaml"
    _yaml_config(config)
    linked_parent = tmp_path / "linked-config"
    linked_parent.symlink_to(real_parent, target_is_directory=True)

    with pytest.raises(CredentialMigrationFailed):
        inspect_provider_config(linked_parent / "config.yaml")

    assert not (tmp_path / "untrusted-state").exists()


def test_public_inspection_rejects_fifo_config_without_blocking(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config = tmp_path / "config.yaml"
    os.mkfifo(config, 0o600)
    original_open = os.open

    def guarded_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        if os.fspath(path) == config.name and not flags & os.O_NONBLOCK:
            raise AssertionError("provider config must be opened nonblocking")
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", guarded_open)
    with pytest.raises(CredentialMigrationFailed):
        inspect_provider_config(config)


def test_config_parent_swap_after_intent_is_rejected_before_keychain(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _state, _store, backend, _secrets, migrator = _setup(tmp_path)
    parent = tmp_path / "config-parent"
    parent.mkdir()
    config = parent / "config.yaml"
    _yaml_config(config, api_key="must-not-reach-keychain")
    original_write = migrator.receipt._write_unlocked
    moved_parent = tmp_path / "moved-config-parent"
    replacement = yaml.safe_dump({"providers": []}).encode()
    replaced = False

    def swap_parent_after_journal(*args: Any, **kwargs: Any) -> None:
        nonlocal replaced
        original_write(*args, **kwargs)
        if not replaced:
            replaced = True
            parent.rename(moved_parent)
            parent.mkdir()
            config.write_bytes(replacement)
            os.chmod(config, 0o600)

    monkeypatch.setattr(migrator.receipt, "_write_unlocked", swap_parent_after_journal)
    with pytest.raises(CredentialMigrationFailed, match="changed"):
        migrator.migrate_static_config(config)

    assert backend._store == {}  # noqa: SLF001 - fake backend assertion
    assert config.read_bytes() == replacement
    assert "must-not-reach-keychain" in (
        moved_parent / "config.yaml"
    ).read_text(encoding="utf-8")


def test_migration_and_cooperating_save_share_config_domain_lock(
    tmp_path: Path,
) -> None:
    _state, _store, _backend, _secrets, migrator = _setup(tmp_path)
    config = tmp_path / "config.yaml"
    _yaml_config(config, api_key="one-secret")
    lease = migrator.config_lease(config)
    lease.__enter__()
    entered = threading.Event()
    finished = threading.Event()

    def contender() -> None:
        try:
            with migrator.config_lease(config):
                entered.set()
        finally:
            finished.set()

    thread = threading.Thread(target=contender, daemon=True)
    try:
        thread.start()
        assert not entered.wait(timeout=0.2)
    finally:
        lease.__exit__(None, None, None)
    assert finished.wait(timeout=2)
    assert entered.is_set()


def test_journal_writes_all_bytes_when_os_write_is_partial(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    original_write = os.write

    def partial_write(fd: int, payload: bytes | bytearray | memoryview) -> int:
        return original_write(fd, bytes(payload[:3]))

    monkeypatch.setattr(os, "write", partial_write)
    receipt = MigrationReceiptV1(state)
    receipt.begin_migration(
        "example",
        "model_provider",
        "js-agent",
        ref_id="6" * 32,
    )

    pending = receipt.get_pending()
    assert len(pending) == 1
    assert pending[0].ref is not None
    assert pending[0].ref.ref_id == "6" * 32


def test_static_migration_fsyncs_temp_files_and_parent_directories(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Bind both journal and config publication to their durability barriers."""
    from js.security import provider_credential_migration as migration

    _state, _store, _backend, _secrets, migrator = _setup(tmp_path)
    config = tmp_path / "config.yaml"
    _yaml_config(config, api_key="durable-secret")
    events: list[str] = []
    fd_names: dict[int, str] = {}
    original_open = os.open
    original_fsync = os.fsync
    original_replace = os.replace
    original_unlink = os.unlink
    original_swap = migration._rename_swap

    def tracked_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        fd = original_open(path, flags, mode, dir_fd=dir_fd)
        fd_names[fd] = os.fsdecode(path)
        return fd

    def tracked_fsync(fd: int) -> None:
        events.append(f"fsync:{fd_names.get(fd, '<directory>')}")
        original_fsync(fd)

    def tracked_replace(
        src: str | bytes,
        dst: str | bytes,
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
    ) -> None:
        events.append(f"replace:{os.fsdecode(src)}->{os.fsdecode(dst)}")
        original_replace(
            src,
            dst,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
        )

    def tracked_unlink(
        path: str | bytes,
        *,
        dir_fd: int | None = None,
    ) -> None:
        events.append(f"unlink:{os.fsdecode(path)}")
        original_unlink(path, dir_fd=dir_fd)

    def tracked_swap(dir_fd: int, left: str, right: str) -> None:
        events.append(f"swap:{left}->{right}")
        original_swap(dir_fd, left, right)

    monkeypatch.setattr(os, "open", tracked_open)
    monkeypatch.setattr(os, "fsync", tracked_fsync)
    monkeypatch.setattr(os, "replace", tracked_replace)
    monkeypatch.setattr(os, "unlink", tracked_unlink)
    monkeypatch.setattr(migration, "_rename_swap", tracked_swap)

    assert migrator.migrate_static_config(config) is True

    journal_temp = ".provider-credential-migration-"
    journal_fsync = next(
        index
        for index, event in enumerate(events)
        if event.startswith(f"fsync:{journal_temp}") and event.endswith(".tmp")
    )
    journal_replace = next(
        index
        for index, event in enumerate(events)
        if event.startswith(f"replace:{journal_temp}")
        and event.endswith("->.provider-credential-migration-v1.json")
    )
    journal_dir_fsync = next(
        index
        for index, event in enumerate(events[journal_replace + 1 :], journal_replace + 1)
        if event.startswith("fsync:") and not event.endswith(".tmp")
    )
    assert journal_fsync < journal_replace < journal_dir_fsync

    config_temp = ".config.yaml.credential-migration-"
    config_fsync = next(
        index
        for index, event in enumerate(events)
        if event.startswith(f"fsync:{config_temp}") and event.endswith(".tmp")
    )
    config_swap = next(
        index
        for index, event in enumerate(events)
        if event.startswith(f"swap:{config_temp}") and event.endswith("->config.yaml")
    )
    config_unlink = next(
        index
        for index, event in enumerate(events[config_swap + 1 :], config_swap + 1)
        if event.startswith(f"unlink:{config_temp}")
    )
    config_dir_fsync = next(
        index
        for index, event in enumerate(events[config_unlink + 1 :], config_unlink + 1)
        if event.startswith("fsync:") and not event.endswith(".tmp")
    )
    assert config_fsync < config_swap < config_unlink < config_dir_fsync


@pytest.mark.parametrize(
    ("failure_point", "expected_error"),
    [
        ("journal_temp_fsync", MigrationJournalUnsafe),
        ("config_temp_fsync", CredentialMigrationFailed),
        ("journal_replace", MigrationJournalUnsafe),
        ("journal_parent_fsync", MigrationJournalUnsafe),
        ("config_swap", CredentialMigrationFailed),
        ("config_parent_fsync", CredentialMigrationFailed),
    ],
)
def test_static_durable_primitive_failure_is_closed_and_restart_converges(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    failure_point: str,
    expected_error: type[Exception],
) -> None:
    from js.security import provider_credential_migration as migration

    state, store, backend, secrets, migrator = _setup(tmp_path)
    config = tmp_path / "config.yaml"
    secret = "durable-failure-secret"
    _yaml_config(config, api_key=secret)
    fd_names: dict[int, str] = {}
    injected = False
    journal_replaced = False
    config_swapped = False
    original_open = os.open
    original_fsync = os.fsync
    original_replace = os.replace
    original_swap = migration._rename_swap

    def fail_once() -> None:
        nonlocal injected
        injected = True
        raise OSError("private durable driver detail")

    def tracked_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        fd = original_open(path, flags, mode, dir_fd=dir_fd)
        fd_names[fd] = os.fsdecode(path)
        return fd

    def injected_fsync(fd: int) -> None:
        name = fd_names.get(fd, "")
        if not injected and (
            (
                failure_point == "journal_temp_fsync"
                and name.startswith(".provider-credential-migration-")
                and name.endswith(".tmp")
            )
            or (
                failure_point == "config_temp_fsync"
                and name.startswith(".config.yaml.credential-migration-")
                and name.endswith(".tmp")
            )
            or (failure_point == "journal_parent_fsync" and journal_replaced)
            or (failure_point == "config_parent_fsync" and config_swapped)
        ):
            fail_once()
        original_fsync(fd)

    def injected_replace(
        src: str | bytes,
        dst: str | bytes,
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
    ) -> None:
        nonlocal journal_replaced
        if (
            not injected
            and failure_point == "journal_replace"
            and os.fsdecode(dst) == ".provider-credential-migration-v1.json"
        ):
            fail_once()
        original_replace(
            src,
            dst,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
        )
        if os.fsdecode(dst) == ".provider-credential-migration-v1.json":
            journal_replaced = True

    def injected_swap(dir_fd: int, left: str, right: str) -> None:
        nonlocal config_swapped
        if not injected and failure_point == "config_swap" and right == config.name:
            fail_once()
        original_swap(dir_fd, left, right)
        if right == config.name:
            config_swapped = True

    with monkeypatch.context() as failure:
        failure.setattr(os, "open", tracked_open)
        failure.setattr(os, "fsync", injected_fsync)
        failure.setattr(os, "replace", injected_replace)
        failure.setattr(migration, "_rename_swap", injected_swap)
        with pytest.raises(expected_error) as captured:
            migrator.migrate_static_config(config)

    assert injected is True
    message = str(captured.value)
    assert secret not in message
    assert "private" not in message
    assert str(config) not in message

    interrupted = inspect_provider_config(config)["providers"][0]
    if interrupted.get("api_key") == secret:
        assert interrupted.get("credential_ref") is None
    else:
        interrupted_ref = ProviderCredentialRefV1.model_validate(
            interrupted["credential_ref"]
        )
        assert store.require(
            interrupted_ref,
            expected_kind="model_provider",
        ) == secret

    restarted = ProviderCredentialMigrator(
        state,
        store,
        product_id="js-agent",
        secret_manager=secrets,
    )
    restarted.migrate_static_config(config)

    final_provider = inspect_provider_config(config)["providers"][0]
    assert "api_key" not in final_provider
    assert "api_key_env" not in final_provider
    final_ref = ProviderCredentialRefV1.model_validate(
        final_provider["credential_ref"]
    )
    assert store.require(final_ref, expected_kind="model_provider") == secret
    assert restarted.receipt.recover() is None
    assert len(backend._store) == 1  # noqa: SLF001 - no credential orphan


def test_config_write_all_and_original_inode_check_prevent_overwrite(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _state, store, _backend, _secrets, migrator = _setup(tmp_path)
    config = tmp_path / "config.yaml"
    _yaml_config(config, api_key="journal-tracked-secret")
    replacement = yaml.safe_dump({"providers": []}).encode()
    original_write = os.write
    swapped = False

    def partial_write_and_swap(
        fd: int,
        payload: bytes | bytearray | memoryview,
    ) -> int:
        nonlocal swapped
        raw = bytes(payload)
        count = original_write(fd, raw[:5])
        if not swapped and b"credential_ref:" in raw:
            swapped = True
            other = config.with_suffix(".replacement")
            other.write_bytes(replacement)
            os.chmod(other, 0o600)
            os.replace(other, config)
        return count

    monkeypatch.setattr(os, "write", partial_write_and_swap)
    with pytest.raises(CredentialMigrationFailed, match="changed"):
        migrator.migrate_static_config(config)

    assert swapped is True
    assert config.read_bytes() == replacement
    pending = migrator.receipt.get_pending()
    assert len(pending) == 1 and pending[0].ref is not None
    assert store.require(pending[0].ref, expected_kind="model_provider") == (
        "journal-tracked-secret"
    )


def test_atomic_swap_restores_noncooperating_config_replacement(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _state, _store, _backend, _secrets, migrator = _setup(tmp_path)
    config = tmp_path / "config.yaml"
    _yaml_config(config, api_key="journal-tracked-secret")
    competitor = yaml.safe_dump({"competitor": True}).encode()
    from js.security import provider_credential_migration as migration

    original_swap = migration._rename_swap
    raced = False

    def install_competitor_then_swap(dir_fd: int, left: str, right: str) -> None:
        nonlocal raced
        if not raced:
            raced = True
            other = config.with_suffix(".competitor")
            other.write_bytes(competitor)
            os.chmod(other, 0o600)
            os.replace(other, config)
        original_swap(dir_fd, left, right)

    monkeypatch.setattr(migration, "_rename_swap", install_competitor_then_swap)
    with pytest.raises(CredentialMigrationFailed, match="changed"):
        migrator.migrate_static_config(config)

    assert raced is True
    assert config.read_bytes() == competitor


def test_toml_static_migration_round_trip(tmp_path: Path) -> None:
    _state, store, _backend, _secrets, migrator = _setup(tmp_path)
    config = tmp_path / "config.toml"
    config.write_text(
        """
[[providers]]
name = "example"
base_url = "https://provider.example/v1"
api_key = "toml-secret"
api_key_env = "NO_LONGER_AUTHORITY"
models = []
""".strip()
        + "\n",
        encoding="utf-8",
    )
    os.chmod(config, 0o600)

    assert migrator.migrate_static_config(config) is True

    document = inspect_provider_config(config)
    provider = document["providers"][0]
    assert "api_key" not in provider
    assert "api_key_env" not in provider
    ref = ProviderCredentialRefV1.model_validate(provider["credential_ref"])
    assert store.require(ref, expected_kind="model_provider") == "toml-secret"
    assert migrator.receipt.recover() is None


@pytest.mark.parametrize("suffix", (".YAML", ".YML", ".TOML"))
def test_uppercase_static_config_suffixes_migrate_consistently(
    tmp_path: Path,
    suffix: str,
) -> None:
    _state, store, _backend, _secrets, migrator = _setup(tmp_path)
    config = tmp_path / f"config{suffix}"
    if suffix.lower() == ".toml":
        config.write_text(
            '[[providers]]\nname="example"\nbase_url="https://example.test"\n'
            'api_key="upper-secret"\nmodels=[]\n',
            encoding="utf-8",
        )
    else:
        _yaml_config(config, api_key="upper-secret")
    os.chmod(config, 0o600)

    assert migrator.migrate_static_config(config) is True
    provider = inspect_provider_config(config)["providers"][0]
    ref = ProviderCredentialRefV1.model_validate(provider["credential_ref"])
    assert store.require(ref, expected_kind="model_provider") == "upper-secret"


@pytest.mark.parametrize("kind", ("dangling", "unsupported_missing"))
def test_invalid_config_target_rejected_before_state_or_keychain_effect(
    tmp_path: Path,
    kind: str,
) -> None:
    state = tmp_path / "state"
    store, backend = fake_keychain_store()
    target = tmp_path / ("dangling.yaml" if kind == "dangling" else "missing.txt")
    if kind == "dangling":
        target.symlink_to(tmp_path / "does-not-exist")

    with pytest.raises(CredentialMigrationFailed):
        ProviderCredentialMigrator.migrate_paths_preflight(
            target,
            state_dir=state,
            product_id="js-agent",
        )

    assert not state.exists()
    assert backend._store == {}  # noqa: SLF001


def test_publish_failure_keeps_source_and_restart_converges(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _state, store, _backend, _secrets, migrator = _setup(tmp_path)
    config = tmp_path / "config.yaml"
    _yaml_config(config, api_key="survives-publish-failure")
    original_publish = migrator._publish_config

    def fail_publish(*_args: Any, **_kwargs: Any) -> None:
        raise CredentialMigrationFailed("injected publication failure")

    monkeypatch.setattr(migrator, "_publish_config", fail_publish)
    with pytest.raises(CredentialMigrationFailed):
        migrator.migrate_static_config(config)
    assert "survives-publish-failure" in config.read_text(encoding="utf-8")
    pending = migrator.receipt.get_pending()
    assert len(pending) == 1 and pending[0].ref is not None
    assert store.require(pending[0].ref, expected_kind="model_provider") == (
        "survives-publish-failure"
    )

    monkeypatch.setattr(migrator, "_publish_config", original_publish)
    assert migrator.migrate_static_config(config) is True
    assert "survives-publish-failure" not in config.read_text(encoding="utf-8")
    assert migrator.receipt.recover() is None


@pytest.mark.parametrize("cleanup_failure", ("delete_raises", "delete_still_reads"))
def test_legacy_cleanup_failure_preserves_journal_and_restart_converges(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    cleanup_failure: str,
) -> None:
    state, store, backend, secrets, migrator = _setup(tmp_path)
    config = tmp_path / "config.yaml"
    _yaml_config(config)
    legacy_name = "static_provider_apikey_example"
    secrets.store(legacy_name, "restart-after-cleanup-secret")
    original_delete = secrets.delete

    if cleanup_failure == "delete_raises":

        def failed_delete(_name: str) -> None:
            raise RuntimeError("private legacy delete detail")

    else:

        def failed_delete(_name: str) -> None:
            return None

    monkeypatch.setattr(secrets, "delete", failed_delete)
    with pytest.raises(
        CredentialMigrationFailed,
        match="legacy credential cleanup failed",
    ):
        migrator.migrate_static_config(config)

    pending = migrator.receipt.get_pending()
    assert len(pending) == 1
    assert pending[0].phase == "config_published"
    assert "restart-after-cleanup-secret" not in config.read_text(encoding="utf-8")
    assert secrets.retrieve(legacy_name) == "restart-after-cleanup-secret"

    monkeypatch.setattr(secrets, "delete", original_delete)
    restarted = ProviderCredentialMigrator(
        state,
        store,
        product_id="js-agent",
        secret_manager=secrets,
    )
    assert restarted.migrate_static_config(config) is False
    assert secrets.retrieve(legacy_name) is None
    assert restarted.receipt.recover() is None
    assert len(backend._store) == 1  # noqa: SLF001 - recovered without orphan


@pytest.mark.parametrize("failed_journal_write", [1, 2, 3, 4, 5])
def test_every_static_durable_phase_restart_converges(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    failed_journal_write: int,
) -> None:
    state, store, backend, secrets, migrator = _setup(tmp_path)
    config = tmp_path / "config.yaml"
    _yaml_config(config)
    secrets.store("static_provider_apikey_example", "restart-secret")
    original_write = migrator.receipt._write_unlocked
    calls = 0

    def fail_selected_write(*args: Any, **kwargs: Any) -> None:
        nonlocal calls
        calls += 1
        if calls == failed_journal_write:
            raise MigrationJournalUnsafe("injected durable phase failure")
        original_write(*args, **kwargs)

    monkeypatch.setattr(migrator.receipt, "_write_unlocked", fail_selected_write)
    with pytest.raises(MigrationJournalUnsafe):
        migrator.migrate_static_config(config)
    monkeypatch.setattr(migrator.receipt, "_write_unlocked", original_write)

    restarted = ProviderCredentialMigrator(
        state,
        store,
        product_id="js-agent",
        secret_manager=secrets,
    )
    restarted.migrate_static_config(config)

    provider = inspect_provider_config(config)["providers"][0]
    ref = ProviderCredentialRefV1.model_validate(provider["credential_ref"])
    assert store.require(ref, expected_kind="model_provider") == "restart-secret"
    assert secrets.retrieve("static_provider_apikey_example") is None
    assert restarted.receipt.recover() is None
    assert len(backend._store) == 1  # noqa: SLF001 - no orphan after recovery


def test_missing_keychain_after_config_publish_is_fatal(tmp_path: Path) -> None:
    _state, store, _backend, _secrets, migrator = _setup(tmp_path)
    missing = {
        "ref_id": "a" * 32,
        "product_id": "js-agent",
        "kind": "model_provider",
    }
    config = tmp_path / "config.yaml"
    _yaml_config(config, ref=missing)
    with pytest.raises(SourceClearedButKeychainMissing):
        migrator.migrate_static_config(config)


def test_config_and_journal_reference_mismatch_is_rejected(tmp_path: Path) -> None:
    _state, store, _backend, _secrets, migrator = _setup(tmp_path)
    config_ref = store.put_verified("js-agent", "model_provider", "config-secret")
    journal_ref = store.put_verified("js-agent", "model_provider", "journal-secret")
    config = tmp_path / "config.yaml"
    _yaml_config(config, ref=config_ref.model_dump(mode="json"))
    original = config.read_bytes()
    migrator.receipt.begin_migration(
        "example",
        "model_provider",
        "js-agent",
        ref_id=journal_ref.ref_id,
    )
    migrator.receipt.update_phase("example", "keychain_verified")

    with pytest.raises(CredentialMigrationFailed, match="reference"):
        migrator.migrate_static_config(config)

    assert config.read_bytes() == original
    assert store.require(config_ref, expected_kind="model_provider") == "config-secret"
    assert store.require(journal_ref, expected_kind="model_provider") == "journal-secret"


def test_dynamic_migration_without_atomic_provider_store_fails_closed(tmp_path: Path) -> None:
    _state, _store, _backend, secrets, migrator = _setup(tmp_path)
    secrets.store("provider_apikey_example", "must-not-be-deleted")
    with pytest.raises(CredentialMigrationFailed, match="store transaction"):
        migrator.migrate_dynamic_provider("example", "provider_apikey_example")
    assert secrets.retrieve("provider_apikey_example") == "must-not-be-deleted"


def test_same_provider_migration_is_single_flight(tmp_path: Path) -> None:
    _state, _store, _backend, _secrets, migrator = _setup(tmp_path)
    config = tmp_path / "config.yaml"
    _yaml_config(config, api_key="one-secret")
    results: list[bool] = []
    errors: list[BaseException] = []
    error_traces: list[str] = []

    def worker() -> None:
        try:
            results.append(migrator.migrate_static_config(config))
        except BaseException as exc:  # test captures thread failures
            errors.append(exc)
            error_traces.append(traceback.format_exc())

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)
    assert not errors, error_traces
    assert sorted(results) == [False, True]
    assert migrator.receipt.recover() is None


def test_search_staging_journal_precedes_keychain_write(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _state, _store, backend, _secrets, migrator = _setup(tmp_path)

    def fail_journal(*_args: Any, **_kwargs: Any) -> None:
        raise MigrationJournalUnsafe("injected journal failure")

    monkeypatch.setattr(migrator.receipt, "_write_unlocked", fail_journal)
    with pytest.raises(MigrationJournalUnsafe):
        migrator.stage_search_credential("search-secret")
    assert backend._store == {}  # noqa: SLF001 - fake backend assertion


def test_search_second_journal_failure_after_keychain_write_recovers_orphan(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    state, store, backend, secrets, migrator = _setup(tmp_path)
    config = tmp_path / "config.yaml"
    _yaml_config(config)
    original_write = migrator.receipt._write_unlocked
    writes = 0

    def fail_second_write(*args: Any, **kwargs: Any) -> None:
        nonlocal writes
        writes += 1
        if writes == 2:
            raise MigrationJournalUnsafe("injected verified journal failure")
        original_write(*args, **kwargs)

    monkeypatch.setattr(migrator.receipt, "_write_unlocked", fail_second_write)
    with pytest.raises(MigrationJournalUnsafe):
        migrator.stage_search_credential("orphan-after-write-secret")

    pending = migrator.receipt.get_pending()
    assert len(pending) == 1
    assert pending[0].phase == "prepared"
    assert pending[0].ref is not None
    assert store.require(
        pending[0].ref,
        expected_kind="search_provider",
    ) == "orphan-after-write-secret"

    restarted = ProviderCredentialMigrator(
        state,
        store,
        product_id="js-agent",
        secret_manager=secrets,
    )
    assert restarted.recover_search_credential(config) is None
    assert restarted.receipt.recover() is None
    assert backend._store == {}  # noqa: SLF001 - unpublished key removed


def test_search_save_failure_restart_removes_orphan(tmp_path: Path) -> None:
    state, store, _backend, secrets, migrator = _setup(tmp_path)
    config = tmp_path / "config.yaml"
    _yaml_config(config)

    ref = migrator.stage_search_credential("search-secret")
    assert store.require(ref, expected_kind="search_provider") == "search-secret"

    restarted = ProviderCredentialMigrator(
        state,
        store,
        product_id="js-agent",
        secret_manager=secrets,
    )
    assert restarted.recover_search_credential(config) is None
    assert store.get(ref, expected_kind="search_provider") is None
    assert restarted.receipt.recover() is None


def test_search_crash_after_config_save_preserves_committed_secret(tmp_path: Path) -> None:
    state, store, _backend, secrets, migrator = _setup(tmp_path)
    config = tmp_path / "config.yaml"
    _yaml_config(config)
    ref = migrator.stage_search_credential("search-secret")
    document = yaml.safe_load(config.read_text(encoding="utf-8"))
    document["search_credential_ref"] = ref.model_dump(mode="json")
    config.write_text(yaml.safe_dump(document), encoding="utf-8")
    os.chmod(config, 0o600)

    restarted = ProviderCredentialMigrator(
        state,
        store,
        product_id="js-agent",
        secret_manager=secrets,
    )
    assert restarted.recover_search_credential(config) == ref
    assert store.require(ref, expected_kind="search_provider") == "search-secret"
    assert restarted.receipt.recover() is None


def test_search_commit_requires_persisted_matching_reference(tmp_path: Path) -> None:
    _state, store, _backend, _secrets, migrator = _setup(tmp_path)
    config = tmp_path / "config.yaml"
    _yaml_config(config)
    ref = migrator.stage_search_credential("search-secret")

    with pytest.raises(CredentialMigrationFailed, match="reference"):
        migrator.commit_search_credential(ref, config_path=config)

    assert store.require(ref, expected_kind="search_provider") == "search-secret"
    pending = migrator.receipt.get_pending()
    assert len(pending) == 1
    assert pending[0].kind == "search_provider"


@pytest.mark.parametrize("failed_commit_write", (1, 2, 3))
def test_each_search_commit_journal_failure_restart_converges(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    failed_commit_write: int,
) -> None:
    state, store, _backend, secrets, migrator = _setup(tmp_path)
    config = tmp_path / "config.yaml"
    _yaml_config(config)
    ref = migrator.stage_search_credential("committed-search-secret")
    document = yaml.safe_load(config.read_text(encoding="utf-8"))
    document["search_credential_ref"] = ref.model_dump(mode="json")
    config.write_text(yaml.safe_dump(document), encoding="utf-8")
    os.chmod(config, 0o600)
    original_write = migrator.receipt._write_unlocked
    writes = 0

    def fail_selected_write(*args: Any, **kwargs: Any) -> None:
        nonlocal writes
        writes += 1
        if writes == failed_commit_write:
            raise MigrationJournalUnsafe("injected commit journal failure")
        original_write(*args, **kwargs)

    monkeypatch.setattr(migrator.receipt, "_write_unlocked", fail_selected_write)
    with pytest.raises(MigrationJournalUnsafe):
        migrator.commit_search_credential(ref, config_path=config)

    assert store.require(ref, expected_kind="search_provider") == (
        "committed-search-secret"
    )
    restarted = ProviderCredentialMigrator(
        state,
        store,
        product_id="js-agent",
        secret_manager=secrets,
    )
    assert restarted.recover_search_credential(config) == ref
    assert restarted.receipt.recover() is None
    assert store.require(ref, expected_kind="search_provider") == (
        "committed-search-secret"
    )
