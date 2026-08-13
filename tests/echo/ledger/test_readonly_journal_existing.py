"""Existing-only readonly journal API: zero create, repair, or path reopen."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from js.echo.ledger.journal import (
    FileEchoLedger,
    read_verified_logical_records_existing,
    read_verified_records_existing,
)


def _open_existing(path: Path) -> int:
    return os.open(
        path,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
    )


def test_read_verified_records_existing_matches_writer(tmp_path: Path) -> None:
    journal_path = tmp_path / "chat.jsonl"
    mac_key = b"k" * 32
    writer = FileEchoLedger(journal_path, mac_key=mac_key)
    writer.append(
        record_type="approval",
        tenant_id="owner-a",
        run_id="run-a",
        payload={"event_type": "approval_approved", "request_id": "r1"},
    )
    expected = writer.records
    fd = _open_existing(journal_path)
    try:
        records = read_verified_records_existing(journal_fd=fd, mac_key=mac_key)
    finally:
        os.close(fd)
    assert records == expected


def test_read_verified_records_existing_does_not_construct_writer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    journal_path = tmp_path / "chat.jsonl"
    mac_key = b"k" * 32
    writer = FileEchoLedger(journal_path, mac_key=mac_key)
    writer.append(
        record_type="decision",
        tenant_id="owner-a",
        run_id="run-a",
        payload={"decision_id": "d1"},
    )
    expected = writer.records

    def _forbidden_init(self: FileEchoLedger, *args: Any, **kwargs: Any) -> None:
        raise AssertionError("FileEchoLedger must not be constructed")

    monkeypatch.setattr(FileEchoLedger, "__init__", _forbidden_init)
    fd = _open_existing(journal_path)
    try:
        records = read_verified_records_existing(journal_fd=fd, mac_key=mac_key)
    finally:
        os.close(fd)
    assert records == expected


def test_read_verified_records_existing_corrupt_tail_is_side_effect_free(
    tmp_path: Path,
) -> None:
    journal_path = tmp_path / "chat.jsonl"
    mac_key = b"k" * 32
    writer = FileEchoLedger(journal_path, mac_key=mac_key)
    writer.append(
        record_type="decision",
        tenant_id="owner-a",
        run_id="run-a",
        payload={"decision_id": "d1"},
    )
    before = journal_path.read_bytes()
    journal_path.write_bytes(before + b"\n{not-json")
    after_write = journal_path.read_bytes()
    inode = journal_path.stat().st_ino
    fd = _open_existing(journal_path)
    try:
        with pytest.raises(ValueError):
            read_verified_records_existing(journal_fd=fd, mac_key=mac_key)
    finally:
        os.close(fd)
    assert journal_path.read_bytes() == after_write
    assert journal_path.stat().st_ino == inode
    assert not any(path.name.endswith(".corrupt") for path in tmp_path.iterdir())


def test_read_verified_logical_records_existing_reads_compacted_archive(
    tmp_path: Path,
) -> None:
    journal_path = tmp_path / "chat.jsonl"
    mac_key = b"k" * 32
    writer = FileEchoLedger(journal_path, mac_key=mac_key)
    for index in range(4):
        writer.append(
            record_type="decision",
            tenant_id="owner-a",
            run_id=f"run-{index}",
            payload={"decision_id": f"d{index}"},
        )
    assert writer.compact(max_records=1) is True
    expected = writer.verified_logical_records()
    archive_path = journal_path.with_suffix(journal_path.suffix + ".archive.sqlite3")
    journal_fd = _open_existing(journal_path)
    archive_fd = _open_existing(archive_path)
    try:
        records = read_verified_logical_records_existing(
            journal_fd=journal_fd,
            mac_key=mac_key,
            archive_fd=archive_fd,
        )
    finally:
        os.close(archive_fd)
        os.close(journal_fd)
    assert [(record.record_type, record.run_id) for record in records] == [
        (record.record_type, record.run_id) for record in expected
    ]
