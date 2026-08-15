"""Killable subprocess budget for PDF/XLSX/Work document parsers."""

from __future__ import annotations

import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, BinaryIO

MAX_PARSE_OUTPUT_BYTES = 262_144
MAX_PARSE_WALL_SECONDS = 8.0
MAX_PARSE_RSS_MB = 256
MAX_PARSE_PIDS = 8
MAX_PDF_PAGES = 32
MAX_XLSX_CELLS = 20_000


class ParseBudgetError(RuntimeError):
    """Document parsing exceeded a local resource budget."""


def extract_pdf_text(source: Path | BinaryIO) -> str:
    _require_optional_import({"pypdf", "pdfplumber"}, "js-agent[pdf]")
    return run_bounded_document_parse("pdf", source)


def extract_excel_text(source: Path | BinaryIO) -> str:
    _require_optional_import({"pandas", "openpyxl"}, "js-agent[office]")
    return run_bounded_document_parse("xlsx", source)


def extract_work_pdf(source: Path | BinaryIO) -> dict[str, Any]:
    raw = run_bounded_document_parse("work_pdf", source)
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ParseBudgetError("document parser returned invalid json") from exc
    if not isinstance(payload, dict):
        raise ParseBudgetError("document parser returned invalid json")
    if payload.get("ok") is not True:
        raise ValueError(str(payload.get("error") or "PDF parse failed"))
    return payload


def run_bounded_document_parse(kind: str, source: Path | BinaryIO) -> str:
    snapshot = _snapshot_source(source)
    try:
        return _spawn_parse_worker(kind, snapshot)
    finally:
        try:
            os.unlink(snapshot)
        except FileNotFoundError:
            pass


def _require_optional_import(names: set[str], extra: str) -> None:
    for name in names:
        try:
            __import__(name)
            return
        except ImportError:
            continue
    raise ImportError(f"Install {extra} to extract this document type.")


def _snapshot_source(source: Path | BinaryIO) -> str:
    with tempfile.NamedTemporaryFile(prefix="js-parse-", suffix=".bin", delete=False) as handle:
        if isinstance(source, Path):
            payload = Path(source).read_bytes()
        else:
            source.seek(0)
            payload = source.read()
            try:
                source.seek(0)
            except Exception:
                pass
        if len(payload) > 8 * 1024 * 1024:
            raise ParseBudgetError("document exceeds input byte budget")
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
        mode = os.fstat(handle.fileno()).st_mode
        if not stat.S_ISREG(mode):
            raise ParseBudgetError("parser snapshot is not a regular file")
        return handle.name


def _spawn_parse_worker(kind: str, snapshot_path: str) -> str:
    env = {
        "PATH": "/usr/bin:/bin",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    proc = subprocess.Popen(
        [
            sys.executable,
            "-I",
            "-m",
            "js.security.parse_worker",
            kind,
            snapshot_path,
            str(MAX_PDF_PAGES),
            str(MAX_XLSX_CELLS),
            str(MAX_PARSE_OUTPUT_BYTES),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        start_new_session=True,
    )
    deadline = time.monotonic() + MAX_PARSE_WALL_SECONDS
    try:
        while proc.poll() is None:
            if time.monotonic() > deadline:
                _kill_group(proc)
                raise ParseBudgetError("document parser exceeded wall-clock budget")
            rss_mb, pids = _tree_usage(proc.pid)
            if rss_mb > MAX_PARSE_RSS_MB:
                _kill_group(proc)
                raise ParseBudgetError("document parser exceeded RSS budget")
            if pids > MAX_PARSE_PIDS:
                _kill_group(proc)
                raise ParseBudgetError("document parser exceeded process budget")
            time.sleep(0.05)
        stdout, _stderr = proc.communicate(timeout=1)
    except ParseBudgetError:
        raise
    except Exception:
        _kill_group(proc)
        raise ParseBudgetError("document parser failed closed") from None
    if proc.returncode != 0:
        raise ParseBudgetError("document parser failed closed")
    if len(stdout) > MAX_PARSE_OUTPUT_BYTES:
        raise ParseBudgetError("document parser exceeded output budget")
    return stdout.decode("utf-8", errors="replace")


def _tree_usage(pid: int) -> tuple[float, int]:
    try:
        import psutil  # type: ignore[import-untyped]
    except ImportError:
        return 0.0, 1
    try:
        root = psutil.Process(pid)
        processes = [root, *root.children(recursive=True)]
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.Error):
        return 0.0, 0
    rss = 0
    live = 0
    for process in processes:
        try:
            rss += int(process.memory_info().rss)
            live += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.Error):
            continue
    return rss / (1024 * 1024), live


def _kill_group(proc: subprocess.Popen[Any]) -> None:
    if proc.pid and os.name == "posix":
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            pass
    try:
        proc.kill()
    except (ProcessLookupError, OSError):
        pass
