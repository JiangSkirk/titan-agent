"""Attachment parsing helpers extracted from JSAgent."""

from __future__ import annotations

from js.security.bounded_parse import extract_excel_text, extract_pdf_text

__all__ = ["extract_excel_text", "extract_pdf_text", "format_size"]


def format_size(size_bytes: int) -> str:
    """Format byte size to human-readable string."""
    size = float(size_bytes)
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"
