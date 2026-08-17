"""Desktop webview CSP and DOM-sink regression (Phase 1E)."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DESKTOP_SRC = ROOT / "desktop" / "src"


def test_index_html_keeps_fail_closed_csp() -> None:
    source = (DESKTOP_SRC / "index.html").read_text(encoding="utf-8")
    assert "default-src 'none'" in source
    assert "object-src 'none'" in source
    assert "base-uri 'none'" in source
    assert "script-src" not in source


def test_recovery_html_keeps_strict_csp_and_textcontent() -> None:
    source = (DESKTOP_SRC / "recovery.html").read_text(encoding="utf-8")
    assert "default-src 'none'" in source
    assert "object-src 'none'" in source
    assert "title.textContent" in source
    assert "message.textContent" in source
    assert "innerHTML" not in source
    assert "eval(" not in source


def test_desktop_src_has_no_dom_xss_sinks() -> None:
    forbidden = ("innerHTML", "outerHTML", "document.write", "eval(")
    hits: list[str] = []
    for path in DESKTOP_SRC.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in {".html", ".js", ".ts"}:
            continue
        text = path.read_text(encoding="utf-8")
        for token in forbidden:
            if token in text:
                hits.append(f"{path.relative_to(ROOT)}:{token}")
    assert hits == []
