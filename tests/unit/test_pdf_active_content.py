from pathlib import Path
from typing import Any

import pytest

from filevet.analyzers.malware.pdf_active_content import PdfActiveContent
from tests.corpus import generators
from tests.helpers import rules, run

RULE = "malware.pdf_active_content"


def _titles(sample_dir: Path, **kwargs: Any) -> dict[str, str]:
    result = run(PdfActiveContent(), generators.pdf(sample_dir, **kwargs))
    return {f.title: f.severity for f in result.findings}


@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [
        (
            {"javascript": "app.alert(1)"},
            {"JavaScript in PDF": "high", "Automatic action in PDF": "high"},
        ),
        (
            {"launch": "C:\\missing\\x.exe"},
            {"Launch action in PDF": "critical", "Automatic action in PDF": "critical"},
        ),
        ({"rich_media": True}, {"Rich media (Flash or video) in PDF": "high"}),
        (
            {"xfa": True, "submit_form": "https://example.invalid"},
            {"XFA form in PDF": "medium", "Form submission in PDF": "medium"},
        ),
        ({"uri": "https://example.invalid"}, {"Link to a URI in PDF": "low"}),
        (
            {"uri": "https://example.invalid", "open_page": True},
            {"Link to a URI in PDF": "medium", "Automatic action in PDF": "medium"},
        ),
        ({"filter_chain": True}, {"Unusual filter chain": "medium"}),
        ({"open_page": True}, {}),
        ({"text": "Invoice\nTotal 10.00 EUR"}, {}),
    ],
)
def test_active_content(kwargs: dict[str, Any], expected: dict[str, str], sample_dir: Path) -> None:
    assert _titles(sample_dir, **kwargs) == expected


def test_hex_obfuscated_names(sample_dir: Path) -> None:
    titles = _titles(sample_dir, javascript="app.alert(1)", obfuscate=True)
    assert titles["Obfuscated PDF names"] == "high"
    assert titles["JavaScript in PDF"] == "high"


def test_javascript_in_object_stream(sample_dir: Path) -> None:
    result = run(PdfActiveContent(), generators.pdf(sample_dir, javascript="x", object_stream=True))
    [js] = [f for f in result.findings if f.title == "JavaScript in PDF"]
    assert "object stream" in js.description


def test_embedded_files_become_children(sample_dir: Path) -> None:
    path = generators.pdf(sample_dir, embedded={"a.csv": ["csv"], "b.exe": ["pe_stub"]})
    result = run(PdfActiveContent(), path)
    assert rules(result) == {RULE: "low"}
    assert [c.data[:4] for c in result.children] == [b"date", b"MZ\0\0"]


@pytest.mark.parametrize("kwargs", [{"truncated": True}, {"bad_startxref": True}])
def test_broken_structure(kwargs: dict[str, bool], sample_dir: Path) -> None:
    assert rules(run(PdfActiveContent(), generators.pdf(sample_dir, **kwargs))) == {
        "parser.malformed": "medium"
    }


def test_minimal_pdf_is_quiet(benign_pdf: Path) -> None:
    assert rules(run(PdfActiveContent(), benign_pdf)) == {}


def test_bad_flate_stream_is_ignored(sample_dir: Path) -> None:
    path = sample_dir / "bad.pdf"
    path.write_bytes(
        b"%PDF-1.7\n1 0 obj\n<< /Filter /FlateDecode /Type /EmbeddedFile >>\nstream\nnot zlib"
        b"\nendstream\nendobj\n%%EOF\n"
    )
    result = run(PdfActiveContent(), path)
    assert [c.data for c in result.children] == [b""]
