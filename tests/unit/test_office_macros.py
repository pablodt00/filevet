from pathlib import Path
from typing import Any

import pytest

from filevet.analyzers.malware.office_macros import OfficeMacros, decompress
from tests.corpus import generators
from tests.helpers import rules, run

RULE = "malware.office_macros"
CELLS = [["a"]]
EXE = "C:\\missing\\filevet.exe"


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (
            'Sub Workbook_Open()\r\nShell "x"\r\nEnd Sub',
            {"Auto-run macro": "critical", "Suspicious macro code": "high"},
        ),
        ("Sub AutoOpen()\r\nEnd Sub", {"Auto-run macro": "high"}),
        (
            'Sub X()\r\nSet o = CreateObject("WScript.Shell")\r\nEnd Sub',
            {"Suspicious macro code": "high"},
        ),
        ('Sub Total()\r\nRange("A1").Value = 1\r\nEnd Sub', {}),
    ],
)
def test_vba_source(source: str, expected: dict[str, str], sample_dir: Path) -> None:
    result = run(OfficeMacros(), generators.ole(sample_dir, name="legacy.xls", vba=source))
    assert {f.title: f.severity for f in result.findings} == {"VBA macros": "medium", **expected}


def test_long_vba_module_spans_chunks(sample_dir: Path) -> None:
    source = "' padding\r\n" * 800 + "Sub Document_Open()\r\nEnd Sub"
    path = generators.ole(sample_dir, name="letter.doc", vba=source)
    assert "Auto-run macro" in {f.title for f in run(OfficeMacros(), path).findings}


def test_decompress_matches_spec_example() -> None:
    data = bytes.fromhex(
        "012FB000236161616263646582660070616768696A01380861"
        "6B6C00306D6E6F7006710270041072737475761077787 97A003C".replace(" ", "")
    )
    assert decompress(data, 1000) == b"#aaabcdefaaaaghijaaaaaklaaamnopqaaaaaaaaaaaarstuvwxyzaaa"


@pytest.mark.parametrize(
    ("generator", "kwargs", "title"),
    [
        ("xlsx", {"cells": CELLS, "vba": ""}, "VBA macros"),
        ("docx", {"name": "a.docm", "vba": ""}, "VBA macros"),
        ("xlsx", {"cells": CELLS, "macro_sheet": True}, "XLM macro sheet"),
        ("xlsx", {"cells": CELLS, "macro_sheet": True}, "Auto-open macro name"),
        ("xlsx", {"cells": CELLS, "dde_link": True}, "DDE field"),
        ("docx", {"dde": f'"{EXE}"'}, "DDE field"),
        (
            "docx",
            {"remote_template": "https://example.invalid/t.dotm"},
            "Remote template or object",
        ),
        ("ole", {"name": "book.xls", "macro_sheet": True}, "XLM macro sheet"),
        ("ole", {"name": "letter.doc", "dde": f'"{EXE}"'}, "DDE field"),
    ],
)
def test_office_threats(
    generator: str, kwargs: dict[str, Any], title: str, sample_dir: Path
) -> None:
    result = run(OfficeMacros(), getattr(generators, generator)(sample_dir, **kwargs))
    assert title in {f.title for f in result.findings}


@pytest.mark.parametrize(
    ("generator", "kwargs"),
    [
        ("xlsx", {"cells": [["=SUM(1,2)"]]}),
        ("docx", {"hyperlink": "https://example.invalid"}),
        ("docx", {"text": "Please use DDE carefully."}),
        ("ole", {"name": "legacy.xls"}),
        ("ole", {"name": "letter.doc"}),
        ("zip_entries", {"entries": {"a.xml": ["xml"]}}),
        ("disguised", {"name": "a.zip", "parts": ["zip_broken"]}),
    ],
)
def test_benign_documents(generator: str, kwargs: dict[str, Any], sample_dir: Path) -> None:
    assert rules(run(OfficeMacros(), getattr(generators, generator)(sample_dir, **kwargs))) == {}


def test_ole_package_becomes_child(sample_dir: Path) -> None:
    path = generators.ole(sample_dir, name="letter.doc", package={"invoice.exe": ["pe_stub"]})
    [child] = run(OfficeMacros(), path).children
    assert child.name == "invoice.exe"
    assert child.data.startswith(b"MZ")


def test_broken_ole_is_malformed(sample_dir: Path) -> None:
    path = generators.disguised(sample_dir, name="a.xls", parts=["ole_broken"])
    assert rules(run(OfficeMacros(), path)) == {"parser.malformed": "medium"}
