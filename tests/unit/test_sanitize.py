import csv
import io
import json
import zipfile
from pathlib import Path

import pytest

from filevet.analyzers.malware.office_macros import OfficeMacros
from filevet.analyzers.malware.pdf_active_content import PdfActiveContent
from filevet.analyzers.parser.archive import Archive
from filevet.core.errors import ScanError
from filevet.core.pipeline import extract_text, sanitize, scan
from filevet.interfaces import cli
from tests.corpus import generators


def _kinds(removed: list) -> set[str]:
    return {f.rule_id for f in removed}


def test_pdf_loses_active_content_but_keeps_its_text(sample_dir: Path) -> None:
    path = generators.pdf(
        sample_dir,
        javascript="app.alert(1)",
        launch="calc.exe",
        uri="https://example.invalid",
        embedded={"a.exe": ["pe_stub"]},
        submit_form="https://example.invalid/form",
    )
    assert scan(path, analyzers=[PdfActiveContent()]).findings

    clean, removed = sanitize(path)

    assert {"sanitize.javascript", "sanitize.embedded_file", "sanitize.annotation"} <= _kinds(
        removed
    )
    assert scan(clean, analyzers=[PdfActiveContent()]).findings == []
    assert "Invoice 2026-0001" in extract_text(clean)


def test_benign_pdf_comes_back_with_nothing_removed(sample_dir: Path) -> None:
    clean, removed = sanitize(generators.pdf(sample_dir))
    assert removed == []
    assert clean.startswith(b"%PDF-")


def test_csv_formula_cells_are_prefixed(sample_dir: Path) -> None:
    rows = [["date", "amount", "note"], ["2026-01-02", "-12.50", '=HYPERLINK("x")']]
    rows.append(["2026-01-03", "+34 600", "@SUM(A1)"])
    clean, removed = sanitize(generators.csv_rows(sample_dir, rows=rows))

    assert list(csv.reader(io.StringIO(clean.decode()))) == [
        rows[0],
        ["2026-01-02", "-12.50", '\'=HYPERLINK("x")'],
        ["2026-01-03", "+34 600", "'@SUM(A1)"],
    ]
    [finding] = removed
    assert finding.title == "Removed 2 formula item(s)"


def test_xlsm_loses_macros_and_external_links(sample_dir: Path) -> None:
    path = generators.xlsx(
        sample_dir,
        name="m.xlsm",
        cells=[["ok"]],
        vba="Sub AutoOpen()\nEnd Sub",
        macro_sheet=True,
        dde_link=True,
    )
    clean, removed = sanitize(path)

    with zipfile.ZipFile(io.BytesIO(clean)) as zf:
        names = set(zf.namelist())
        rels = zf.read("xl/_rels/workbook.xml.rels")
        types = zf.read("[Content_Types].xml")
        workbook = zf.read("xl/workbook.xml")
    assert not {n for n in names if "vbaProject" in n or "macrosheets" in n or "externalLinks" in n}
    assert b"vbaProject" not in rels and b"externalLink" not in rels
    assert b"macroEnabled" not in types
    assert b"Auto_Open" not in workbook and b"Sheet1" in workbook
    assert _kinds(removed) == {"sanitize.macro", "sanitize.external_link"}
    report = scan(clean, analyzers=[Archive(), OfficeMacros()])
    assert not {f.rule_id for f in report.findings if f.rule_id.startswith("malware.")}


def test_unsupported_and_broken_files_fail_closed(sample_dir: Path) -> None:
    with pytest.raises(ScanError, match="not supported for ole"):
        sanitize(generators.ole(sample_dir))
    with pytest.raises(ScanError, match="sanitizing failed"):
        sanitize(b"%PDF-1.4\nnot really a pdf")
    with pytest.raises(ScanError, match="sanitizing failed"):
        sanitize(generators.nested_zip(sample_dir, depth=1))


def test_cli_writes_output_and_report(sample_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = generators.pdf(sample_dir, javascript="app.alert(1)")
    out = sample_dir / "clean.pdf"
    assert cli.main(["sanitize", str(path), "--output", str(out)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["input"] == path.name
    assert "sanitize.javascript" in {r["rule_id"] for r in report["removed"]}
    assert out.read_bytes().startswith(b"%PDF-")


def test_cli_refuses_to_overwrite_the_input(sample_dir: Path) -> None:
    path = generators.pdf(sample_dir)
    with pytest.raises(SystemExit) as exc:
        cli.main(["sanitize", str(path), "--output", str(path)])
    assert exc.value.code == cli.USAGE_ERROR
