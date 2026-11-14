from pathlib import Path

import pytest

from filevet.analyzers.parser.csv_formula_injection import (
    MAX_COLUMNS,
    MAX_FINDINGS,
    CsvFormulaInjection,
    risk,
)
from filevet.core.finding import Severity
from tests.corpus import generators
from tests.helpers import rules, run


@pytest.mark.parametrize(
    "value",
    ["", "Rent", "-12.50", "+1,200.00", "-1.234,56 EUR", "+49 30 1234567", "(+1) 555 0100",
     "-", "+2.5%", "2026-01-02", "a=b", "'quoted'", "Müller"],
)  # fmt: skip
def test_plain_values_are_quiet(value: str) -> None:
    assert risk(value) is None


@pytest.mark.parametrize(
    ("value", "severity"),
    [
        ("=1+1", Severity.HIGH),
        ("@SUM(1)", Severity.HIGH),
        ("\t=1+1", Severity.HIGH),
        ("\r=1+1", Severity.HIGH),
        ('  "=1+1', Severity.HIGH),
        ("\uff1d1+1", Severity.HIGH),
        ("\uff201+1", Severity.HIGH),
        ("- see notes", Severity.MEDIUM),
        ("-2+3", Severity.MEDIUM),
        ("+cmd|' /C calc'!A0", Severity.HIGH),
        ('-HYPERLINK("https://example.invalid")', Severity.HIGH),
        ("+IMPORTXML(A1, B1)", Severity.HIGH),
        ("-DDE(x)", Severity.HIGH),
    ],
)
def test_formula_like_values(value: str, severity: Severity) -> None:
    assert risk(value) is severity


def test_csv_reports_cell(sample_dir: Path) -> None:
    path = generators.csv_rows(sample_dir, rows=[["a", "b"], ["x", "=1+1"]], delimiter=";")
    [finding] = run(CsvFormulaInjection(), path).findings
    assert finding.location.cell == "B2"  # type: ignore[union-attr]
    assert finding.evidence == "=1+1"


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16", "latin-1", "cp1252"])
def test_encodings(encoding: str, sample_dir: Path) -> None:
    rows = [["Name", "Note"], ["Müller Søren", "=1+1"]]
    path = generators.csv_rows(sample_dir, rows=rows, encoding=encoding)
    assert rules(run(CsvFormulaInjection(), path)) == {"parser.csv_formula_injection": "high"}


def test_findings_are_capped(sample_dir: Path) -> None:
    path = generators.csv_rows(sample_dir, rows=[["=1"]] * (MAX_FINDINGS + 10))
    assert len(run(CsvFormulaInjection(), path).findings) == MAX_FINDINGS


def test_too_many_columns_is_malformed(sample_dir: Path) -> None:
    path = generators.csv_rows(sample_dir, rows=[["x"] * (MAX_COLUMNS + 1)])
    assert rules(run(CsvFormulaInjection(), path)) == {"parser.malformed": "medium"}


def test_benign_statement(sample_dir: Path) -> None:
    assert rules(run(CsvFormulaInjection(), generators.bank_statement_csv(sample_dir))) == {}


@pytest.mark.parametrize("shared", [True, False])
def test_xlsx_strings_that_look_like_formulas(shared: bool, sample_dir: Path) -> None:
    cells = [["Note", "Total"], ["@SUM(1)", "=SUM(1,2)"]]
    path = generators.xlsx(sample_dir, cells=cells, shared_strings=shared)
    [finding] = run(CsvFormulaInjection(), path).findings
    assert finding.location.sheet == "sheet1"  # type: ignore[union-attr]
    assert finding.location.cell == "A2"  # type: ignore[union-attr]


def test_xlsx_real_formulas_are_quiet(sample_dir: Path) -> None:
    path = generators.xlsx(sample_dir, cells=[["=SUM(1,2)", "-12.50"]], shared_strings=True)
    assert rules(run(CsvFormulaInjection(), path)) == {}


@pytest.mark.parametrize("parts", [["zip"], ["zip_broken"]])
def test_other_zips_are_ignored(parts: list[str], sample_dir: Path) -> None:
    path = generators.disguised(sample_dir, name="a.zip", parts=parts)
    assert rules(run(CsvFormulaInjection(), path)) == {}
