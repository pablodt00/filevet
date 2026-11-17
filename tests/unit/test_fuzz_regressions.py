from collections.abc import Callable
from pathlib import Path

import pytest

from filevet.analyzers.integrity.financial_data import FinancialData
from filevet.analyzers.malware.pdf_active_content import PdfActiveContent
from filevet.core.analyzer import AnalyzerResult, load_analyzers
from filevet.core.pipeline import scan
from tests import helpers
from tests.corpus import generators

CASES: dict[str, Callable[[Path], Path]] = {
    "xml_unknown_encoding": lambda out: generators.camt053(out, declared_encoding="utf-9"),
    "zip_invalid_deflate": generators.corrupt_deflate,
    "pdf_huge_startxref": lambda out: generators.pdf(out, startxref=10**30),
    "csv_bare_carriage_return": lambda out: generators.csv_rows(
        out, rows=[["date", "amount\rnote"], ["2026-01-02", "10.00"]]
    ),
}


@pytest.mark.parametrize("case", CASES)
def test_fuzz_crash_is_handled_inside_every_analyzer(case: str, sample_dir: Path) -> None:
    path = CASES[case](sample_dir)
    artifact = helpers.artifact(path)
    for analyzer in load_analyzers():
        if analyzer.name != "malware.clamav" and analyzer.supports(artifact):
            AnalyzerResult.model_validate(helpers.run(analyzer, path))
    report = scan(path)
    assert not [r for r in report.analyzer_runs if r.status != "ok"]


def test_huge_startxref_is_reported_as_malformed(sample_dir: Path) -> None:
    path = CASES["pdf_huge_startxref"](sample_dir)
    assert "parser.malformed" in helpers.rules(helpers.run(PdfActiveContent(), path))


def test_bare_carriage_return_ends_a_csv_row(sample_dir: Path) -> None:
    path = CASES["csv_bare_carriage_return"](sample_dir)
    rules = helpers.rules(helpers.run(FinancialData(), path))
    assert "parser.malformed" not in rules
