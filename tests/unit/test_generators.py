import zipfile
from pathlib import Path

import pytest

from tests.corpus import generators
from tests.corpus.judge import judge

CALLS = [
    ("csv_rows", {"rows": [["date", "amount"], ["2026-01-02", "\t=1+1"]]}),
    ("bank_statement_csv", {"rows": 5}),
    ("camt053", {"doctype": '<!DOCTYPE d [<!ENTITY e "x">]>', "remittance_xml": "&e;"}),
    ("nested_zip", {"depth": 3}),
    ("disguised", {"name": "invoice.pdf", "parts": ["pdf", "zip"]}),
    ("pdf", {"javascript": "app.alert('filevet')", "launch": "C:\\missing\\x (1).exe"}),
    ("xlsx", {"cells": [["Total", "=SUM(1,2)"]], "macro": True}),
]


@pytest.mark.parametrize(("name", "args"), CALLS, ids=[c[0] for c in CALLS])
def test_generator_writes_into_run_dir(
    name: str, args: dict[str, object], sample_dir: Path
) -> None:
    path = getattr(generators, name)(sample_dir, **args)
    assert path.parent == sample_dir.resolve()
    assert path.stat().st_size > 0


def test_generators_refuse_dirs_outside_tmp_samples(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        generators.csv_rows(tmp_path, rows=[["a"]])


def test_generators_refuse_names_that_leave_the_run_dir(sample_dir: Path) -> None:
    with pytest.raises(ValueError):
        generators.csv_rows(sample_dir, rows=[["a"]], name="../escape.csv")


def test_nested_zip_caps_expanded_size(sample_dir: Path) -> None:
    with pytest.raises(ValueError):
        generators.nested_zip(sample_dir, inner_size=generators.MAX_EXPANDED_BYTES + 1)


def test_fake_iban_has_valid_checksum() -> None:
    iban = generators.fake_iban(42)
    digits = "".join(str(int(c, 36)) for c in iban[4:] + iban[:4])
    assert len(iban) == 22
    assert int(digits) % 97 == 1


def test_pdf_xref_points_at_objects(sample_dir: Path) -> None:
    data = generators.pdf(sample_dir, javascript="app.alert(1)").read_bytes()
    xref = int(data.rsplit(b"startxref\n", 1)[1].split(b"\n")[0])
    entries = data[xref:].split(b"\n")[3:9]
    for number, entry in enumerate(entries, 1):
        offset = int(entry[:10])
        assert data[offset:].startswith(f"{number} 0 obj".encode())


def test_xlsx_macro_adds_vba_part(sample_dir: Path) -> None:
    with zipfile.ZipFile(generators.xlsx(sample_dir, cells=[["a"]], macro=True)) as zf:
        assert "xl/vbaProject.bin" in zf.namelist()
    with zipfile.ZipFile(generators.xlsx(sample_dir, cells=[["a"]], name="b.xlsx")) as zf:
        assert "xl/vbaProject.bin" not in zf.namelist()


HOSTILE = {"must_find": ["parser.a", "parser.b"], "min_severity": "high", "verdict": "block"}


def _report(verdict: str, *findings: tuple[str, str]) -> dict[str, object]:
    return {"verdict": verdict, "findings": [{"rule_id": r, "severity": s} for r, s in findings]}


@pytest.mark.parametrize(
    ("report", "expected", "passed"),
    [
        (_report("block", ("parser.b", "critical")), HOSTILE, True),
        (_report("block", ("parser.a", "medium")), HOSTILE, False),
        (_report("block", ("parser.c", "high")), HOSTILE, False),
        (_report("review", ("parser.a", "high")), HOSTILE, False),
        (_report("pass", ("parser.a", "info")), {"verdict": "pass"}, True),
        (_report("review"), {"verdict": "pass"}, False),
    ],
)
def test_judge(report: dict[str, object], expected: dict[str, object], passed: bool) -> None:
    assert judge(report, expected) is passed
