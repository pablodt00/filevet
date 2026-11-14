import io
import zipfile
from datetime import date
from decimal import Decimal

import pytest
from defusedxml.ElementTree import fromstring

from filevet.core import extract_finance as ef
from filevet.core.finding import Location
from tests.corpus.generators import fake_iban

VALID = "DE89370400440532013000"


def test_valid_iban_passes() -> None:
    assert ef.iban_problem(VALID) is None
    assert ef.iban_problem("DE89 3704 0044 0532 0130 00") is None
    assert ef.iban_problem(fake_iban(7)) is None


@pytest.mark.parametrize(
    ("iban", "problem"),
    [
        ("DE88370400440532013000", "mod-97"),
        ("DE8937040044053201300", "21 characters"),
        ("QQ89370400440532013000", "unknown IBAN country"),
        ("DEXX370400440532013000", "invalid characters"),
    ],
)
def test_invalid_iban(iban: str, problem: str) -> None:
    assert problem in (ef.iban_problem(iban) or "")


@pytest.mark.parametrize(
    ("bic", "problem"),
    [
        ("COBADEFFXXX", None),
        ("COBADEFF", None),
        ("COBAQQFF", "unknown country"),
        ("COBA1", "layout"),
    ],
)
def test_bic(bic: str, problem: str | None) -> None:
    result = ef.bic_problem(bic)
    assert result is None if problem is None else problem in (result or "")


def test_mask_keeps_first_and_last_group() -> None:
    assert ef.mask("IBAN ES9121000418450200051332 ok") == "IBAN ES91 **** **** **** **** 1332 ok"
    assert ef.mask("no iban, 1,250.00 EUR") == "no iban, 1,250.00 EUR"


@pytest.mark.parametrize(
    ("text", "value"),
    [
        ("Total 1,234.56 EUR", Decimal("1234.56")),
        ("Summe 1.234,56", Decimal("1234.56")),
        ("Debit -125.00", Decimal("-125.00")),
        ("Debit 125,00-", Decimal("-125.00")),
        ("Amount 99.50", Decimal("99.50")),
    ],
)
def test_amounts(text: str, value: Decimal) -> None:
    assert ef.amounts(text) == [value]


@pytest.mark.parametrize("text", ["Date 15.01.2026", "VAT 19.00%", "Invoice 2026-0001", "1,000"])
def test_not_amounts(text: str) -> None:
    assert ef.amounts(text) == []


def test_dates() -> None:
    found = dict(ef.dates("2026-01-15 31.02.2026 05/13/2026 32/13/2026"))
    assert found == {
        "2026-01-15": date(2026, 1, 15),
        "31.02.2026": None,
        "05/13/2026": date(2026, 5, 13),
        "32/13/2026": None,
    }


def test_from_text_labels_and_trims() -> None:
    ibans, bics = ef.from_text(f"IBAN: {VALID} BIC: COBADEFFXXX", Location())
    assert [(i.value, i.labeled) for i in ibans] == [(VALID, True)]
    assert [b.value for b in bics] == ["COBADEFFXXX"]
    spaced, _ = ef.from_text("IBAN DE89 3704 0044 0532 0130 00 BIC", Location())
    assert spaced[0].value == VALID


def test_from_text_ignores_unlabeled_unknown_codes() -> None:
    ibans, _ = ef.from_text("Reference RF18539007547034", Location())
    assert ibans == []


def test_from_table_uses_headers() -> None:
    rows = [["name", "IBAN", "BIC"], ["Muster", VALID, "COBADEFF"], ["x", "", ""]]
    ibans, bics = ef.from_table(rows, "Sheet1")
    assert ibans[0].value == VALID and ibans[0].location.cell == "B2"
    assert bics[0].location == Location(sheet="Sheet1", cell="C2")


def test_from_iso20022() -> None:
    root = fromstring(
        f"<Document><Acct><IBAN>{VALID}</IBAN><BICFI>COBADEFF</BICFI></Acct></Document>"
    )
    ibans, bics = ef.from_iso20022(root)
    assert ibans[0].location.xpath == "/Document/Acct/IBAN"
    assert bics[0].value == "COBADEFF"


def test_read_csv_and_decode() -> None:
    assert ef.read_csv("a;b\n1;Müller\n".encode()) == [["a", "b"], ["1", "Müller"]]
    rows = ef.read_csv("a;b\n1;x\xe9\n".encode("latin-1"))
    assert [len(row) for row in rows] == [2, 2]


def test_read_xlsx() -> None:
    main = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("xl/sharedStrings.xml", f'<sst xmlns="{main}"><si><t>IBAN</t></si></sst>')
        zf.writestr(
            "xl/worksheets/sheet1.xml",
            f'<worksheet xmlns="{main}"><sheetData><row><c t="s"><v>0</v></c>'
            f'<c t="inlineStr"><is><t>{VALID}</t></is></c><c><v>12.5</v></c><c t="s"><v>9</v></c>'
            "</row></sheetData></worksheet>",
        )
        zf.writestr("xl/worksheets/sheet2.xml", "<broken")
    with zipfile.ZipFile(buf) as zf:
        sheets = ef.read_xlsx(zf, 1 << 20)
    assert sheets == {"sheet1": [["IBAN", VALID, "12.5", ""]], "sheet2": []}


def test_column() -> None:
    assert [ef.column(n) for n in (1, 26, 27)] == ["A", "Z", "AA"]
