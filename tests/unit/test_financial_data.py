from pathlib import Path

import pytest

from filevet.analyzers.integrity import financial_data
from filevet.analyzers.integrity.financial_data import FinancialData
from filevet.core.analyzer import AnalysisContext, Expected, Party
from filevet.core.finding import Severity
from filevet.core.limits import DEFAULT_LIMITS
from tests.corpus.generators import bank_statement_csv, camt053, csv_rows, fake_iban, pdf, xlsx
from tests.helpers import artifact, rules, run

BAD_IBAN = "DE00123456780000000001"
SUPPLIER = Expected(parties={"Muster Lieferant GmbH": Party(ibans=[fake_iban(2)])})


def _run(path: Path, expected: Expected | None = None, mask: bool = True) -> dict[str, Severity]:
    ctx = AnalysisContext(limits=DEFAULT_LIMITS, expected=expected or Expected(), mask=mask)
    return rules(FinancialData().analyze(artifact(path), ctx))


def _invoice(*lines: str) -> str:
    return "\n".join(["Invoice 2026-0001", "Muster Lieferant GmbH", *lines])


@pytest.mark.parametrize(
    "path_args",
    [
        {"generator": "pdf", "text": _invoice("Item A 40.00", "Item B 60.00", "Total 100.00")},
        {
            "generator": "pdf",
            "text": _invoice("Net 2 x 50.00 100.00", "Item 10.00", "VAT 19% 20.90", "Total 130.90"),
        },
        {"generator": "pdf", "text": _invoice("Subtotal 100.00", "VAT 19.00", "Total 119.00")},
        {
            "generator": "pdf",
            "text": f"Statement\nOpening 1,000.00\nIBAN {fake_iban(1)}\nClosing 875.00",
        },
        {
            "generator": "pdf",
            "text": "Opening 1,000.00\nPayment -125.00\n15.01.2026 Fee -0.00\nClosing 875.00",
        },
        {"generator": "camt053", "entries": 3, "opening": "1000.00", "closing": "1375.00"},
        {
            "generator": "camt053",
            "message": "pain.001.001.09",
            "entries": 3,
            "control_sum": "375.00",
            "end_to_end": "E2E-{i}",
        },
        {
            "generator": "camt053",
            "value_date": "2026-01-14",
            "end_to_end": "NOTPROVIDED",
            "entries": 2,
        },
        {"generator": "csv"},
        {"generator": "xlsx"},
    ],
    ids=[
        "invoice",
        "invoice-vat",
        "invoice-subtotal",
        "statement-no-entries",
        "statement",
        "camt",
        "pain",
        "camt-dates",
        "csv",
        "xlsx",
    ],
)
def test_benign(sample_dir: Path, path_args: dict[str, object]) -> None:
    kind = path_args.pop("generator")
    if kind == "pdf":
        path = pdf(sample_dir, **path_args)  # type: ignore[arg-type]
    elif kind == "camt053":
        path = camt053(sample_dir, **path_args)  # type: ignore[arg-type]
    elif kind == "csv":
        path = bank_statement_csv(sample_dir)
    else:
        path = xlsx(sample_dir, cells=[["IBAN", "Amount"], [fake_iban(3), "10.00"]])
    assert _run(path, SUPPLIER) == {}


def test_invalid_iban_in_pdf(sample_dir: Path) -> None:
    path = pdf(sample_dir, text=_invoice(f"IBAN: {BAD_IBAN}", "Total 10.00"))
    assert _run(path) == {"integrity.iban_invalid": Severity.MEDIUM}


def test_evidence_is_masked_unless_asked(sample_dir: Path) -> None:
    path = pdf(sample_dir, text=f"IBAN: {BAD_IBAN}")
    ctx = AnalysisContext(limits=DEFAULT_LIMITS)
    assert (
        FinancialData().analyze(artifact(path), ctx).findings[0].evidence
        == "DE00 **** **** **** **** 01"
    )
    ctx = AnalysisContext(limits=DEFAULT_LIMITS, mask=False)
    assert FinancialData().analyze(artifact(path), ctx).findings[0].evidence == BAD_IBAN


def test_invalid_iban_and_bic_in_csv(sample_dir: Path) -> None:
    rows = [["name", "iban", "bic"], ["A", BAD_IBAN, "COBAQQFF"], ["B", fake_iban(1), "COBADEFF"]]
    found = _run(csv_rows(sample_dir, rows=rows))
    assert found == {
        "integrity.iban_invalid": Severity.MEDIUM,
        "integrity.bic_invalid": Severity.LOW,
    }


def test_invalid_iban_in_camt(sample_dir: Path) -> None:
    assert _run(camt053(sample_dir, iban=BAD_IBAN)) == {"integrity.iban_invalid": Severity.MEDIUM}


def test_two_beneficiary_ibans(sample_dir: Path) -> None:
    text = _invoice(f"IBAN {fake_iban(1)}", "Total 10.00", f"Please pay to IBAN {fake_iban(2)}")
    assert _run(pdf(sample_dir, text=text)) == {"integrity.iban_inconsistent": Severity.MEDIUM}


def test_bic_country_differs(sample_dir: Path) -> None:
    text = f"IBAN {fake_iban(1)} BIC BNPAFRPPXXX"
    assert _run(pdf(sample_dir, text=text)) == {"integrity.bic_invalid": Severity.LOW}


def test_iban_not_allowlisted(sample_dir: Path) -> None:
    text = _invoice(f"IBAN {fake_iban(5)}")
    assert _run(pdf(sample_dir, text=text), SUPPLIER) == {
        "integrity.iban_not_allowlisted": Severity.MEDIUM
    }
    assert _run(pdf(sample_dir, text=_invoice(f"IBAN {fake_iban(2)}")), SUPPLIER) == {}
    path = camt053(sample_dir, message="pain.001.001.09", creditor_iban=fake_iban(5))
    assert _run(path, SUPPLIER) == {"integrity.iban_not_allowlisted": Severity.MEDIUM}
    rows = [["supplier", "iban"], ["Muster Lieferant GmbH", fake_iban(5)], ["Other", fake_iban(6)]]
    assert _run(csv_rows(sample_dir, rows=rows), SUPPLIER) == {
        "integrity.iban_not_allowlisted": Severity.MEDIUM
    }


@pytest.mark.parametrize(
    "text",
    [
        _invoice("Item A 40.00", "Item B 70.00", "Total 100.00"),
        _invoice("Item A 40.00", "Item B 60.00", "Subtotal 90.00", "VAT 19.00", "Total 119.00"),
        "Opening 1,000.00\nPayment -125.00\nClosing 900.00",
    ],
)
def test_totals_mismatch_in_text(sample_dir: Path, text: str) -> None:
    assert _run(pdf(sample_dir, text=text)) == {"integrity.totals_mismatch": Severity.MEDIUM}


def test_camt_balances_do_not_reconcile(sample_dir: Path) -> None:
    path = camt053(sample_dir, entries=3, opening="1000.00", closing="1400.00")
    assert _run(path) == {"integrity.totals_mismatch": Severity.MEDIUM}


def test_pain_control_sum(sample_dir: Path) -> None:
    path = camt053(sample_dir, message="pain.001.001.09", entries=3, control_sum="400.00")
    assert _run(path) == {"integrity.totals_mismatch": Severity.MEDIUM}


def test_pain_transaction_count(sample_dir: Path) -> None:
    path = camt053(sample_dir, message="pain.001.001.09", entries=2, control_sum="250.00")
    path.write_text(path.read_text().replace("<NbOfTxs>2</NbOfTxs>", "<NbOfTxs>3</NbOfTxs>"))
    assert _run(path) == {"integrity.totals_mismatch": Severity.MEDIUM}


@pytest.mark.parametrize(
    "args",
    [
        {"value_date": "2026-01-01"},
        {"booked": "2026-02-15"},
        {"created": "2099-01-31T18:00:00", "booked": "2099-01-15"},
    ],
)
def test_camt_date_anomaly(sample_dir: Path, args: dict[str, str]) -> None:
    assert _run(camt053(sample_dir, **args)) == {"integrity.date_anomaly": Severity.MEDIUM}


def test_statement_period(sample_dir: Path) -> None:
    path = camt053(sample_dir)
    period = (
        "<FrToDt><FrDtTm>2026-01-01T00:00:00</FrDtTm><ToDtTm>2026-01-10T23:59:59</ToDtTm></FrToDt>"
    )
    path.write_text(path.read_text().replace("</Acct>", "</Acct>" + period))
    assert _run(path) == {"integrity.date_anomaly": Severity.MEDIUM}


def test_impossible_date_in_text_and_table(sample_dir: Path) -> None:
    assert _run(pdf(sample_dir, text="Invoice date 31.02.2026")) == {
        "integrity.date_anomaly": Severity.MEDIUM
    }
    rows = [["date", "amount"], ["2026-13-01", "10.00"]]
    assert _run(csv_rows(sample_dir, rows=rows)) == {"integrity.date_anomaly": Severity.MEDIUM}


def test_duplicate_ids(sample_dir: Path) -> None:
    pain = camt053(sample_dir, message="pain.001.001.09", entries=2, end_to_end="E2E-1")
    assert _run(pain) == {"integrity.duplicate_ids": Severity.MEDIUM}
    camt = camt053(sample_dir, entries=2, end_to_end="REF-1")
    assert _run(camt) == {"integrity.duplicate_ids": Severity.LOW}


def test_plain_text_and_other_inputs(sample_dir: Path) -> None:
    note = sample_dir / "note.txt"
    note.write_text(f"Please pay to IBAN {BAD_IBAN}\n")
    assert _run(note) == {"integrity.iban_invalid": Severity.MEDIUM}
    other = sample_dir / "other.xml"
    other.write_text("<root><IBAN>DE00</IBAN></root>")
    assert _run(other) == {}
    other.write_text("<root")
    assert _run(other) == {}
    archive = sample_dir / "a.zip"
    archive.write_bytes(b"PK\x03\x04broken")
    assert _run(archive) == {}


def test_reader_error_is_a_finding(sample_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(*args: object) -> None:
        raise ValueError

    monkeypatch.setattr(financial_data, "_check", broken)
    assert rules(run(FinancialData(), pdf(sample_dir))) == {"parser.malformed": Severity.MEDIUM}
