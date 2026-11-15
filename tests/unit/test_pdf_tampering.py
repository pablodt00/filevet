from pathlib import Path

import pytest

from filevet.analyzers.integrity import pdf_tampering
from filevet.analyzers.integrity.pdf_tampering import PdfTampering
from filevet.core.analyzer import AnalysisContext, Expected, Party
from filevet.core.finding import Severity
from filevet.core.limits import DEFAULT_LIMITS
from filevet.core.pdf import Pdf, lines, parse_cmap, string, tokens
from tests.corpus.generators import fake_iban, pdf, signed_pdf
from tests.helpers import artifact, rules, run

STATEMENT = "Statement January 2026\nOpening 1,000.00\nPayment -125.00\nClosing 875.00"


def _findings(path: Path, rule: str, **ctx: object) -> list[str]:
    context = AnalysisContext(limits=DEFAULT_LIMITS, **ctx)  # type: ignore[arg-type]
    result = PdfTampering().analyze(artifact(path), context)
    return [f.evidence for f in result.findings if f.rule_id == rule]


def test_plain_pdf_has_no_findings(sample_dir: Path) -> None:
    assert rules(run(PdfTampering(), pdf(sample_dir, text=STATEMENT))) == {}


def test_reads_text_lines(sample_dir: Path) -> None:
    doc = Pdf(pdf(sample_dir, text=STATEMENT).read_bytes(), 1 << 20)
    assert lines(doc.pages(0)) == [f"1\t{line}" for line in STATEMENT.split("\n")]


def test_amount_changed_in_update(sample_dir: Path) -> None:
    edited = STATEMENT.replace("-125.00", "-25.00").replace("875.00", "975.00")
    path = pdf(sample_dir, text=STATEMENT, updates=[edited])
    found = rules(run(PdfTampering(), path))
    assert found["integrity.pdf_incremental_updates"] == Severity.MEDIUM
    assert found["integrity.pdf_revision_diff"] == Severity.MEDIUM
    assert "-25.00" in _findings(path, "integrity.pdf_revision_diff")[0]


def test_name_change_is_low(sample_dir: Path) -> None:
    path = pdf(sample_dir, text="Invoice for Anna Beispiel", updates=["Invoice for Otto Muster"])
    assert rules(run(PdfTampering(), path))["integrity.pdf_revision_diff"] == Severity.LOW


def test_form_fill_is_at_most_low(sample_dir: Path) -> None:
    path = pdf(sample_dir, text=STATEMENT, form_fill="REF-2026-0001")
    found = rules(run(PdfTampering(), path))
    assert found == {"integrity.pdf_incremental_updates": Severity.LOW}


def test_signed_pdf_update_is_low(sample_dir: Path) -> None:
    found = rules(run(PdfTampering(), signed_pdf(sample_dir)))
    assert max(found.values(), key=lambda s: s.rank).rank <= Severity.LOW.rank


def test_white_box_over_iban(sample_dir: Path) -> None:
    text = f"Invoice 2026-0001\nIBAN {fake_iban(1)}\nTotal 100.00"
    path = pdf(sample_dir, text=text, cover_line=1, cover_text=f"IBAN {fake_iban(9)}")
    evidence = _findings(path, "integrity.pdf_text_overlay")
    assert len(evidence) == 2
    assert "DE" in evidence[0] and "****" in evidence[0]
    unmasked = _findings(path, "integrity.pdf_text_overlay", mask=False)
    assert fake_iban(1) in unmasked[0]


def test_text_on_separate_lines_does_not_overlap(sample_dir: Path) -> None:
    path = pdf(sample_dir, text="\n".join(f"Line {i} 1{i}.00" for i in range(30)))
    assert "integrity.pdf_text_overlay" not in rules(run(PdfTampering(), path))


def test_retyped_amount(sample_dir: Path) -> None:
    path = pdf(sample_dir, text="Invoice\nItem 10.00\nTotal 10.00", retyped_line=2)
    assert rules(run(PdfTampering(), path))["integrity.pdf_font_anomaly"] == Severity.MEDIUM


def test_font_added_in_update(sample_dir: Path) -> None:
    path = pdf(sample_dir, text="Invoice", updates=["Invoice 2"], retyped_line=0)
    data = path.read_bytes() + b"9 0 obj\n<< /Type /Font /BaseFont /Courier >>\nendobj\n"
    data += b"startxref\n0\n%%EOF\n"
    path.write_bytes(data)
    assert "Courier" in " ".join(_findings(path, "integrity.pdf_font_anomaly"))


def test_producer_changed(sample_dir: Path) -> None:
    path = pdf(
        sample_dir,
        text=STATEMENT,
        producer="BankCore Statements 4.2",
        updates=[STATEMENT],
        update_producer="Consumer PDF Editor 11",
    )
    evidence = _findings(path, "integrity.pdf_producer_mismatch")
    assert evidence == ["BankCore Statements 4.2 -> Consumer PDF Editor 11"]


def test_dates_and_xmp_disagree(sample_dir: Path) -> None:
    path = pdf(
        sample_dir,
        producer="BankCore",
        xmp_producer="Other Tool",
        created="D:20260131120000+01'00'",
        modified="D:20260101120000Z",
    )
    found = run(PdfTampering(), path).findings
    assert {f.title for f in found} == {"PDF dates contradict each other", "PDF metadata disagree"}


def test_unexpected_producer_for_known_issuer(sample_dir: Path) -> None:
    path = pdf(sample_dir, text="Beispiel Bank AG statement", producer="Edit Tool")
    expected = Expected(parties={"Beispiel Bank AG": Party(producers=["BankCore"])})
    assert _findings(path, "integrity.pdf_producer_mismatch", expected=expected) == ["Edit Tool"]
    fine = Expected(parties={"Beispiel Bank AG": Party(producers=["Edit Tool"])})
    assert _findings(path, "integrity.pdf_producer_mismatch", expected=fine) == []


def test_garbage_pdf_does_not_raise(sample_dir: Path) -> None:
    path = sample_dir / "bad.pdf"
    for data in (
        b"%PDF-1.7\n1 0 obj\n<< /Type /ObjStm /First 99999999999 >>\nstream\nx\nendstream\n",
        b"%PDF-1.7\n" + bytes(range(256)) * 50,
        b"%PDF-1.7\n1 0 obj (\\",
    ):
        path.write_bytes(data)
        assert rules(run(PdfTampering(), path)) == {}


def test_reader_error_is_a_finding(sample_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(data: bytes, budget: int) -> None:
        raise ValueError

    monkeypatch.setattr(pdf_tampering, "Pdf", broken)
    assert rules(run(PdfTampering(), pdf(sample_dir))) == {"parser.malformed": Severity.MEDIUM}


def test_object_streams_and_cmaps(sample_dir: Path) -> None:
    import zlib

    inner = b"6 0 << /Type /Page /Parent 2 0 R /Contents 7 0 R >>"
    cmap = (
        b"beginbfchar <01> <0041> endbfchar "
        b"beginbfrange <02> <03> <0042> <04> <05> [<0044> <0045>] endbfrange"
    )
    content = b"BT /F1 10 Tf 10 10 Td <0102030405> Tj [(x) -300 (y)] TJ ET"
    data = (
        b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [6 0 R] /Resources << /Font << /F1 8 0 R >> >> >>\n"
        b"endobj\n8 0 obj\n<< /Type /Font /ToUnicode 9 0 R >>\nendobj\n"
        b"9 0 obj\n<< >>\nstream\n"
        + cmap
        + b"\nendstream\nendobj\n"
        + b"3 0 obj\n<< /Type /ObjStm /N 1 /First 4 /Filter /FlateDecode >>\nstream\n"
        + zlib.compress(inner)
        + b"\nendstream\nendobj\n7 0 obj\n<< >>\nstream\n"
        + content
        + b"\nendstream\nendobj\ntrailer << /Root 1 0 R >>\n"
    )
    pages = Pdf(data, 1 << 20).pages(0)
    assert [t.text for t in pages[0].texts] == ["ABCDE"]
    assert parse_cmap(cmap) == {
        b"\x01": "A",
        b"\x02": "B",
        b"\x03": "C",
        b"\x04": "D",
        b"\x05": "E",
    }


def test_tokens_and_strings() -> None:
    kinds = [
        k for k, _ in tokens(b"% c\n<</A 1>> (a\\(b\\)c\\101\\\n) <414> [1 /N] BI /W 1 ID xx EI Q")
    ]
    assert kinds == [
        "name",
        "num",
        "str",
        "str",
        "[",
        "num",
        "name",
        "]",
        "op",
        "name",
        "num",
        "op",
        "op",
    ]
    assert string(b"/Producer <FEFF0041>", b"Producer") == "A"
    assert string(b"/Producer (a\\nb)", b"Producer") == "a\nb"
    assert string(b"/Creator 5", b"Producer") is None
