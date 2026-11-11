import csv
import io
import zipfile
from pathlib import Path
from xml.sax.saxutils import escape

__all__ = [
    "bank_statement_csv",
    "camt053",
    "csv_rows",
    "disguised",
    "fake_iban",
    "nested_zip",
    "pdf",
    "xlsx",
]

SAMPLES_ROOT = Path(__file__).resolve().parents[3] / "tmp-samples"
MAX_EXPANDED_BYTES = 64 << 20
MAX_ZIP_DEPTH = 20


def _write(out: Path, name: str, data: bytes) -> Path:
    path = (out / name).resolve()
    if path.parent != out.resolve() or out.resolve().parent != SAMPLES_ROOT:
        raise ValueError(f"samples go in a run directory directly under {SAMPLES_ROOT}")
    path.write_bytes(data)
    return path


def fake_iban(n: int) -> str:
    bban = f"12345678{n:010d}"
    check = 98 - int(bban + "131400") % 97
    return f"DE{check:02d}{bban}"


def csv_rows(
    out: Path,
    *,
    rows: list[list[str]],
    name: str = "export.csv",
    delimiter: str = ",",
    quote_all: bool = False,
    encoding: str = "utf-8",
) -> Path:
    buf = io.StringIO()
    quoting = csv.QUOTE_ALL if quote_all else csv.QUOTE_MINIMAL
    csv.writer(buf, delimiter=delimiter, quoting=quoting).writerows(rows)
    return _write(out, name, buf.getvalue().encode(encoding))


def bank_statement_csv(out: Path, *, rows: int = 100, name: str = "statement.csv") -> Path:
    lines = [["date", "description", "counterparty_iban", "amount", "currency"]]
    for i in range(rows):
        amount = f"{(i * 37) % 5000 / 10:.2f}"
        lines.append(
            [
                f"2026-{i % 12 + 1:02d}-{i % 28 + 1:02d}",
                f"Invoice 2026-{i:04d} Müller & Søn GmbH",
                fake_iban(i),
                f"-{amount}" if i % 3 else amount,
                "EUR",
            ]
        )
    return csv_rows(out, rows=lines, name=name)


def camt053(
    out: Path,
    *,
    name: str = "camt053.xml",
    doctype: str = "",
    remittance_xml: str = "Invoice 2026-0001",
    entries: int = 1,
    encoding: str = "utf-8",
) -> Path:
    entry = (
        '<Ntry><Amt Ccy="EUR">125.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Sts><Cd>BOOK</Cd></Sts>'
        "<BookgDt><Dt>2026-01-15</Dt></BookgDt><NtryDtls><TxDtls><RmtInf>"
        f"<Ustrd>{remittance_xml}</Ustrd></RmtInf></TxDtls></NtryDtls></Ntry>"
    )
    xml = (
        f'<?xml version="1.0" encoding="{encoding}"?>\n{doctype}\n'
        '<Document xmlns="urn:iso:std:iso:20022:tech:xsd:camt.053.001.08"><BkToCstmrStmt>'
        "<GrpHdr><MsgId>STMT-0001</MsgId><CreDtTm>2026-01-31T18:00:00</CreDtTm></GrpHdr>"
        f"<Stmt><Id>STMT-0001-01</Id><Acct><Id><IBAN>{fake_iban(1)}</IBAN></Id></Acct>"
        f"{entry * entries}</Stmt></BkToCstmrStmt></Document>\n"
    )
    return _write(out, name, xml.encode(encoding))


def nested_zip(
    out: Path,
    *,
    name: str = "archive.zip",
    depth: int = 1,
    inner_name: str = "statement.csv",
    inner_size: int = 1024,
) -> Path:
    if not 0 < inner_size <= MAX_EXPANDED_BYTES or not 0 < depth <= MAX_ZIP_DEPTH:
        raise ValueError(f"inner_size <= {MAX_EXPANDED_BYTES} and depth <= {MAX_ZIP_DEPTH}")
    data, entry = b"0" * inner_size, inner_name
    for level in range(depth):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
            zf.writestr(entry, data)
        data, entry = buf.getvalue(), f"level{level}.zip"
    return _write(out, name, data)


def _zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("readme.txt", "statement attached\n")
    return buf.getvalue()


def disguised(out: Path, *, name: str, parts: list[str]) -> Path:
    blobs = {
        "pdf": b"%PDF-1.4\n%%EOF\n",
        "png": b"\x89PNG\r\n\x1a\n",
        "html": b"<html><body>Invoice 2026-0001</body></html>\n",
        "csv": b"date,amount\n2026-01-02,10.00\n",
        "zip": _zip_bytes(),
    }
    return _write(out, name, b"".join(blobs[part] for part in parts))


def _pdf_string(text: str) -> str:
    return "(" + text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)") + ")"


def pdf(
    out: Path,
    *,
    name: str = "invoice.pdf",
    text: str = "Invoice 2026-0001",
    javascript: str | None = None,
    launch: str | None = None,
) -> Path:
    catalog, page_aa, actions = "<< /Type /Catalog /Pages 2 0 R", "", []
    if javascript is not None:
        actions.append(f"<< /S /JavaScript /JS {_pdf_string(javascript)} >>")
        catalog += f" /OpenAction {5 + len(actions)} 0 R"
    if launch is not None:
        actions.append(f"<< /S /Launch /F {_pdf_string(launch)} >>")
        page_aa = f" /AA << /O {5 + len(actions)} 0 R >>"
    stream = f"BT /F1 12 Tf 72 720 Td {_pdf_string(text)} Tj ET"
    objects = [
        catalog + " >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        f"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R{page_aa} >>",
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        f"<< /Length {len(stream)} >>\nstream\n{stream}\nendstream",
        *actions,
    ]
    body, offsets = b"%PDF-1.7\n", []
    for number, obj in enumerate(objects, 1):
        offsets.append(len(body))
        body += f"{number} 0 obj\n{obj}\nendobj\n".encode("latin-1")
    xref = len(body)
    body += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode()
    body += "".join(f"{offset:010d} 00000 n \n" for offset in offsets).encode()
    body += f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n".encode()
    body += f"startxref\n{xref}\n%%EOF\n".encode()
    return _write(out, name, body)


def _cell(value: str) -> str:
    if value.startswith("="):
        return f"<c><f>{escape(value[1:])}</f></c>"
    return f'<c t="inlineStr"><is><t xml:space="preserve">{escape(value)}</t></is></c>'


def xlsx(
    out: Path, *, cells: list[list[str]], name: str = "statement.xlsx", macro: bool = False
) -> Path:
    main = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
    rel = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
    pkg = "http://schemas.openxmlformats.org/package/2006/relationships"
    workbook_type = (
        "application/vnd.ms-excel.sheet.macroEnabled.main+xml"
        if macro
        else "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"
    )
    vba_type = '<Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/>'
    vba_rel = (
        '<Relationship Id="rId2" Target="vbaProject.bin" '
        'Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject"/>'
    )
    rows = "".join("<row>" + "".join(_cell(v) for v in row) + "</row>" for row in cells)
    parts = {
        "[Content_Types].xml": (
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" '
            'ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            f"{vba_type if macro else ''}"
            f'<Override PartName="/xl/workbook.xml" ContentType="{workbook_type}"/>'
            '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/'
            'vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>'
        ),
        "_rels/.rels": (
            f'<Relationships xmlns="{pkg}"><Relationship Id="rId1" Target="xl/workbook.xml" '
            f'Type="{rel}/officeDocument"/></Relationships>'
        ),
        "xl/workbook.xml": (
            f'<workbook xmlns="{main}" xmlns:r="{rel}"><sheets>'
            '<sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>'
        ),
        "xl/_rels/workbook.xml.rels": (
            f'<Relationships xmlns="{pkg}"><Relationship Id="rId1" '
            f'Target="worksheets/sheet1.xml" Type="{rel}/worksheet"/>'
            f"{vba_rel if macro else ''}</Relationships>"
        ),
        "xl/worksheets/sheet1.xml": (
            f'<worksheet xmlns="{main}"><sheetData>{rows}</sheetData></worksheet>'
        ),
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for part, xml in parts.items():
            zf.writestr(part, '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n' + xml)
        if macro:
            zf.writestr("xl/vbaProject.bin", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + bytes(504))
    return _write(out, name, buf.getvalue())
