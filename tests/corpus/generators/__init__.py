import base64
import binascii
import csv
import io
import itertools
import struct
import zipfile
import zlib
from pathlib import Path
from xml.sax.saxutils import escape

__all__ = [
    "bank_statement_csv",
    "camt053",
    "csv_rows",
    "disguised",
    "docx",
    "eicar",
    "fake_iban",
    "iso20022_xsd",
    "nested_zip",
    "ole",
    "pdf",
    "xlsx",
    "zip_entries",
]

SAMPLES_ROOT = Path(__file__).resolve().parents[3] / "tmp-samples"
MAX_EXPANDED_BYTES = 64 << 20
MAX_ZIP_DEPTH = 20
MAX_COPIES = 5000


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


_ISO_ROOTS = {
    "camt.052": "BkToCstmrAcctRpt",
    "camt.053": "BkToCstmrStmt",
    "camt.054": "BkToCstmrDbtCdtNtfctn",
    "pain.001": "CstmrCdtTrfInitn",
    "pain.008": "CstmrDrctDbtInitn",
    "pacs.008": "FIToFICstmrCdtTrf",
}


def camt053(
    out: Path,
    *,
    name: str = "camt053.xml",
    doctype: str = "",
    remittance_xml: str = "Invoice 2026-0001",
    entries: int = 1,
    encoding: str = "utf-8",
    message: str = "camt.053.001.08",
    msg_id: str = "STMT-0001",
    created: str = "2026-01-31T18:00:00",
    nesting: int = 0,
) -> Path:
    remittance = "<Nst>" * nesting + remittance_xml + "</Nst>" * nesting
    if message.startswith("camt"):
        entry = (
            '<Ntry><Amt Ccy="EUR">125.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Sts><Cd>BOOK</Cd></Sts>'
            "<BookgDt><Dt>2026-01-15</Dt></BookgDt><NtryDtls><TxDtls><RmtInf>"
            f"<Ustrd>{remittance}</Ustrd></RmtInf></TxDtls></NtryDtls></Ntry>"
        )
        body = (
            f"<Stmt><Id>{msg_id}-01</Id><Acct><Id><IBAN>{fake_iban(1)}</IBAN></Id></Acct>"
            f"{entry * entries}</Stmt>"
        )
    else:
        tx = (
            '<CdtTrfTxInf><Amt><InstdAmt Ccy="EUR">125.00</InstdAmt></Amt>'
            "<Cdtr><Nm>Muster Lieferant GmbH</Nm></Cdtr>"
            f"<CdtrAcct><Id><IBAN>{fake_iban(2)}</IBAN></Id></CdtrAcct>"
            f"<RmtInf><Ustrd>{remittance}</Ustrd></RmtInf></CdtTrfTxInf>"
        )
        body = (
            f"<PmtInf><PmtInfId>{msg_id}-01</PmtInfId><Dbtr><Nm>Beispiel AG</Nm></Dbtr>"
            f"<DbtrAcct><Id><IBAN>{fake_iban(1)}</IBAN></Id></DbtrAcct>{tx * entries}</PmtInf>"
        )
    root = _ISO_ROOTS[message[:8]]
    xml = (
        f'<?xml version="1.0" encoding="{encoding}"?>\n{doctype}\n'
        f'<Document xmlns="urn:iso:std:iso:20022:tech:xsd:{message}"><{root}>'
        f"<GrpHdr><MsgId>{msg_id}</MsgId><CreDtTm>{created}</CreDtTm></GrpHdr>"
        f"{body}</{root}></Document>\n"
    )
    return _write(out, name, xml.encode(encoding))


def iso20022_xsd(out: Path, *, message: str = "camt.053.001.08") -> Path:
    ns = f"urn:iso:std:iso:20022:tech:xsd:{message}"
    xsd = f"""<?xml version="1.0" encoding="UTF-8"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns="{ns}" targetNamespace="{ns}"
  elementFormDefault="qualified">
  <xs:element name="Document">
    <xs:complexType><xs:sequence><xs:element name="{_ISO_ROOTS[message[:8]]}">
      <xs:complexType><xs:sequence>
        <xs:element name="GrpHdr"><xs:complexType><xs:sequence>
          <xs:element name="MsgId"><xs:simpleType><xs:restriction base="xs:string">
            <xs:minLength value="1"/><xs:maxLength value="35"/>
          </xs:restriction></xs:simpleType></xs:element>
          <xs:element name="CreDtTm" type="xs:dateTime"/>
        </xs:sequence></xs:complexType></xs:element>
        <xs:any processContents="skip" minOccurs="0" maxOccurs="unbounded"/>
      </xs:sequence></xs:complexType>
    </xs:element></xs:sequence></xs:complexType>
  </xs:element>
</xs:schema>
"""
    return _write(out, f"{message}.xsd", xsd.encode())


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


def _zip_bytes(parts: dict[str, str | bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for part, data in parts.items():
            zf.writestr(part, data)
    return buf.getvalue()


_CII = (
    '<?xml version="1.0" encoding="UTF-8"?>\n<rsm:CrossIndustryInvoice xmlns:rsm='
    '"urn:un:unece:uncefact:data:standard:CrossIndustryInvoice:100"><rsm:ExchangedDocument>'
    "<ID>2026-0001</ID></rsm:ExchangedDocument></rsm:CrossIndustryInvoice>\n"
)
_MT940 = ":20:STMT0001\r\n:25:DE12345678/0000000001\r\n:28C:1/1\r\n:60F:C260101EUR1000,00\r\n"
_PE_DOS = b"This program cannot be run in DOS mode.\r\r\n$"


def _blob(part: str) -> bytes:
    blobs = {
        "pdf": b"%PDF-1.4\n%%EOF\n",
        "png": b"\x89PNG\r\n\x1a\n" + bytes(16),
        "jpeg": b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + bytes(32) + b"\xff\xd9",
        "html": b"<html><body>Invoice 2026-0001</body></html>\n",
        "csv": b"date,amount\n2026-01-02,10.00\n",
        "xml": _CII.encode(),
        "mt940": _MT940.encode(),
        "zip": _zip_bytes({"readme.txt": "statement attached\n"}),
        "pe_stub": (b"M" + b"Z").ljust(128, b"\0"),
        "pe": (b"M" + b"Z").ljust(78, b"\0") + _PE_DOS + bytes(64),
        "elf_stub": (b"\x7f" + b"ELF\x02\x01\x01").ljust(64, b"\0"),
        "lnk_stub": (b"L\0\0\0" + bytes.fromhex("0114020000000000c000000000000046")).ljust(
            76, b"\0"
        ),
        "script": b"#!/bin/sh\necho filevet\n",
        "rar_stub": b"Rar!\x1a\x07\x00".ljust(32, b"\0"),
        "zip_broken": b"PK\x03\x04".ljust(48, b"\xff"),
        "ole_broken": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1".ljust(512, b"\0"),
    }
    return blobs[part]


def disguised(out: Path, *, name: str, parts: list[str]) -> Path:
    return _write(out, name, b"".join(_blob(part) for part in parts))


def eicar(out: Path, *, name: str = "eicar.com") -> Path:
    head = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
    tail = "-".join(["EICAR", "STANDARD", "ANTIVIRUS", "TEST", "FILE!$H+H*"])
    return _write(out, name, (head + tail).encode())


def zip_entries(
    out: Path,
    *,
    name: str = "archive.zip",
    entries: dict[str, list[str]],
    symlinks: dict[str, str] | None = None,
    copies: int = 1,
    overlap: bool = False,
) -> Path:
    if not 0 < copies <= MAX_COPIES:
        raise ValueError(f"copies <= {MAX_COPIES}")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for i in range(copies):
            for entry, parts in entries.items():
                zf.writestr(f"{i:04d}-{entry}" if copies > 1 else entry, _blobs(parts))
        for link, target in (symlinks or {}).items():
            info = zipfile.ZipInfo(link)
            info.create_system = 3
            info.external_attr = 0o120777 << 16
            zf.writestr(info, target)
    data = buf.getvalue()
    if overlap:
        eocd = data.rindex(b"PK\x05\x06")
        _, _, _, count, _, size, start, _ = struct.unpack_from("<IHHHHIIH", data, eocd)
        directory = data[start : start + size]
        data = data[:start] + directory * 2
        data += struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, count * 2, count * 2, size * 2, start, 0)
    return _write(out, name, data)


def _blobs(parts: list[str]) -> bytes:
    return b"".join(_blob(part) for part in parts)


_SECTOR = 512
_NONE, _END, _FATSECT = 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFD


def _ole_bytes(streams: dict[str, bytes]) -> bytes:
    names, kinds, datas = ["Root Entry"], [5], [b""]
    kids: list[list[int]] = [[]]
    index = {"": 0}

    def add(key: str, parent: str, name: str, kind: int, data: bytes) -> None:
        index[key] = len(names)
        kids[index[parent]].append(len(names))
        names.append(name)
        kinds.append(kind)
        datas.append(data)
        kids.append([])

    for path, data in streams.items():
        *storages, leaf = path.split("/")
        parent = ""
        for storage in storages:
            if f"{parent}/{storage}" not in index:
                add(f"{parent}/{storage}", parent, storage, 1, b"")
            parent = f"{parent}/{storage}"
        add(path, parent, leaf, 2, data.ljust(4096, b"\0"))

    body, fat, starts = b"", list[int](), list[int]()
    right = dict.fromkeys(range(len(names)), _NONE)
    for i, data in enumerate(datas):
        right.update(itertools.pairwise(kids[i]))
        starts.append(len(fat) if data else (_END if kinds[i] == 5 else 0))
        if data:
            sectors = -(-len(data) // _SECTOR)
            fat += [*range(len(fat) + 1, len(fat) + sectors), _END]
            body += data.ljust(sectors * _SECTOR, b"\0")

    directory = b"".join(
        _dir_entry(
            names[i], kinds[i], right[i], kids[i][0] if kids[i] else _NONE, starts[i], len(datas[i])
        )
        for i in range(len(names))
    )
    directory = directory.ljust(-(-len(directory) // _SECTOR) * _SECTOR, b"\0")
    dir_start = len(fat)
    fat += [*range(dir_start + 1, dir_start + len(directory) // _SECTOR), _END]
    fat_sectors = 1
    while len(fat) + fat_sectors > 128 * fat_sectors:
        fat_sectors += 1
    fat_start = len(fat)
    fat += [_FATSECT] * fat_sectors
    fat += [_NONE] * (128 * fat_sectors - len(fat))
    header = struct.pack(
        "<8s16sHHHHH6sIIIIIIIII",
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
        bytes(16),
        0x3E,
        3,
        0xFFFE,
        9,
        6,
        bytes(6),
        0,
        fat_sectors,
        dir_start,
        0,
        4096,
        _END,
        0,
        _END,
        0,
    )
    difat = [*range(fat_start, fat_start + fat_sectors)] + [_NONE] * (109 - fat_sectors)
    header += struct.pack("<109I", *difat)
    return header + body + directory + struct.pack(f"<{len(fat)}I", *fat)


def _dir_entry(name: str, kind: int, right: int, child: int, start: int, size: int) -> bytes:
    encoded = (name + "\0").encode("utf-16-le") if kind else b""
    return struct.pack(
        "<64sHBBIII16sIQQIQ", encoded, len(encoded), kind, 1, _NONE, right, child,
        bytes(16), 0, 0, 0, start, size,
    )  # fmt: skip


def _vba_container(source: str) -> bytes:
    data, container = source.encode("latin-1"), b"\x01"
    for i in range(0, len(data), 3584):
        chunk = data[i : i + 3584]
        tokens = b"".join(b"\x00" + chunk[j : j + 8] for j in range(0, len(chunk), 8))
        container += struct.pack("<H", (len(tokens) - 1) | 0xB000) + tokens
    return container


def _vba_streams(source: str, storage: str) -> dict[str, bytes]:
    code = f'Attribute VB_Name = "Module1"\r\n{source}'
    return {
        f"{storage}VBA/_VBA_PROJECT": b"\xcc\x61\xff\xff\x00",
        f"{storage}VBA/dir": b"\x01",
        f"{storage}VBA/Module1": _vba_container(code),
        f"{storage}PROJECT": b'ID="{00000000-0000-0000-0000-000000000000}"\r\nModule=Module1\r\n',
    }


def _native(label: str, data: bytes) -> bytes:
    name = label.encode("latin-1") + b"\0"
    body = struct.pack("<H", 2) + name + name + struct.pack("<II", 0x00030000, len(name)) + name
    body += struct.pack("<I", len(data)) + data
    return struct.pack("<I", len(body)) + body


def _biff(macro_sheet: bool) -> bytes:
    sheet_name = b"Sheet1"
    sheet = struct.pack("<IBBBB", 0, 0, 1 if macro_sheet else 0, len(sheet_name), 0) + sheet_name
    return (
        struct.pack("<HH", 0x0809, 16)
        + bytes(16)
        + struct.pack("<HH", 0x0085, len(sheet))
        + sheet
        + struct.pack("<HH", 0x000A, 0)
    )


def ole(
    out: Path,
    *,
    name: str = "legacy.xls",
    text: str = "Invoice 2026-0001",
    vba: str | None = None,
    macro_sheet: bool = False,
    dde: str | None = None,
    package: dict[str, list[str]] | None = None,
) -> Path:
    return _write(out, name, _ole_document(name, text, vba, macro_sheet, dde, package))


def _ole_document(
    name: str,
    text: str,
    vba: str | None,
    macro_sheet: bool,
    dde: str | None,
    package: dict[str, list[str]] | None,
) -> bytes:
    streams: dict[str, bytes] = {}
    if name.endswith(".doc"):
        field = f"\x13 DDEAUTO {dde} \x15" if dde else ""
        streams["WordDocument"] = (text + field).encode("latin-1")
        storage = "Macros/"
    elif not name.endswith(".bin"):
        streams["Workbook"] = _biff(macro_sheet)
        storage = "_VBA_PROJECT_CUR/"
    else:
        storage = ""
    if vba is not None:
        streams.update(_vba_streams(vba, storage))
    for label, parts in (package or {}).items():
        streams["\x01Ole10Native"] = _native(label, _blobs(parts))
    return _ole_bytes(streams)


def _pdf_string(text: str) -> str:
    return "(" + text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)") + ")"


def _pdf_stream(entries: str, data: bytes) -> bytes:
    return f"<< {entries} /Length {len(data)} >>\nstream\n".encode() + data + b"\nendstream"


_OBFUSCATED = {
    b"/JavaScript": b"/J#61vaScript",
    b"/JS ": b"/J#53 ",
    b"/OpenAction": b"/Open#41ction",
    b"/Launch": b"/L#61unch",
}


def pdf(
    out: Path,
    *,
    name: str = "invoice.pdf",
    text: str = "Invoice 2026-0001",
    javascript: str | None = None,
    launch: str | None = None,
    uri: str | None = None,
    submit_form: str | None = None,
    embedded: dict[str, list[str]] | None = None,
    xfa: bool = False,
    rich_media: bool = False,
    open_page: bool = False,
    obfuscate: bool = False,
    object_stream: bool = False,
    filter_chain: bool = False,
    truncated: bool = False,
    bad_startxref: bool = False,
) -> Path:
    objects: list[bytes | None] = [b""] * 5

    def add(obj: bytes | str) -> int:
        objects.append(obj.encode("latin-1") if isinstance(obj, str) else obj)
        return len(objects)

    catalog, page_extra, annots = "", "", []
    if javascript is not None:
        action = f"<< /S /JavaScript /JS {_pdf_string(javascript)} >>"
        if object_stream:
            ref = len(objects) + 2
            head = f"{ref} 0 ".encode()
            data = zlib.compress(head + action.encode("latin-1"))
            add(_pdf_stream(f"/Type /ObjStm /N 1 /First {len(head)} /Filter /FlateDecode", data))
            objects.append(None)
        else:
            ref = add(action)
        catalog += f" /OpenAction {ref} 0 R"
    if launch is not None:
        ref = add(f"<< /S /Launch /F {_pdf_string(launch)} >>")
        page_extra += f" /AA << /O {ref} 0 R >>"
    for kind, target in (("URI /URI", uri), ("SubmitForm /F", submit_form)):
        if target is not None:
            ref = add(f"<< /S /{kind} {_pdf_string(target)} >>")
            annots.append(f"<< /Type /Annot /Subtype /Link /Rect [72 690 300 710] /A {ref} 0 R >>")
    if rich_media:
        annots.append("<< /Type /Annot /Subtype /RichMedia /Rect [72 600 300 680] >>")
    if xfa:
        ref = add(_pdf_stream("", b'<xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/"/>'))
        catalog += f" /AcroForm << /Fields [] /XFA {ref} 0 R >>"
    if open_page:
        catalog += " /OpenAction [3 0 R /Fit]"
    if embedded:
        names = []
        for filename, parts in embedded.items():
            data = zlib.compress(_blobs(parts))
            stream = add(_pdf_stream("/Type /EmbeddedFile /Filter /FlateDecode", data))
            spec = add(
                f"<< /Type /Filespec /F {_pdf_string(filename)} /EF << /F {stream} 0 R >> >>"
            )
            names.append(f"{_pdf_string(filename)} {spec} 0 R")
        catalog += f" /Names << /EmbeddedFiles << /Names [{' '.join(names)}] >> >>"
    if annots:
        page_extra += f" /Annots [{' '.join(annots)}]"

    lines = " T* ".join(f"{_pdf_string(line)} Tj" for line in text.split("\n"))
    content = f"BT /F1 12 Tf 14 TL 72 720 Td {lines} ET".encode("latin-1")
    if filter_chain:
        encoded = binascii.hexlify(base64.a85encode(zlib.compress(content)) + b"~>") + b">"
        chain = "/Filter [/ASCIIHexDecode /ASCII85Decode /FlateDecode]"
        objects[4] = _pdf_stream(chain, encoded)
    else:
        objects[4] = _pdf_stream("", content)
    objects[:4] = [
        f"<< /Type /Catalog /Pages 2 0 R{catalog} >>".encode(),
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            f"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R{page_extra} >>"
        ).encode(),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    body, offsets = b"%PDF-1.7\n", list[int | None]()
    for number, obj in enumerate(objects, 1):
        if obj is None:
            offsets.append(None)
            continue
        if obfuscate:
            for plain, hidden in _OBFUSCATED.items():
                obj = obj.replace(plain, hidden)
        offsets.append(len(body))
        body += f"{number} 0 obj\n".encode() + obj + b"\nendobj\n"
    if truncated:
        return _write(out, name, body[: len(body) * 3 // 4])
    xref = len(body)
    body += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode()
    body += "".join(
        "0000000000 65535 f \n" if offset is None else f"{offset:010d} 00000 n \n"
        for offset in offsets
    ).encode()
    body += f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n".encode()
    body += f"startxref\n{xref + 7 if bad_startxref else xref}\n%%EOF\n".encode()
    return _write(out, name, body)


_MAIN = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_PKG = "http://schemas.openxmlformats.org/package/2006/relationships"
_XML_DECL = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'


def _rels(*relationships: tuple[str, str, bool]) -> str:
    items = "".join(
        f'<Relationship Id="rId{i}" Type="{kind}" Target="{escape(target, {chr(34): "&quot;"})}"'
        f"{' TargetMode=' + chr(34) + 'External' + chr(34) if external else ''}/>"
        for i, (kind, target, external) in enumerate(relationships, 1)
    )
    return f'<Relationships xmlns="{_PKG}">{items}</Relationships>'


def _ooxml(parts: dict[str, str | bytes]) -> bytes:
    return _zip_bytes({k: _XML_DECL + v if isinstance(v, str) else v for k, v in parts.items()})


def _content_types(main: str, *extra: str) -> str:
    return (
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" '
        'ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/>'
        f'<Override PartName="{main}"/>{"".join(extra)}</Types>'
    )


def _cell(value: str, strings: list[str] | None) -> str:
    if value.startswith("="):
        return f"<c><f>{escape(value[1:])}</f></c>"
    if strings is not None:
        strings.append(value)
        return f'<c t="s"><v>{len(strings) - 1}</v></c>'
    return f'<c t="inlineStr"><is><t xml:space="preserve">{escape(value)}</t></is></c>'


def xlsx(
    out: Path,
    *,
    cells: list[list[str]],
    name: str = "statement.xlsx",
    vba: str | None = None,
    shared_strings: bool = False,
    macro_sheet: bool = False,
    dde_link: bool = False,
    embedded: dict[str, list[str]] | None = None,
) -> Path:
    strings: list[str] | None = [] if shared_strings else None
    rows = "".join("<row>" + "".join(_cell(v, strings) for v in row) + "</row>" for row in cells)
    workbook_rels = [(f"{_REL}/worksheet", "worksheets/sheet1.xml", False)]
    names = ""
    parts: dict[str, str | bytes] = {
        "_rels/.rels": _rels((f"{_REL}/officeDocument", "xl/workbook.xml", False)),
        "xl/worksheets/sheet1.xml": (
            f'<worksheet xmlns="{_MAIN}"><sheetData>{rows}</sheetData></worksheet>'
        ),
    }
    if strings is not None:
        items = "".join(f'<si><t xml:space="preserve">{escape(s)}</t></si>' for s in strings)
        parts["xl/sharedStrings.xml"] = f'<sst xmlns="{_MAIN}">{items}</sst>'
        workbook_rels.append((f"{_REL}/sharedStrings", "sharedStrings.xml", False))
    if vba is not None:
        parts["xl/vbaProject.bin"] = _ole_bytes(_vba_streams(vba, ""))
        workbook_rels.append(
            (
                "http://schemas.microsoft.com/office/2006/relationships/vbaProject",
                "vbaProject.bin",
                False,
            )
        )
    if macro_sheet:
        parts["xl/macrosheets/sheet2.xml"] = (
            '<xm:macrosheet xmlns:xm="http://schemas.microsoft.com/office/excel/2006/main" '
            f'xmlns="{_MAIN}"><sheetData><row><c><f>EXEC("C:\\missing\\filevet.exe")</f></c>'
            "</row></sheetData></xm:macrosheet>"
        )
        workbook_rels.append((f"{_REL}/xlMacrosheet", "macrosheets/sheet2.xml", False))
        names = (
            '<definedNames><definedName name="_xlnm.Auto_Open">Macro1!$A$1</definedName>'
            "</definedNames>"
        )
    if dde_link:
        parts["xl/externalLinks/externalLink1.xml"] = (
            f'<externalLink xmlns="{_MAIN}"><ddeLink ddeService="cmd" '
            'ddeTopic="/c C:\\missing\\filevet.exe"/></externalLink>'
        )
        workbook_rels.append((f"{_REL}/externalLink", "externalLinks/externalLink1.xml", False))
    if embedded:
        parts["xl/embeddings/oleObject1.bin"] = _ole_document(
            "o.bin", "", None, False, None, embedded
        )
    main_type = (
        "application/vnd.ms-excel.sheet.macroEnabled.main+xml"
        if vba
        else ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml")
    )
    parts["[Content_Types].xml"] = _content_types(
        f'/xl/workbook.xml" ContentType="{main_type}',
        '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/'
        'vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>',
    )
    parts["xl/workbook.xml"] = (
        f'<workbook xmlns="{_MAIN}" xmlns:r="{_REL}"><sheets>'
        f'<sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets>{names}</workbook>'
    )
    parts["xl/_rels/workbook.xml.rels"] = _rels(*workbook_rels)
    return _write(out, name, _ooxml(parts))


def docx(
    out: Path,
    *,
    name: str = "letter.docx",
    text: str = "Invoice 2026-0001",
    dde: str | None = None,
    remote_template: str | None = None,
    hyperlink: str | None = None,
    vba: str | None = None,
) -> Path:
    w = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
    runs = f"<w:r><w:t>{escape(text)}</w:t></w:r>"
    if dde:
        runs += (
            '<w:r><w:fldChar w:fldCharType="begin"/></w:r>'
            f'<w:r><w:instrText xml:space="preserve"> DDEAUTO {escape(dde)} </w:instrText></w:r>'
            '<w:r><w:fldChar w:fldCharType="end"/></w:r>'
        )
    document_rels = [(f"{_REL}/settings", "settings.xml", False)]
    if hyperlink:
        document_rels.append((f"{_REL}/hyperlink", hyperlink, True))
    parts: dict[str, str | bytes] = {
        "[Content_Types].xml": _content_types(
            '/word/document.xml" ContentType="application/'
            "vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"
        ),
        "_rels/.rels": _rels((f"{_REL}/officeDocument", "word/document.xml", False)),
        "word/document.xml": (
            f'<w:document xmlns:w="{w}"><w:body><w:p>{runs}</w:p></w:body></w:document>'
        ),
        "word/settings.xml": f'<w:settings xmlns:w="{w}"/>',
    }
    if remote_template:
        parts["word/_rels/settings.xml.rels"] = _rels(
            (f"{_REL}/attachedTemplate", remote_template, True)
        )
    if vba is not None:
        parts["word/vbaProject.bin"] = _ole_bytes(_vba_streams(vba, ""))
        document_rels.append(
            (
                "http://schemas.microsoft.com/office/2006/relationships/vbaProject",
                "vbaProject.bin",
                False,
            )
        )
    parts["word/_rels/document.xml.rels"] = _rels(*document_rels)
    return _write(out, name, _ooxml(parts))
