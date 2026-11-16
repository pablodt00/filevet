import csv
import io
import posixpath
import re
import zipfile
from collections import Counter
from collections.abc import Callable
from functools import partial

import pikepdf

from filevet.analyzers.parser.csv_formula_injection import MAX_FIELD, risk
from filevet.core.analyzer import AnalysisContext, AnalyzerResult, ExtractedFile
from filevet.core.artifact import Artifact
from filevet.core.extract_finance import decode
from filevet.core.finding import Finding, Severity
from filevet.core.limits import Limits

Removed = Counter[tuple[str, str]]

PDF_KEYS = {
    "/OpenAction": "action",
    "/AA": "action",
    "/A": "action",
    "/JS": "javascript",
    "/JavaScript": "javascript",
    "/EmbeddedFiles": "embedded_file",
    "/AcroForm": "form",
    "/XFA": "form",
}
XLSX_PARTS = {
    "xl/vbaProject.bin": "macro",
    "xl/vbaProjectSignature.bin": "macro",
    "xl/macrosheets/": "macro",
    "xl/externalLinks/": "external_link",
}
MACRO_TYPE = b"application/vnd.ms-excel.sheet.macroEnabled.main+xml"
SHEET_TYPE = b"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"
_ATTR = r'\b{}\s*=\s*"([^"]*)"'
AUTO_NAME = re.compile(
    rb'<(?:\w+:)?definedName\b[^>]*\bname\s*=\s*"_xlnm\.Auto_\w*"[^>]*>[^<]*</(?:\w+:)?definedName>'
)


class Sanitizer:
    name = "pipeline.sanitize"
    version = "0.1.0"

    def supports(self, artifact: Artifact) -> bool:
        return artifact.detected_type in {"pdf", "text", "zip"}

    def analyze(self, artifact: Artifact, ctx: AnalysisContext) -> AnalyzerResult:
        data = artifact.read(ctx.limits.max_input_bytes)
        handlers: dict[str, Callable[[bytes, Limits], tuple[bytes, Removed]]] = {
            "pdf": _pdf,
            "text": _csv,
            "zip": _xlsx,
        }
        clean, removed = handlers[artifact.detected_type](data, ctx.limits)
        findings = [
            Finding(
                rule_id=f"sanitize.{kind}",
                title=f"Removed {count} {kind.replace('_', ' ')} item(s)",
                description=where,
                severity=Severity.INFO,
            )
            for (kind, where), count in sorted(removed.items())
        ]
        return AnalyzerResult(findings=findings, children=[ExtractedFile(name="clean", data=clean)])


def _pdf(data: bytes, limits: Limits) -> tuple[bytes, Removed]:
    removed: Removed = Counter()
    with pikepdf.open(io.BytesIO(data)) as pdf:
        if "/AcroForm" in pdf.Root:
            pdf.generate_appearance_streams()
        pdf.flatten_annotations()
        for number, page in enumerate(pdf.pages, 1):
            if "/Annots" in page.obj:
                removed["annotation", f"page {number}"] += len(page.obj.Annots)
                del page.obj["/Annots"]
        for obj in pdf.objects:
            _strip(obj, removed)
        out = io.BytesIO()
        pdf.save(out)
    return out.getvalue(), removed


def _strip(obj: object, removed: Removed) -> None:
    if isinstance(obj, pikepdf.Dictionary | pikepdf.Stream):
        for key in sorted(obj.keys() & PDF_KEYS.keys()):
            removed[PDF_KEYS[key], f"{key} entries"] += 1
            del obj[key]
        children = [obj[k] for k in sorted(obj.keys())]
    elif isinstance(obj, pikepdf.Array):
        children = list(obj)
    else:
        return
    for child in children:
        if isinstance(child, pikepdf.Object) and not child.is_indirect:
            _strip(child, removed)


def _csv(data: bytes, limits: Limits) -> tuple[bytes, Removed]:
    text = decode(data)
    try:
        delimiter = csv.Sniffer().sniff(text[:16384], ",;\t|").delimiter
    except csv.Error:
        delimiter = ","
    csv.field_size_limit(MAX_FIELD)
    removed: Removed = Counter()
    out = io.StringIO()
    writer = csv.writer(out, delimiter=delimiter)
    for row in csv.reader(io.StringIO(text, newline=""), delimiter=delimiter):
        neutral = [f"'{v}" if risk(v) else v for v in row]
        removed["formula", "cells prefixed with '"] += sum(map(str.__ne__, row, neutral))
        writer.writerow(neutral)
    return out.getvalue().encode(), +removed


def _xlsx(data: bytes, limits: Limits) -> tuple[bytes, Removed]:
    removed: Removed = Counter()
    budget = limits.max_total_expanded_bytes
    with zipfile.ZipFile(io.BytesIO(data)) as zin:
        names = zin.namelist()
        if "xl/workbook.xml" not in names:
            raise ValueError("only XLSX workbooks can be sanitized")
        dropped = {n for n in names if _kind(n)}
        parts = {}
        for info in zin.infolist():
            if info.filename in dropped:
                removed[_kind(info.filename), info.filename] += 1
                continue
            with zin.open(info) as f:
                parts[info.filename] = f.read(budget + 1)
            budget -= len(parts[info.filename])
            if budget < 0:
                raise ValueError("workbook expands past max_total_expanded_bytes")
    ids: set[bytes] = set()
    for name in [n for n in parts if n.endswith(".rels")]:
        base = posixpath.dirname(posixpath.dirname(name))
        gone = partial(_gone, base=base, dropped=dropped, ids=ids)
        parts[name] = _drop(parts[name], b"Relationship", gone)
    if "[Content_Types].xml" in parts:
        types = _drop(
            parts["[Content_Types].xml"],
            b"Override",
            lambda e: _attr(e, b"PartName").lstrip(b"/").decode(errors="replace") in dropped,
        )
        parts["[Content_Types].xml"] = types.replace(MACRO_TYPE, SHEET_TYPE)
    workbook = _drop(parts["xl/workbook.xml"], b"sheet", lambda e: _attr(e, b"r:id") in ids)
    workbook, autos = AUTO_NAME.subn(b"", _drop_block(workbook, b"externalReferences"))
    if autos:
        removed["macro", "auto-run defined names"] += autos
    parts["xl/workbook.xml"] = workbook
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zout:
        for name, content in parts.items():
            zout.writestr(name, content)
    return out.getvalue(), removed


def _kind(name: str) -> str:
    return next((kind for prefix, kind in XLSX_PARTS.items() if name.startswith(prefix)), "")


def _attr(element: bytes, name: bytes) -> bytes:
    found = re.search(_ATTR.format(re.escape(name.decode())).encode(), element)
    return found.group(1) if found else b""


def _gone(element: bytes, base: str, dropped: set[str], ids: set[bytes]) -> bool:
    target = _attr(element, b"Target").decode(errors="replace")
    if _attr(element, b"TargetMode") == b"External":
        return False
    path = target.lstrip("/") if target.startswith("/") else posixpath.join(base, target)
    if posixpath.normpath(path) in dropped:
        ids.add(_attr(element, b"Id"))
        return True
    return False


def _drop(xml: bytes, tag: bytes, gone: Callable[[bytes], bool]) -> bytes:
    pattern = re.compile(rb"<(?:\w+:)?" + tag + rb"\b[^>]*/>")
    return pattern.sub(lambda m: b"" if gone(m.group(0)) else m.group(0), xml)


def _drop_block(xml: bytes, tag: bytes) -> bytes:
    start = re.search(rb"<(?:\w+:)?" + tag + rb"\b", xml)
    if start is None:
        return xml
    close = re.compile(rb"</(?:\w+:)?" + tag + rb"\s*>").search(xml, start.end())
    return xml[: start.start()] + xml[close.end() :] if close else xml
