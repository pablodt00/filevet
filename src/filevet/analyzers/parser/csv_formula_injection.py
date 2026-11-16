import csv
import io
import re
import unicodedata
import zipfile
from collections.abc import Iterable, Iterator
from xml.etree.ElementTree import Element

from defusedxml.ElementTree import fromstring

from filevet.core.analyzer import AnalysisContext, AnalyzerResult
from filevet.core.artifact import Artifact
from filevet.core.errors import XML_ERRORS, ZIP_ERRORS
from filevet.core.extract_finance import column, decode
from filevet.core.finding import Finding, Location, Severity

MAX_ROWS = 1_000_000
MAX_COLUMNS = 1_000
MAX_FIELD = 1 << 17
MAX_FINDINGS = 50
SNIFF = 1 << 14
LEADING = " \t\r\n\"'　"
TRIGGERS = "=+-@"
NUMBER = re.compile(r"[+-][\d\s.,'()%]*\d[\d\s.,'()%]*( ?[A-Z]{3})?")
DANGEROUS = re.compile(
    r"(?i)(\w+\s*\|\s*'|cmd\s*\||\b(hyperlink|webservice|importxml|importdata|importhtml|"
    r"importfeed|importrange|image|call|register|exec|filterxml)\s*\(|\bdde(auto)?\b)"
)
OWASP = "https://owasp.org/www-community/attacks/CSV_Injection"
CWE_1236 = "https://cwe.mitre.org/data/definitions/1236.html"


class CsvFormulaInjection:
    name = "parser.csv_formula_injection"
    version = "0.1.0"

    def supports(self, artifact: Artifact) -> bool:
        return artifact.detected_type in {"text", "zip"}

    def analyze(self, artifact: Artifact, ctx: AnalysisContext) -> AnalyzerResult:
        data = artifact.read(ctx.limits.max_input_bytes)
        cells: Iterable[tuple[Location, str]]
        if artifact.detected_type == "text":
            cells = _csv_cells(data)
        else:
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as zf:
                    cells = list(_xlsx_cells(zf, ctx.limits.max_input_bytes))
            except (*ZIP_ERRORS, ValueError):
                return AnalyzerResult()
        findings = []
        try:
            for location, value in cells:
                if (severity := risk(value)) is not None:
                    findings.append(_finding(location, value, severity))
                    if len(findings) == MAX_FINDINGS:
                        break
        except (csv.Error, _TooLarge) as exc:
            findings.append(
                Finding(
                    rule_id="parser.malformed",
                    title="CSV could not be parsed",
                    description=f"Parsing stopped: {exc}. The rest of the file was not checked.",
                    severity=Severity.MEDIUM,
                    evidence=str(exc),
                )
            )
        return AnalyzerResult(findings=findings)


def risk(value: str) -> Severity | None:
    head = value.lstrip(LEADING)[:1]
    if not head or head.isalnum():
        return None
    text = unicodedata.normalize("NFKC", value).lstrip(LEADING)
    if len(text) < 2 or text[0] not in TRIGGERS:
        return None
    if text[0] in "+-" and NUMBER.fullmatch(text):
        return None
    return Severity.HIGH if text[0] in "=@" or DANGEROUS.search(text) else Severity.MEDIUM


class _TooLarge(Exception):
    pass


def _csv_cells(data: bytes) -> Iterator[tuple[Location, str]]:
    text = decode(data)
    try:
        dialect: type[csv.Dialect] | csv.Dialect = csv.Sniffer().sniff(text[:SNIFF], ",;\t|")
    except csv.Error:
        dialect = csv.excel
    csv.field_size_limit(MAX_FIELD)
    for row_number, row in enumerate(csv.reader(io.StringIO(text, newline=""), dialect), 1):
        if row_number > MAX_ROWS:
            raise _TooLarge(f"more than {MAX_ROWS} rows")
        if len(row) > MAX_COLUMNS:
            raise _TooLarge(f"row {row_number} has more than {MAX_COLUMNS} columns")
        for number, value in enumerate(row, 1):
            yield Location(cell=f"{column(number)}{row_number}"), value


def _xlsx_cells(zf: zipfile.ZipFile, limit: int) -> Iterator[tuple[Location, str]]:
    names = set(zf.namelist())
    if "xl/workbook.xml" not in names:
        return
    strings = []
    if "xl/sharedStrings.xml" in names:
        for si in _local(_xml(zf, "xl/sharedStrings.xml", limit), "si"):
            strings.append("".join(t.text or "" for t in _local(si, "t")))
    for part in sorted(n for n in names if n.startswith("xl/worksheets/") and n.endswith(".xml")):
        sheet = part.rsplit("/", 1)[1].removesuffix(".xml")
        for row_number, row in enumerate(_local(_xml(zf, part, limit), "row"), 1):
            for number, cell in enumerate(_local(row, "c"), 1):
                if next(_local(cell, "f"), None) is not None:
                    continue
                ref = cell.get("r") or f"{column(number)}{row.get('r') or row_number}"
                if cell.get("t") == "inlineStr":
                    value = "".join(t.text or "" for t in _local(cell, "t"))
                elif cell.get("t") == "s":
                    v = next(_local(cell, "v"), None)
                    text = v.text if v is not None else None
                    index = int(text) if text and text.isdigit() else -1
                    value = strings[index] if 0 <= index < len(strings) else ""
                else:
                    continue
                yield Location(sheet=sheet, cell=ref), value


def _xml(zf: zipfile.ZipFile, part: str, limit: int) -> Element:
    try:
        with zf.open(part) as f:
            root: Element = fromstring(f.read(limit), forbid_dtd=True)
            return root
    except (*XML_ERRORS, *ZIP_ERRORS):
        return Element("empty")


def _local(element: Element, name: str) -> Iterator[Element]:
    return (e for e in element.iter() if e.tag.rsplit("}", 1)[-1] == name)


def _finding(location: Location, value: str, severity: Severity) -> Finding:
    return Finding(
        rule_id="parser.csv_formula_injection",
        title="Cell runs as a formula in a spreadsheet",
        description="The value starts with a formula character, so a spreadsheet app runs it.",
        severity=severity,
        location=location,
        evidence=value,
        references=[OWASP, CWE_1236],
    )
