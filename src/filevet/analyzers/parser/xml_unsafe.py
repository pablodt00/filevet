import io
import re

from defusedxml.ElementTree import iterparse

from filevet.core.analyzer import AnalysisContext, AnalyzerResult
from filevet.core.artifact import Artifact
from filevet.core.errors import XML_ERRORS
from filevet.core.finding import Finding, Location, Severity
from filevet.core.identify import iso20022_message

MAX_DEPTH = 64
DOCTYPE = re.compile(r"<!DOCTYPE\b[^\[>]*(\[.*?\]\s*)?>", re.I | re.S)
ENTITY = re.compile(r"<!ENTITY\s+(%\s+)?\S+\s+(SYSTEM|PUBLIC|\"[^\"]*\"|'[^']*')", re.I)
EXTERNAL_ID = re.compile(r"\b(SYSTEM|PUBLIC)\s+[\"']", re.I)
XINCLUDE = "http://www.w3.org/2001/XInclude"
CWE_611 = "https://cwe.mitre.org/data/definitions/611.html"
CWE_776 = "https://cwe.mitre.org/data/definitions/776.html"
OWASP_XXE = "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"


class XmlUnsafe:
    name = "parser.xml_unsafe"
    version = "0.1.0"

    def supports(self, artifact: Artifact) -> bool:
        return artifact.detected_type == "xml"

    def analyze(self, artifact: Artifact, ctx: AnalysisContext) -> AnalyzerResult:
        data = artifact.read(ctx.limits.max_input_bytes)
        utf16 = data.startswith((b"\xff\xfe", b"\xfe\xff"))
        text = data.decode("utf-16" if utf16 else "utf-8", "replace")
        payment = iso20022_message(text) is not None
        findings = []
        if doctype := DOCTYPE.search(text):
            findings += _dtd(doctype[0], doctype.start(), payment)
        if XINCLUDE in text:
            findings.append(
                _finding("XInclude", "pulls in other files when processed", Severity.HIGH, XINCLUDE)
            )
        if not findings:
            findings += _parse(data)
        return AnalyzerResult(findings=findings)


def _dtd(dtd: str, offset: int, payment: bool) -> list[Finding]:
    where = Location(offset=offset)
    entities = ENTITY.findall(dtd)
    findings = []
    if EXTERNAL_ID.search(dtd):
        why = "references an external resource, which is how XXE reads local files"
        findings.append(_finding("External entity or DTD", why, Severity.CRITICAL, dtd, where))
    if any(p for p, _ in entities):
        why = "declares a parameter entity, used for blind XXE and out-of-band data theft"
        findings.append(_finding("Parameter entity", why, Severity.CRITICAL, dtd, where))
    if len(entities) > 1 and re.search(r"<!ENTITY[^>]*&[\w.:-]+;", dtd):
        why = "has entities that expand other entities (billion laughs)"
        findings.append(_finding("Entity expansion", why, Severity.CRITICAL, dtd, where, CWE_776))
    if not findings:
        severity = Severity.HIGH if payment else Severity.MEDIUM
        why = "has a DTD" + (", which an ISO 20022 message never needs" if payment else "")
        findings.append(_finding("Document type declaration", why, severity, dtd, where))
    return findings


def _parse(data: bytes) -> list[Finding]:
    depth = 0
    try:
        for event, element in iterparse(io.BytesIO(data), events=("start", "end")):
            depth += 1 if event == "start" else -1
            if depth > MAX_DEPTH:
                why = f"nests elements more than {MAX_DEPTH} levels deep"
                return [_finding("Deep nesting", why, Severity.MEDIUM, element.tag)]
            if event == "end":
                element.clear()
    except XML_ERRORS as exc:
        return [
            Finding(
                rule_id="parser.malformed",
                title="XML could not be parsed",
                description=f"The XML is not well formed ({type(exc).__name__}).",
                severity=Severity.MEDIUM,
                evidence=str(exc),
            )
        ]
    return []


def _finding(
    title: str,
    why: str,
    severity: Severity,
    evidence: str,
    where: Location | None = None,
    reference: str = CWE_611,
) -> Finding:
    return Finding(
        rule_id="parser.xml_unsafe",
        title=title,
        description=f"The XML {why}.",
        severity=severity,
        location=where,
        evidence=evidence,
        references=[reference, OWASP_XXE],
    )
