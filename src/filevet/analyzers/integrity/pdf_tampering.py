import re
from collections import Counter
from datetime import UTC, datetime, timedelta, timezone
from difflib import SequenceMatcher
from xml.etree.ElementTree import ParseError

from defusedxml import DefusedXmlException
from defusedxml.ElementTree import fromstring

from filevet.analyzers.integrity.pdf import Box, Page, Pdf, Text, is_type, lines, name, refs
from filevet.core.analyzer import AnalysisContext, AnalyzerResult
from filevet.core.artifact import Artifact
from filevet.core.extract_finance import AMOUNT, DATE, IBAN, mask
from filevet.core.finding import Finding, Location, Severity

MAX_FINDINGS = 10
MAX_LINES = 20_000
OVERLAP = 0.5
PDF_DATE = re.compile(
    r"(?:D:)?(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?(?:([+-])(\d{2})'?(\d{2})?)?"
)
SUBSET = re.compile(r"^[A-Z]{6}\+")
FONT_KINDS = (b"Font", b"FontDescriptor")
REFERENCES = ["https://www.pdfa.org/resource/iso-32000-pdf/"]


class PdfTampering:
    name = "integrity.pdf_tampering"
    version = "0.1.0"

    def supports(self, artifact: Artifact) -> bool:
        return artifact.detected_type == "pdf"

    def analyze(self, artifact: Artifact, ctx: AnalysisContext) -> AnalyzerResult:
        data = artifact.read(ctx.limits.max_input_bytes)
        try:
            pdf = Pdf(data, ctx.limits.max_total_expanded_bytes)
            pages = [] if pdf.encrypted else [pdf.pages(i) for i in range(len(pdf.ends))]
            findings = [
                *_revisions(pdf),
                *_diff(pages),
                *_producer(pdf, pages[-1] if pages else [], ctx),
                *_overlay(pages[-1] if pages else []),
                *_fonts(pdf, pages[-1] if pages else []),
            ]
        except (ValueError, IndexError, KeyError, OverflowError, RecursionError) as exc:
            findings = [
                Finding(
                    rule_id="parser.malformed",
                    title="PDF could not be read for integrity checks",
                    description=f"Reading failed: {type(exc).__name__}. The checks did not run.",
                    severity=Severity.MEDIUM,
                    evidence=type(exc).__name__,
                )
            ]
        if ctx.mask:
            findings = [f.model_copy(update={"evidence": mask(f.evidence)}) for f in findings]
        return AnalyzerResult(findings=findings)


def _revisions(pdf: Pdf) -> list[Finding]:
    if len(pdf.segments) < 2:
        return []
    severity, notes = Severity.INFO, []
    for revision in range(1, len(pdf.segments)):
        objs = pdf.objects(revision)
        contents = {
            r for o in objs.values() if is_type(o.body, b"Page") for r in refs(o.body, b"Contents")
        }
        info = pdf.trailer_ref(revision, b"Info")
        kinds = set()
        for num, obj in pdf.segments[revision].items():
            kinds.add(_kind(num, obj.body, contents, info))
        kinds.discard("structure")
        if "content" in kinds:
            severity = Severity.MEDIUM
        elif kinds & {"page", "font", "other"} and severity == Severity.INFO:
            severity = Severity.LOW
        notes.append(f"revision {revision + 1}: {', '.join(sorted(kinds)) or 'structure only'}")
    why = (
        "Page content changed after the document was first saved."
        if severity == Severity.MEDIUM
        else "The document was saved again after it was created. Page content did not change."
    )
    return [
        _finding(
            "pdf_incremental_updates",
            f"PDF was saved {len(pdf.segments)} times",
            why,
            severity,
            "; ".join(notes),
        )
    ]


def _kind(num: int, body: bytes, contents: set[int], info: int | None) -> str:
    if num in contents:
        return "content"
    if any(is_type(body, kind) for kind in FONT_KINDS) or b"/FontFile" in body:
        return "font"
    if is_type(body, b"Page"):
        return "page"
    if num == info or is_type(body, b"Metadata"):
        return "metadata"
    if is_type(body, b"Sig") or b"/ByteRange" in body:
        return "signature"
    if is_type(body, b"Annot") or b"/FT" in body or b"/AcroForm" in body:
        return "form"
    if any(is_type(body, kind) for kind in (b"XRef", b"ObjStm", b"Catalog", b"Pages")):
        return "structure"
    return "other"


def _diff(revisions: list[list[Page]]) -> list[Finding]:
    findings: list[Finding] = []
    texts = [lines(pages)[:MAX_LINES] for pages in revisions]
    for revision in range(1, len(texts)):
        old, new = texts[revision - 1], texts[revision]
        matcher = SequenceMatcher(None, old, new, autojunk=False)
        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag == "equal" or len(findings) == MAX_FINDINGS:
                continue
            before = " / ".join(line.split("\t", 1)[1] for line in old[i1:i2])
            after = " / ".join(line.split("\t", 1)[1] for line in new[j1:j2])
            page = int((old[i1:i2] or new[j1:j2])[0].split("\t", 1)[0])
            data = any(p.search(before + " " + after) for p in (AMOUNT, IBAN, DATE))
            findings.append(
                _finding(
                    "pdf_revision_diff",
                    f"Text changed in revision {revision + 1}",
                    "An amount, IBAN or date was changed after the document was first saved."
                    if data
                    else "Text on the page was changed after the document was first saved.",
                    Severity.MEDIUM if data else Severity.LOW,
                    f"{before!r} -> {after!r}",
                    Location(page=page),
                )
            )
    return findings


def _producer(pdf: Pdf, pages: list[Page], ctx: AnalysisContext) -> list[Finding]:
    findings = []
    infos = [pdf.info(i) for i in range(len(pdf.ends))]
    first, last = infos[0], infos[-1]
    created, modified = _date(last.get("CreationDate")), _date(last.get("ModDate"))
    if created and modified and modified < created:
        why = "The modification date is earlier than the creation date."
        evidence = f"created {last['CreationDate']}, modified {last['ModDate']}"
        findings.append(
            _finding(
                "pdf_producer_mismatch",
                "PDF dates contradict each other",
                why,
                Severity.MEDIUM,
                evidence,
            )
        )
    producers = [info["Producer"] for info in infos if info.get("Producer")]
    if producers and first.get("Producer") and producers[-1] != first["Producer"]:
        why = "The first and the last version were written by different software."
        evidence = f"{first['Producer']} -> {producers[-1]}"
        findings.append(
            _finding(
                "pdf_producer_mismatch",
                "PDF producer changed between revisions",
                why,
                Severity.LOW,
                evidence,
            )
        )
    xmp = _xmp_producer(pdf.xmp(len(pdf.ends) - 1))
    if xmp and last.get("Producer") and xmp.strip() != last["Producer"].strip():
        why = "The XMP metadata and the document info name different producers."
        evidence = f"XMP {xmp}, Info {last['Producer']}"
        findings.append(
            _finding("pdf_producer_mismatch", "PDF metadata disagree", why, Severity.LOW, evidence)
        )
    text = " ".join(t.text for page in pages for t in page.texts).casefold()
    for party_name, party in ctx.expected.parties.items():
        if party.producers and party_name.casefold() in text:
            unexpected = sorted({p for p in producers if p not in party.producers})
            if unexpected:
                why = (
                    "The document names a known issuer, but was not produced by its usual software."
                )
                findings.append(
                    _finding(
                        "pdf_producer_mismatch",
                        "Unexpected PDF producer for this issuer",
                        why,
                        Severity.MEDIUM,
                        ", ".join(unexpected),
                    )
                )
    return findings


def _date(value: str | None) -> datetime | None:
    match = PDF_DATE.match(value or "")
    if match is None:
        return None
    parts = [
        int(p) if p else d for p, d in zip(match.groups()[:6], (0, 1, 1, 0, 0, 0), strict=True)
    ]
    zone = UTC
    if match[7]:
        offset = timedelta(hours=int(match[8] or 0), minutes=int(match[9] or 0))
        zone = timezone(offset if match[7] == "+" else -offset)
    try:
        return datetime(parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], tzinfo=zone)
    except ValueError:
        return None


def _xmp_producer(data: bytes) -> str | None:
    if not data:
        return None
    try:
        root = fromstring(data, forbid_dtd=True)
    except (ParseError, DefusedXmlException):
        return None
    for element in root.iter():
        for key, value in element.attrib.items():
            if key.endswith("}Producer"):
                return str(value)
        if element.tag.endswith("}Producer") and element.text:
            return str(element.text)
    return None


def _overlay(pages: list[Page]) -> list[Finding]:
    findings: list[Finding] = []
    for page in pages:
        for box in page.boxes:
            covered = [t for t in page.texts if t.order < box.order and _overlap(box, t) > OVERLAP]
            if covered and len(findings) < MAX_FINDINGS:
                why = "A white rectangle is painted over text, hiding the original content."
                evidence = " / ".join(t.text for t in covered)
                findings.append(
                    _finding(
                        "pdf_text_overlay",
                        "Text hidden under a white box",
                        why,
                        Severity.MEDIUM,
                        evidence,
                        Location(page=page.number),
                    )
                )
        texts = sorted(page.texts, key=lambda t: t.y)
        for i, low in enumerate(texts):
            for high in texts[i + 1 :]:
                if high.y - low.y > max(low.height, high.height) or len(findings) >= MAX_FINDINGS:
                    break
                if low.text.strip() != high.text.strip() and _overlap(low, high) > OVERLAP:
                    first, second = sorted((low, high), key=lambda t: t.order)
                    why = "Text is drawn on top of other text, a common way to change a value."
                    evidence = f"{first.text!r} under {second.text!r}"
                    findings.append(
                        _finding(
                            "pdf_text_overlay",
                            "Text drawn over other text",
                            why,
                            Severity.MEDIUM,
                            evidence,
                            Location(page=page.number),
                        )
                    )
    return findings


def _overlap(a: Text | Box, b: Text | Box) -> float:
    ax, ay, aw, ah = a.x, a.y, a.width, a.height
    bx, by, bw, bh = b.x, b.y, b.width, b.height
    width = min(ax + aw, bx + bw) - max(ax, bx)
    height = min(ay + ah, by + bh) - max(ay, by)
    smaller = min(aw * ah, bw * bh)
    return width * height / smaller if width > 0 and height > 0 and smaller > 0 else 0.0


def _fonts(pdf: Pdf, pages: list[Page]) -> list[Finding]:
    findings = []
    for page in pages:
        used = Counter(t.font for t in page.texts)
        families: dict[str, set[str]] = {}
        for key in used:
            base = page.fonts.get(key, "")
            families.setdefault(SUBSET.sub("", base), set()).add(key)
        for keys in families.values():
            if len(keys) < 2 or len({page.fonts.get(k, "") for k in keys}) < 2:
                continue
            rare = min(keys, key=lambda k: used[k])
            texts = [t.text for t in page.texts if t.font == rare and re.search(r"\d", t.text)]
            if texts:
                why = "Digits are set in a second copy of the same font, as editors do on retyping."
                evidence = f"{page.fonts[rare]}: {' / '.join(texts)}"
                findings.append(
                    _finding(
                        "pdf_font_anomaly",
                        "Numbers in a separately embedded font",
                        why,
                        Severity.MEDIUM,
                        evidence,
                        Location(page=page.number),
                    )
                )
        amount_only = {
            key
            for key in used
            if all(AMOUNT.fullmatch(t.text.strip()) for t in page.texts if t.font == key)
        }
        if len(used) > 1 and amount_only and amount_only != set(used):
            for key in sorted(amount_only):
                why = "This font is used for amounts only, and for no other text on the page."
                findings.append(
                    _finding(
                        "pdf_font_anomaly",
                        "Amounts in a font of their own",
                        why,
                        Severity.LOW,
                        page.fonts.get(key, key),
                        Location(page=page.number),
                    )
                )
    for revision in range(1, len(pdf.segments)):
        added = [
            (name(obj.body, b"BaseFont") or name(obj.body, b"FontName") or b"").decode("latin-1")
            for obj in pdf.segments[revision].values()
            if any(is_type(obj.body, kind) for kind in FONT_KINDS)
        ]
        if added:
            why = "Fonts or glyphs were added after the document was first saved."
            findings.append(
                _finding(
                    "pdf_font_anomaly",
                    f"Font changed in revision {revision + 1}",
                    why,
                    Severity.LOW,
                    ", ".join(sorted(set(added))),
                )
            )
    return findings[:MAX_FINDINGS]


def _finding(
    rule: str,
    title: str,
    description: str,
    severity: Severity,
    evidence: str,
    location: Location | None = None,
) -> Finding:
    return Finding(
        rule_id=f"integrity.{rule}",
        title=title,
        description=description,
        severity=severity,
        confidence=0.6 if severity != Severity.INFO else 1.0,
        location=location,
        evidence=evidence,
        references=REFERENCES,
    )
