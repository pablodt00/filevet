import re
import unicodedata
from collections import defaultdict

from filevet.core.analyzer import AnalysisContext, AnalyzerResult
from filevet.core.artifact import Artifact
from filevet.core.extract_text import INVISIBLE, ZERO_WIDTH, Run, runs
from filevet.core.finding import Finding, Location, Severity

MAX_FINDINGS = 200
TAGS = re.compile("[\U000e0000-\U000e007f]+")
BIDI = re.compile("[\u202a-\u202e\u2066-\u2069]")
ZERO_WIDTH_IN_WORD = re.compile(f"[^\\W\\d_][{ZERO_WIDTH}]+[^\\W\\d_]")
COMMON_IN_OFFICE = frozenset({"hidden sheet", "hidden row", "hidden column", "custom XML part"})
WORD = re.compile(r"[^\W\d_]{2,}")
INJECTION = [
    (re.compile(p, re.I), label)
    for p, label in [
        (
            r"\b(ignore|disregard|forget|override)\b.{0,30}\b(previous|prior|above|earlier|all|"
            r"any|your)\b.{0,20}\b(instructions?|prompts?|rules|messages|context)\b",
            "override of earlier instructions",
        ),
        (r"\byou are now\b|\bfrom now on,? you\b|\bact as (a|an|the)\b", "role reassignment"),
        (r"(?m)^[ \t]*(system|assistant|developer)[ \t]*:", "chat role marker"),
        (r"<\|im_(start|end)\|>|\[/?INST\]|<<SYS>>|</?system>", "chat template token"),
        (r"\bnew instructions\b|\binstrucciones nuevas\b", "new instructions"),
        (
            r"\bdo not (tell|inform|mention|reveal)\b.{0,20}\b(user|human|reviewer)\b",
            "instruction to hide something from the user",
        ),
        (
            r"!\[[^\]]*\]\(https?://[^)\s]*\?[^)\s]*\)|\b(send|post|forward|upload)\b.{0,40}"
            r"\b(to|at)\b\s+(https?://|\S+@\S+\.\w+)",
            "exfiltration to a URL or address",
        ),
        (
            r"<tool_call>|\"function_call\"|\b(call|invoke|use) the [\w-]+ (tool|function)\b",
            "tool call",
        ),
        (
            r"\b(approve|authori[sz]e|mark)\b.{0,20}\b(this|the)\b.{0,20}"
            r"\b(invoice|payment|transfer|document)\b.{0,20}\b(as )?(paid|approved|legitimate|"
            r"safe|verified)?",
            "instruction to approve a payment or document",
        ),
        (
            r"\b(ignora|olvida|descarta)\b.{0,30}\b(las |todas las )?(instrucciones|indicaciones)"
            r"\b.{0,20}\b(anteriores|previas)?",
            "override of earlier instructions (Spanish)",
        ),
        (r"\bahora eres\b|\bact(u|ú)a como\b", "role reassignment (Spanish)"),
        (
            r"\bno (le )?(digas|informes|menciones|reveles)\b.{0,20}\b(usuario|revisor)\b",
            "instruction to hide something from the user (Spanish)",
        ),
        (
            r"\baprueba\b.{0,20}\b(esta|este)\b.{0,10}\b(factura|pago|transferencia)\b",
            "instruction to approve a payment (Spanish)",
        ),
    ]
]
REFERENCES = [
    "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    "https://atlas.mitre.org/techniques/AML.T0051",
]


class HiddenContent:
    name = "ai.hidden_content"
    version = "0.1.0"

    def supports(self, artifact: Artifact) -> bool:
        return artifact.detected_type in {"pdf", "zip", "text", "xml", "html"}

    def analyze(self, artifact: Artifact, ctx: AnalysisContext) -> AnalyzerResult:
        data = artifact.read(ctx.limits.max_input_bytes)
        try:
            found = runs(data, artifact.detected_type, ctx.limits.max_total_expanded_bytes)
        except (ValueError, IndexError, KeyError, OverflowError, RecursionError) as exc:
            return AnalyzerResult(
                findings=[
                    Finding(
                        rule_id="parser.malformed",
                        title="File could not be read for hidden content checks",
                        description=f"Reading failed: {type(exc).__name__}. Checks did not run.",
                        severity=Severity.MEDIUM,
                        evidence=type(exc).__name__,
                    )
                ]
            )
        pdf = artifact.detected_type == "pdf"
        findings = _hidden(found, pdf) + _smuggling(found)
        found += [
            Run(_untag(tags), "body", "Unicode tag characters", r.location)
            for r in found
            for tags in TAGS.findall(r.text)
        ]
        findings += _metadata(found) + _injection(found)
        return AnalyzerResult(findings=findings[:MAX_FINDINGS])


def _hidden(found: list[Run], pdf: bool) -> list[Finding]:
    groups: dict[tuple[str, str, Location | None], list[str]] = defaultdict(list)
    for run in found:
        if run.kind != "body" or run.hidden is None:
            continue
        where = run.location
        if where is not None and where.cell:
            where = Location(sheet=where.sheet)
        groups[(run.hidden, "ai.hidden_text" if pdf else "ai.hidden_text_office", where)].append(
            run.text
        )
    findings = []
    for (reason, rule, where), texts in groups.items():
        low = reason in COMMON_IN_OFFICE
        findings.append(
            Finding(
                rule_id=rule,
                title=f"Hidden text: {reason}",
                description=(
                    f"{len(texts)} piece(s) of text are {reason}. A person reading the document "
                    "won't see them, but a text extractor, and so an LLM, will."
                ),
                severity=Severity.LOW if low else Severity.MEDIUM,
                location=where,
                evidence=" ".join(texts),
                references=REFERENCES,
            )
        )
    return findings


def _smuggling(found: list[Run]) -> list[Finding]:
    checks: dict[str, tuple[Severity, str, Location | None]] = {}
    for run in found:
        text = run.text
        if (tags := TAGS.search(text)) and "tags" not in checks:
            checks["tags"] = (Severity.HIGH, _untag(tags[0]), run.location)
        if (bidi := BIDI.search(text)) and "bidi" not in checks:
            checks["bidi"] = (Severity.MEDIUM, _around(text, bidi.start()), run.location)
        if (zw := ZERO_WIDTH_IN_WORD.search(text)) and "zero_width" not in checks:
            checks["zero_width"] = (Severity.MEDIUM, _around(text, zw.start()), run.location)
        if "homoglyph" not in checks:
            words = (w for w in WORD.findall(text) if not w.isascii())
            mixed = next((w for w in words if len(_scripts(w)) > 1), None)
            if mixed:
                checks["homoglyph"] = (Severity.MEDIUM, mixed, run.location)
    titles = {
        "tags": "Unicode tag characters carry hidden ASCII text",
        "bidi": "Bidirectional override characters reorder text (Trojan Source)",
        "zero_width": "Zero-width characters inside words",
        "homoglyph": "Word mixes Latin with Cyrillic or Greek look-alike letters",
    }
    return [
        Finding(
            rule_id="ai.unicode_smuggling",
            title=titles[key],
            description=(
                "The text holds characters that render as nothing or as something else, "
                "so what a person sees differs from what software reads."
            ),
            severity=severity,
            location=where,
            evidence=evidence,
            references=["https://trojansource.codes/", *REFERENCES],
        )
        for key, (severity, evidence, where) in checks.items()
    ]


def _metadata(found: list[Run]) -> list[Finding]:
    findings = []
    for run in found:
        if run.kind != "metadata":
            continue
        label = _matches(run.text)
        if label:
            findings.append(
                Finding(
                    rule_id="ai.metadata_payload",
                    title="Instruction-like text in document metadata",
                    description=f"Metadata holds text that reads like an instruction ({label}).",
                    severity=Severity.HIGH,
                    location=run.location,
                    evidence=run.text,
                    references=REFERENCES,
                )
            )
    return findings


def _injection(found: list[Run]) -> list[Finding]:
    findings = []
    for run in found:
        label = _matches(run.text)
        if not label:
            continue
        hidden = run.hidden is not None
        findings.append(
            Finding(
                rule_id="ai.prompt_injection_patterns",
                title=f"Prompt injection pattern in {'hidden' if hidden else 'visible'} text",
                description=f"The text matches a prompt injection pattern ({label}). "
                + (f"It is hidden from a reader: {run.hidden}." if hidden else "It is visible."),
                severity=Severity.HIGH if hidden else Severity.LOW,
                confidence=0.9 if hidden else 0.3,
                location=run.location,
                evidence=run.text,
                references=REFERENCES,
            )
        )
    return findings


def _matches(text: str) -> str | None:
    clean = unicodedata.normalize("NFKC", INVISIBLE.sub("", text))
    return next((label for pattern, label in INJECTION if pattern.search(clean)), None)


def _untag(tags: str) -> str:
    return "".join(chr(ord(c) - 0xE0000) for c in tags if 0x20 <= ord(c) - 0xE0000 < 0x7F)


def _around(text: str, index: int) -> str:
    return text[max(0, index - 30) : index + 30]


def _scripts(word: str) -> set[str]:
    found = set()
    for c in word:
        script = unicodedata.name(c, "").split(" ", 1)[0]
        if script in {"LATIN", "CYRILLIC", "GREEK"}:
            found.add(script)
    return found
