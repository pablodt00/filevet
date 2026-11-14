import io
import zipfile

from filevet.core.analyzer import AnalysisContext, AnalyzerResult, ExtractedFile
from filevet.core.artifact import Artifact
from filevet.core.finding import Finding, Location, Severity

PDF_WINDOW = 1024
CONTAINERS = frozenset({"zip", "ole", "rar", "7z", "gzip"})
TRAILING = ((b"Rar!\x1a\x07", "rar"), (b"7z\xbc\xaf\x27\x1c", "7z"))
REFERENCES = ["https://cwe.mitre.org/data/definitions/434.html"]


class Polyglot:
    name = "parser.polyglot"
    version = "0.1.0"

    def supports(self, artifact: Artifact) -> bool:
        return artifact.detected_type != "empty"

    def analyze(self, artifact: Artifact, ctx: AnalysisContext) -> AnalyzerResult:
        data = artifact.read(ctx.limits.max_input_bytes)
        found: list[tuple[int, str]] = []
        pdf_at = data.find(b"%PDF-", 1, PDF_WINDOW)
        if pdf_at > 0 and artifact.detected_type != "pdf":
            found.append((pdf_at, "pdf"))
        if artifact.detected_type not in CONTAINERS:
            zip_at = data.find(b"PK\x03\x04", 1)
            if zip_at > 0 and zipfile.is_zipfile(io.BytesIO(data)):
                found.append((zip_at, "zip"))
            found += [(at, kind) for magic, kind in TRAILING if (at := data.find(magic, 1)) > 0]
        findings = [
            Finding(
                rule_id="parser.polyglot",
                title=f"File is also a valid {kind}",
                description=(
                    f"The file is detected as {artifact.detected_type} but has a {kind} "
                    f"starting at byte {at}. Different programs will see different content."
                ),
                severity=Severity.MEDIUM,
                location=Location(offset=at),
                evidence=data[at : at + 16].decode("latin-1"),
                references=REFERENCES,
            )
            for at, kind in found
        ]
        children = [
            ExtractedFile(name=f"polyglot-{at}.{kind}", data=data[at:]) for at, kind in found
        ]
        return AnalyzerResult(findings=findings, children=children)
