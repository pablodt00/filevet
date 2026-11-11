from filevet.core.analyzer import AnalysisContext, AnalyzerResult
from filevet.core.artifact import Artifact
from filevet.core.finding import Finding, Severity
from filevet.core.identify import EXECUTABLE, fits

CWE_434 = "https://cwe.mitre.org/data/definitions/434.html"


class TypeMismatch:
    name = "basic.type_mismatch"
    version = "0.1.0"

    def supports(self, artifact: Artifact) -> bool:
        return True

    def analyze(self, artifact: Artifact, ctx: AnalysisContext) -> AnalyzerResult:
        declared, detected = artifact.declared_type, artifact.detected_type
        findings = []
        if declared and not fits(declared, detected):
            disguised = detected in EXECUTABLE and declared not in EXECUTABLE
            findings.append(
                Finding(
                    rule_id="basic.type_mismatch",
                    title="File content does not match its extension",
                    description=f"The name says {declared} but the content is {detected}.",
                    severity=Severity.CRITICAL if disguised else Severity.MEDIUM,
                    evidence=artifact.name,
                    references=[CWE_434],
                )
            )
        kind = detected if detected in EXECUTABLE else declared
        if kind in EXECUTABLE:
            findings.append(
                Finding(
                    rule_id="basic.executable",
                    title="Executable or script",
                    description=f"The file is a {kind} that runs code when opened.",
                    severity=Severity.HIGH,
                    evidence=artifact.name,
                    references=[CWE_434],
                )
            )
        return AnalyzerResult(findings=findings)
