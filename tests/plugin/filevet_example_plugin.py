from filevet.core.analyzer import AnalysisContext, AnalyzerResult
from filevet.core.artifact import Artifact
from filevet.core.finding import Finding, Severity


class SeenText:
    name = "example.seen_text"
    version = "0.1.0"

    def supports(self, artifact: Artifact) -> bool:
        return artifact.detected_type == "text"

    def analyze(self, artifact: Artifact, ctx: AnalysisContext) -> AnalyzerResult:
        finding = Finding(rule_id="example.seen_text", title="Seen", severity=Severity.INFO)
        return AnalyzerResult(findings=[finding])
