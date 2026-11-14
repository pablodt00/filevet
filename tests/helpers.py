import hashlib
from pathlib import Path

from filevet.core.analyzer import AnalysisContext, Analyzer, AnalyzerResult
from filevet.core.artifact import Artifact
from filevet.core.finding import Severity
from filevet.core.identify import SNIFF_BYTES, declared_type, detect_type
from filevet.core.limits import DEFAULT_LIMITS, Limits


def artifact(path: Path, *, depth: int = 0, name: str | None = None) -> Artifact:
    data = path.read_bytes()
    name = name or path.name
    return Artifact(
        name=name,
        size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        md5="",
        declared_type=declared_type(name),
        detected_type=detect_type(data[:SNIFF_BYTES]),
        depth=depth,
        path=path,
    )


def run(
    analyzer: Analyzer, path: Path, *, depth: int = 0, limits: Limits = DEFAULT_LIMITS
) -> AnalyzerResult:
    return analyzer.analyze(artifact(path, depth=depth), AnalysisContext(limits=limits))


def rules(result: AnalyzerResult) -> dict[str, Severity]:
    top: dict[str, Severity] = {}
    for f in result.findings:
        if f.rule_id not in top or f.severity.rank > top[f.rule_id].rank:
            top[f.rule_id] = f.severity
    return top
