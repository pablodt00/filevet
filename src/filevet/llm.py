from importlib.metadata import entry_points
from typing import Protocol

from filevet.core.finding import Finding
from filevet.core.report import Report


class Verifier(Protocol):
    def confidence(self, finding: Finding) -> float: ...


def load_verifier(name: str) -> Verifier:
    found = entry_points(group="filevet.llm_verifiers", name=name)
    if not found:
        raise LookupError(f"no LLM verifier named {name} is installed")
    verifier: Verifier = next(iter(found)).load()()
    return verifier


def second_opinion(report: Report, verifier: Verifier) -> Report:
    findings = [_raise(f, verifier) if f.rule_id.startswith("ai.") else f for f in report.findings]
    return report.model_copy(update={"findings": findings})


def _raise(finding: Finding, verifier: Verifier) -> Finding:
    try:
        opinion = min(1.0, float(verifier.confidence(finding)))
    except Exception:
        return finding
    return finding.model_copy(update={"confidence": max(finding.confidence, opinion)})
