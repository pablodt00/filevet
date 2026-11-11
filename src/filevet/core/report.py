from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, computed_field

from filevet import __version__
from filevet.core.artifact import Artifact
from filevet.core.finding import Finding, Severity

Verdict = Literal["pass", "review", "block"]
Status = Literal["ok", "error", "timeout"]


class AnalyzerRun(BaseModel):
    model_config = ConfigDict(frozen=True)

    analyzer: str
    version: str
    artifact_id: UUID
    status: Status
    duration_ms: float
    error: str | None = None


class Report(BaseModel):
    model_config = ConfigDict(frozen=True)

    filevet_version: str = __version__
    artifacts: list[Artifact]
    findings: list[Finding]
    analyzer_runs: list[AnalyzerRun]

    @computed_field  # type: ignore[prop-decorator]
    @property
    def summary(self) -> dict[Severity, int]:
        counts = dict.fromkeys(reversed(Severity), 0)
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts

    @computed_field  # type: ignore[prop-decorator]
    @property
    def verdict(self) -> Verdict:
        top = max((f.severity.rank for f in self.findings), default=-1)
        if top >= Severity.HIGH.rank:
            return "block"
        return "review" if top == Severity.MEDIUM.rank else "pass"
