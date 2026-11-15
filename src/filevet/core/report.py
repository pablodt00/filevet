from importlib.metadata import version
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, computed_field

from filevet.core.artifact import Artifact
from filevet.core.finding import Finding, Severity

Verdict = Literal["pass", "pass_with_findings", "review", "block"]
Status = Literal["ok", "error", "timeout"]


class AnalyzerRun(BaseModel):
    model_config = ConfigDict(frozen=True)

    analyzer: str
    version: str
    artifact_id: UUID
    status: Status
    duration_ms: float
    error: str | None = None


class Decision(BaseModel):
    model_config = ConfigDict(frozen=True)

    policy: str
    verdict: Verdict
    rule: int | None = Field(description="Index of the policy rule that set the verdict")
    rule_ids: list[str] = Field(description="Rule IDs of the findings that set the verdict")
    reason: str


class Report(BaseModel):
    model_config = ConfigDict(frozen=True)

    schema_version: Literal[2] = 2
    filevet_version: str = Field(default_factory=lambda: version("filevet"))
    artifacts: list[Artifact]
    findings: list[Finding]
    suppressed: list[Finding] = []
    analyzer_runs: list[AnalyzerRun]
    warnings: list[str] = []
    decision: Decision

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
        return self.decision.verdict
