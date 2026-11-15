from collections.abc import Sequence
from datetime import date
from fnmatch import fnmatchcase
from functools import cache
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

from filevet.core.artifact import Artifact
from filevet.core.finding import Finding, Severity
from filevet.core.report import AnalyzerRun, Decision, Report, Verdict

Action = Literal["allow", "pass_with_findings", "review", "block"]
BUILT_IN = ("default", "strict", "ai-ingestion")
MAX_FILE_BYTES = 1 << 20
RANK = {"allow": 0, "pass_with_findings": 1, "review": 2, "block": 3}
VERDICT: dict[str, Verdict] = {
    "allow": "pass",
    "pass_with_findings": "pass_with_findings",
    "review": "review",
    "block": "block",
}


class _Strict(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Match(_Strict):
    rule_id: str | list[str] | None = Field(default=None, description="Rule ID glob or a list")
    severity: Severity | list[Severity] | None = None
    evidence_contains: str | None = None

    def hits(self, finding: Finding) -> bool:
        ids = [self.rule_id] if isinstance(self.rule_id, str) else self.rule_id
        severities = [self.severity] if isinstance(self.severity, Severity) else self.severity
        return (
            (ids is None or any(fnmatchcase(finding.rule_id, i) for i in ids))
            and (severities is None or finding.severity in severities)
            and (self.evidence_contains is None or self.evidence_contains in finding.evidence)
        )


class When(_Strict):
    min_count: int = Field(default=1, ge=1, description="Apply only when this many findings match")


class Rule(_Strict):
    match: Match
    action: Action
    when: When = When()


class Override(_Strict):
    match: Match
    severity: Severity


class Suppression(_Strict):
    rule_id: str
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reason: str = Field(min_length=1)
    expires: date


class Suppressions(_Strict):
    suppressions: list[Suppression] = []


class Policy(_Strict):
    policy_version: Literal[1]
    name: str
    rules: list[Rule] = []
    overrides: list[Override] = []
    default_action: Action = "pass_with_findings"

    @classmethod
    def load(cls, name: str | Path) -> "Policy":
        if str(name) in BUILT_IN:
            return _built_in(str(name))
        return cls.model_validate(_yaml(Path(name)))

    def apply(
        self,
        artifacts: list[Artifact],
        findings: list[Finding],
        runs: list[AnalyzerRun],
        suppressions: Sequence[Suppression] = (),
        today: date | None = None,
    ) -> Report:
        today = today or date.today()
        findings = [self._override(f) for f in findings]
        hashes = {a.id: a.sha256 for a in artifacts}
        active = [s for s in suppressions if s.expires >= today]
        warnings = [
            f"suppression of {s.rule_id} for {s.sha256[:12]} expired on {s.expires}"
            for s in suppressions
            if s.expires < today
        ]
        kept: list[Finding] = []
        suppressed: list[Finding] = []
        for f in findings:
            sha = hashes.get(f.artifact_id) if f.artifact_id else None
            hit = any(s.rule_id == f.rule_id and s.sha256 == sha for s in active)
            (suppressed if hit else kept).append(f)
        return Report(
            artifacts=artifacts,
            findings=kept,
            suppressed=suppressed,
            analyzer_runs=runs,
            warnings=warnings,
            decision=self._decide(kept),
        )

    def _override(self, finding: Finding) -> Finding:
        override = next((o for o in self.overrides if o.match.hits(finding)), None)
        return finding.model_copy(update={"severity": override.severity}) if override else finding

    def _decide(self, findings: list[Finding]) -> Decision:
        if not findings:
            return Decision(
                policy=self.name, verdict="pass", rule=None, rule_ids=[], reason="no findings"
            )
        counts = [sum(r.match.hits(f) for f in findings) for r in self.rules]
        chosen: list[tuple[int | None, Action]] = []
        for f in findings:
            index = next(
                (
                    i
                    for i, r in enumerate(self.rules)
                    if r.match.hits(f) and counts[i] >= r.when.min_count
                ),
                None,
            )
            chosen.append(
                (index, self.rules[index].action if index is not None else self.default_action)
            )
        top = max(RANK[action] for _, action in chosen)
        index, action = next(c for c in chosen if RANK[c[1]] == top)
        rule_ids = sorted(
            {f.rule_id for f, c in zip(findings, chosen, strict=True) if c == (index, action)}
        )
        where = f"rule {index}" if index is not None else "default_action"
        return Decision(
            policy=self.name,
            verdict=VERDICT[action],
            rule=index,
            rule_ids=rule_ids,
            reason=f"{where} of policy {self.name} sets {action} for {', '.join(rule_ids)}",
        )


def load_suppressions(path: Path) -> list[Suppression]:
    return Suppressions.model_validate(_yaml(path) or {}).suppressions


@cache
def _built_in(name: str) -> Policy:
    return Policy.model_validate(_yaml(Path(__file__).with_name(f"{name}.yaml")))


def _yaml(path: Path) -> object:
    with path.open("rb") as f:
        data = f.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise ValueError(f"{path.name} is larger than {MAX_FILE_BYTES} bytes")
    return yaml.safe_load(data)
