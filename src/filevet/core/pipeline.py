import hashlib
import json
import logging
import tempfile
import time
from collections import deque
from collections.abc import Sequence
from pathlib import Path
from uuid import uuid4

from filevet.core.analyzer import (
    AnalysisContext,
    Analyzer,
    AnalyzerResult,
    Expected,
    ExtractedFile,
    load_analyzers,
)
from filevet.core.artifact import Artifact
from filevet.core.errors import ScanError
from filevet.core.extract_text import runs, visible
from filevet.core.finding import Finding, Severity
from filevet.core.identify import SNIFF_BYTES, declared_type, detect_type
from filevet.core.limits import DEFAULT_LIMITS, Limits
from filevet.core.report import AnalyzerRun, Report, Status
from filevet.core.sandbox import Sandbox, get_sandbox
from filevet.policies import Policy, Suppression

log = logging.getLogger("filevet")


def scan(
    source: str | Path | bytes,
    limits: Limits = DEFAULT_LIMITS,
    analyzers: Sequence[Analyzer] | None = None,
    *,
    expected: Expected | None = None,
    mask: bool = True,
    policy: Policy | None = None,
    suppressions: Sequence[Suppression] = (),
    name: str = "",
    sandbox: Sandbox | None = None,
) -> Report:
    sandbox = sandbox or get_sandbox()
    if analyzers is None:
        analyzers = load_analyzers()
    data, name = _read(source, limits, name)
    ctx = AnalysisContext(limits=limits, expected=expected or Expected(), mask=mask)
    artifacts: list[Artifact] = []
    findings: list[Finding] = []
    runs: list[AnalyzerRun] = []
    reached: set[str] = set()
    expanded = 0
    with tempfile.TemporaryDirectory(prefix="filevet-") as tmp:
        pending = deque([_ingest(Path(tmp), name, data, None)])
        del data
        while pending:
            artifact = pending.popleft()
            artifacts.append(artifact)
            for analyzer in analyzers:
                run, result = _run(sandbox, analyzer, artifact, ctx)
                if run is None:
                    continue
                runs.append(run)
                stamp = {"artifact_id": artifact.id, "analyzer": f"{analyzer.name}/{run.version}"}
                findings += [f.model_copy(update=stamp) for f in result.findings]
                if run.error:
                    findings.append(_error_finding(artifact, run))
                for child in result.children:
                    children = len(artifacts) + len(pending) - 1
                    limit = _limit_reached(limits, artifact, children, expanded + len(child.data))
                    if limit:
                        if limit not in reached:
                            reached.add(limit)
                            findings.append(_limit_finding(artifact, limit, limits))
                        break
                    expanded += len(child.data)
                    pending.append(_ingest(Path(tmp), child.name, child.data, artifact))
    return (policy or Policy.load("default")).apply(artifacts, findings, runs, suppressions)


def extract_text(
    source: str | Path | bytes,
    limits: Limits = DEFAULT_LIMITS,
    *,
    visible_only: bool = False,
    sandbox: Sandbox | None = None,
) -> str:
    result = _task(_TextExtractor(visible_only), "text extraction", source, limits, sandbox)
    return result.children[0].data.decode()


def sanitize(
    source: str | Path | bytes, limits: Limits = DEFAULT_LIMITS, *, sandbox: Sandbox | None = None
) -> tuple[bytes, list[Finding]]:
    from filevet.sanitize import Sanitizer

    result = _task(Sanitizer(), "sanitizing", source, limits, sandbox)
    return result.children[0].data, result.findings


def _task(
    task: Analyzer,
    what: str,
    source: str | Path | bytes,
    limits: Limits,
    sandbox: Sandbox | None,
) -> AnalyzerResult:
    data, name = _read(source, limits, "")
    with tempfile.TemporaryDirectory(prefix="filevet-") as tmp:
        artifact = _ingest(Path(tmp), name, data, None)
        if not task.supports(artifact):
            raise ScanError(f"{what} is not supported for {artifact.detected_type} files")
        status, result, error = (sandbox or get_sandbox()).run(
            task, artifact, AnalysisContext(limits=limits)
        )
    if status != "ok" or not result.children:
        raise ScanError(f"{what} failed: {status} {error or ''}".strip())
    return result


class _TextExtractor:
    name = "pipeline.extract_text"
    version = "0.1.0"

    def __init__(self, visible_only: bool) -> None:
        self.visible_only = visible_only

    def supports(self, artifact: Artifact) -> bool:
        return True

    def analyze(self, artifact: Artifact, ctx: AnalysisContext) -> AnalyzerResult:
        data = artifact.read(ctx.limits.max_input_bytes)
        found = runs(data, artifact.detected_type, ctx.limits.max_total_expanded_bytes)
        text = visible(found) if self.visible_only else "\n".join(r.text for r in found)
        return AnalyzerResult(children=[ExtractedFile(name="text", data=text.encode())])


def _read(source: str | Path | bytes, limits: Limits, name: str) -> tuple[bytes, str]:
    if isinstance(source, bytes):
        data = source
    else:
        path = Path(source)
        with path.open("rb") as f:
            data = f.read(limits.max_input_bytes + 1)
        name = path.name
    if len(data) > limits.max_input_bytes:
        raise ScanError(f"input is larger than the {limits.max_input_bytes} byte limit")
    return data, name


def _ingest(tmp: Path, name: str, data: bytes, parent: Artifact | None) -> Artifact:
    artifact_id = uuid4()
    path = tmp / artifact_id.hex
    path.touch(mode=0o600, exist_ok=False)
    path.write_bytes(data)
    path.chmod(0o400)
    return Artifact(
        id=artifact_id,
        name=name,
        size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        md5=hashlib.md5(data, usedforsecurity=False).hexdigest(),
        declared_type=declared_type(name),
        detected_type=detect_type(data[:SNIFF_BYTES]),
        depth=parent.depth + 1 if parent else 0,
        parent_id=parent.id if parent else None,
        path=path,
    )


def _limit_reached(limits: Limits, parent: Artifact, children: int, expanded: int) -> str | None:
    if parent.depth >= limits.max_depth:
        return "max_depth"
    if children >= limits.max_children:
        return "max_children"
    if expanded > limits.max_total_expanded_bytes:
        return "max_total_expanded_bytes"
    return None


def _run(
    sandbox: Sandbox, analyzer: Analyzer, artifact: Artifact, ctx: AnalysisContext
) -> tuple[AnalyzerRun | None, AnalyzerResult]:
    started = time.monotonic()
    outcome: tuple[Status, AnalyzerResult, str | None]
    try:
        supported = analyzer.supports(artifact)
    except Exception as exc:
        outcome = "error", AnalyzerResult(), f"supports() raised {type(exc).__name__}"
    else:
        if not supported:
            return None, AnalyzerResult()
        outcome = sandbox.run(analyzer, artifact, ctx)
    status, result, error = outcome
    run = AnalyzerRun(
        analyzer=analyzer.name,
        version=analyzer.version,
        artifact_id=artifact.id,
        status=status,
        duration_ms=round((time.monotonic() - started) * 1000, 3),
        error=error,
    )
    if log.isEnabledFor(logging.INFO):
        log.info(
            json.dumps(
                {
                    "event": "analyzer_run",
                    "sha256": artifact.sha256,
                    "analyzer": run.analyzer,
                    "status": run.status,
                    "duration_ms": run.duration_ms,
                    "rule_ids": sorted({f.rule_id for f in result.findings}),
                }
            )
        )
    return run, result


def _error_finding(artifact: Artifact, run: AnalyzerRun) -> Finding:
    return Finding(
        rule_id="pipeline.analyzer_error",
        title=f"Analyzer {run.analyzer} did not finish",
        description=f"{run.analyzer} {run.status}: {run.error}. Its checks did not run.",
        severity=Severity.HIGH,
        artifact_id=artifact.id,
        analyzer="pipeline",
    )


def _limit_finding(artifact: Artifact, limit: str, limits: Limits) -> Finding:
    return Finding(
        rule_id="pipeline.limit_exceeded",
        title=f"Scan stopped at the {limit} limit",
        description=f"Extracted content past {limit}={getattr(limits, limit)} was not scanned.",
        severity=Severity.HIGH,
        artifact_id=artifact.id,
        analyzer="pipeline",
    )
