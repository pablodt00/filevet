import hashlib
import json
import logging
import multiprocessing
import resource
import tempfile
import time
from collections import deque
from collections.abc import Sequence
from multiprocessing.connection import Connection
from pathlib import Path
from uuid import uuid4

from pydantic import ValidationError

from filevet.core.analyzer import AnalysisContext, Analyzer, AnalyzerResult, load_analyzers
from filevet.core.artifact import Artifact
from filevet.core.errors import ScanError
from filevet.core.finding import Finding, Severity
from filevet.core.identify import SNIFF_BYTES, declared_type, detect_type
from filevet.core.limits import DEFAULT_LIMITS, Limits
from filevet.core.report import AnalyzerRun, Report, Status

log = logging.getLogger("filevet")
_mp = multiprocessing.get_context("fork")


def scan(
    source: Path | bytes,
    limits: Limits = DEFAULT_LIMITS,
    analyzers: Sequence[Analyzer] | None = None,
) -> Report:
    if analyzers is None:
        analyzers = load_analyzers()
    if isinstance(source, Path):
        with source.open("rb") as f:
            data = f.read(limits.max_input_bytes + 1)
        name = source.name
    else:
        data, name = source, ""
    if len(data) > limits.max_input_bytes:
        raise ScanError(f"input is larger than the {limits.max_input_bytes} byte limit")

    ctx = AnalysisContext(limits=limits)
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
                run, result = _run(analyzer, artifact, ctx)
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
    return Report(artifacts=artifacts, findings=findings, analyzer_runs=runs)


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
    analyzer: Analyzer, artifact: Artifact, ctx: AnalysisContext
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
        outcome = _isolated(analyzer, artifact, ctx)
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


def _isolated(
    analyzer: Analyzer, artifact: Artifact, ctx: AnalysisContext
) -> tuple[Status, AnalyzerResult, str | None]:
    receiver, sender = _mp.Pipe(duplex=False)
    worker = _mp.Process(target=_worker, args=(analyzer, artifact, ctx, sender))
    worker.start()
    sender.close()
    try:
        if not receiver.poll(ctx.limits.timeout_s):
            return "timeout", AnalyzerResult(), f"no result after {ctx.limits.timeout_s:g} s"
        payload = receiver.recv_bytes(2 * ctx.limits.max_total_expanded_bytes + (1 << 20))
    except EOFError:
        worker.join(ctx.limits.timeout_s)
        return "error", AnalyzerResult(), f"worker exited with code {worker.exitcode}"
    except OSError:
        return "error", AnalyzerResult(), "result too large"
    finally:
        worker.kill()
        worker.join()
        receiver.close()
    if payload.startswith(b"!"):
        return "error", AnalyzerResult(), f"raised {payload[1:].decode('ascii', 'replace')}"
    try:
        return "ok", AnalyzerResult.model_validate_json(payload), None
    except ValidationError:
        return "error", AnalyzerResult(), "returned an invalid result"


def _worker(analyzer: Analyzer, artifact: Artifact, ctx: AnalysisContext, conn: Connection) -> None:
    memory = ctx.limits.memory_bytes
    resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
    try:
        result = analyzer.analyze(artifact, ctx)
        payload = AnalyzerResult.model_validate(result).model_dump_json().encode()
    except Exception as exc:
        payload = b"!" + type(exc).__name__.encode("ascii", "replace")
    conn.send_bytes(payload)


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
