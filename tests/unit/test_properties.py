import json
import resource
import time
from pathlib import Path

import jsonschema
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from filevet.core.analyzer import load_analyzers
from filevet.core.limits import Limits
from filevet.core.pipeline import scan

SCHEMA = json.loads(
    (Path(__file__).resolve().parents[2] / "docs" / "schema" / "report.schema.json").read_text()
)
LIMITS = Limits(timeout_s=5, memory_bytes=768 << 20, max_total_expanded_bytes=16 << 20)
ANALYZERS = [a for a in load_analyzers() if a.name != "malware.clamav"]
HEADS = [b"", b"%PDF-1.7\n", b"PK\x03\x04", b"<?xml version='1.0'?><Document>", b"date,amount\n"]
HEADS.append(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")


@settings(deadline=None, max_examples=30, suppress_health_check=[HealthCheck.too_slow])
@given(st.sampled_from(HEADS), st.binary(max_size=4096))
def test_any_file_gives_a_schema_valid_report_within_the_limits(head: bytes, body: bytes) -> None:
    started = time.monotonic()
    report = scan(head + body, LIMITS, ANALYZERS)
    elapsed = time.monotonic() - started

    jsonschema.validate(json.loads(report.model_dump_json()), SCHEMA)
    assert all(run.duration_ms <= LIMITS.timeout_s * 1000 + 1000 for run in report.analyzer_runs)
    assert elapsed <= len(report.analyzer_runs) * (LIMITS.timeout_s + 1) + 5
    peak = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss * 1024
    assert peak <= max(LIMITS.memory_bytes, 1 << 30)
