from collections.abc import Callable
from pathlib import Path

import pytest
import yaml

from filevet.core.analyzer import Expected
from filevet.core.finding import Severity
from filevet.core.pipeline import scan
from tests.corpus import generators

CASES = sorted(Path(__file__).with_name("cases").glob("*/expected.yaml"))
MESSAGES = [
    "camt.052.001.08",
    "camt.053.001.08",
    "camt.054.001.08",
    "pain.001.001.09",
    "pain.008.001.08",
    "pacs.008.001.08",
]


@pytest.mark.parametrize("path", CASES, ids=[p.parent.name for p in CASES])
def test_corpus_case(
    path: Path,
    sample_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    record_property: Callable[[str, object], None],
) -> None:
    case = yaml.safe_load(path.read_text())
    for message in MESSAGES:
        generators.iso20022_xsd(sample_dir, message=message)
    monkeypatch.setenv("FILEVET_XSD_DIR", str(sample_dir))
    monkeypatch.delenv("FILEVET_CLAMD", raising=False)
    sample = getattr(generators, case["generator"])(sample_dir, **case["args"])
    report = scan(sample, expected=Expected.model_validate(case.get("context", {})))
    found = {f.rule_id for f in report.findings}
    flagged = {f.rule_id for f in report.findings if f.severity != Severity.INFO}
    top = max((f.severity for f in report.findings), key=lambda s: s.rank, default=Severity.INFO)
    record_property(
        "corpus",
        {"found": sorted(found), "flagged": sorted(flagged), "expected": case["must_find"]},
    )

    assert set(case["must_find"]) <= found
    assert not set(case.get("must_not_find", [])) & found
    ceiling = Severity(case.get("max_severity", "critical" if case["must_find"] else "medium"))
    assert top.rank <= ceiling.rank, [(f.rule_id, f.severity, f.title) for f in report.findings]


def test_corpus_size() -> None:
    cases = [yaml.safe_load(p.read_text()) for p in CASES]
    assert sum(bool(c["must_find"]) for c in cases) >= 40
    assert sum(not c["must_find"] for c in cases) >= 40
