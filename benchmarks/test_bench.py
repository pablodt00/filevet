import shutil
import tempfile
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from pytest_benchmark.fixture import BenchmarkFixture

from filevet.core.analyzer import load_analyzers
from filevet.core.pipeline import scan
from tests.corpus import generators

ROOT = Path(__file__).resolve().parents[1] / "tmp-samples"
ANALYZERS = [a for a in load_analyzers() if a.name != "malware.clamav"]
SAMPLES: dict[str, Callable[[Path], Path]] = {
    "csv-1k": lambda out: generators.bank_statement_csv(out, rows=1_000),
    "csv-50k": lambda out: generators.bank_statement_csv(out, rows=50_000, name="big.csv"),
    "camt053-1k": lambda out: generators.camt053(out, entries=1_000),
    "pdf": lambda out: generators.pdf(out, javascript="app.alert(1)"),
    "pdf-updates": lambda out: generators.pdf(out, name="u.pdf", updates=["v2"] * 20),
    "xlsx-5k": lambda out: generators.xlsx(
        out, cells=[["2026-01-02", f"Invoice {i}", "10.00"] for i in range(5_000)]
    ),
    "zip-nested": lambda out: generators.nested_zip(out, depth=4, inner_size=1 << 20),
}


@pytest.fixture(scope="module")
def samples() -> Iterator[dict[str, Path]]:
    ROOT.mkdir(exist_ok=True)
    out = Path(tempfile.mkdtemp(dir=ROOT))
    yield {name: make(out) for name, make in SAMPLES.items()}
    shutil.rmtree(out)


@pytest.mark.parametrize("sample", SAMPLES)
def test_scan(benchmark: BenchmarkFixture, samples: dict[str, Path], sample: str) -> None:
    path = samples[sample]
    benchmark.extra_info["bytes"] = path.stat().st_size
    report = benchmark.pedantic(scan, args=(path,), kwargs={"analyzers": ANALYZERS}, rounds=5)
    assert all(run.status == "ok" for run in report.analyzer_runs)
