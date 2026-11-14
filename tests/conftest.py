import os
import shutil
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

MINIMAL_PDF = b"%PDF-1.4\n%%EOF\n"
SAMPLES_ROOT = Path(__file__).resolve().parents[1] / "tmp-samples"


@pytest.fixture
def benign_pdf(tmp_path: Path) -> Path:
    path = tmp_path / "benign.pdf"
    path.write_bytes(MINIMAL_PDF)
    return path


@pytest.fixture
def sample_dir() -> Iterator[Path]:
    SAMPLES_ROOT.mkdir(exist_ok=True)
    path = Path(tempfile.mkdtemp(dir=SAMPLES_ROOT))
    yield path
    shutil.rmtree(path)


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    if os.environ.get("FILEVET_CLAMD"):
        return
    skip = pytest.mark.skip(reason="set FILEVET_CLAMD to the address of a running clamd")
    for item in items:
        if "requires_clamav" in item.keywords:
            item.add_marker(skip)


def pytest_terminal_summary(terminalreporter: pytest.TerminalReporter) -> None:
    rows = []
    for outcome in ("passed", "failed"):
        for report in terminalreporter.stats.get(outcome, []):
            props = dict(getattr(report, "user_properties", []))
            if report.when == "call" and "corpus" in props:
                rows.append((report.nodeid.rsplit("[", 1)[-1].rstrip("]"), props["corpus"]))
    if not rows:
        return
    rules = sorted({r for _, p in rows for r in p["found"] + p["expected"]})
    width = max(len(case) for case, _ in rows)
    write = terminalreporter.write_line
    terminalreporter.section("detection matrix")
    write("+ expected and found, - expected but missing, o found but not expected")
    for i, rule in enumerate(rules, 1):
        write(f"{i:>4}  {rule}")
    write(" " * width + "  " + " ".join(f"{i:>2}" for i in range(1, len(rules) + 1)))
    for case, props in sorted(rows):
        marks = []
        for rule in rules:
            found, expected = rule in props["found"], rule in props["expected"]
            marks.append("+" if found and expected else "-" if expected else "o" if found else ".")
        write(f"{case:<{width}}  " + " ".join(f"{m:>2}" for m in marks))
