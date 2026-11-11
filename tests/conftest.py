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
