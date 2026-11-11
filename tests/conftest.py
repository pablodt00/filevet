import os
from pathlib import Path

import pytest

MINIMAL_PDF = b"%PDF-1.4\n%%EOF\n"


@pytest.fixture
def benign_pdf(tmp_path: Path) -> Path:
    path = tmp_path / "benign.pdf"
    path.write_bytes(MINIMAL_PDF)
    return path


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    if os.environ.get("FILEVET_CLAMD"):
        return
    skip = pytest.mark.skip(reason="set FILEVET_CLAMD to the address of a running clamd")
    for item in items:
        if "requires_clamav" in item.keywords:
            item.add_marker(skip)
