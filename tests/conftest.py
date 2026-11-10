from pathlib import Path

import pytest

MINIMAL_PDF = b"%PDF-1.4\n%%EOF\n"


@pytest.fixture
def benign_pdf(tmp_path: Path) -> Path:
    path = tmp_path / "benign.pdf"
    path.write_bytes(MINIMAL_PDF)
    return path
