import hashlib
from pathlib import Path

from filevet import __version__
from filevet.core.report import SEVERITIES, scan


def test_scan_reports_artifact_and_empty_findings(benign_pdf: Path) -> None:
    report = scan(benign_pdf)

    assert report["filevet_version"] == __version__
    assert report["artifact"] == {
        "name": "benign.pdf",
        "size": benign_pdf.stat().st_size,
        "sha256": hashlib.sha256(benign_pdf.read_bytes()).hexdigest(),
    }
    assert report["findings"] == []
    assert report["summary"] == dict.fromkeys(SEVERITIES, 0)
