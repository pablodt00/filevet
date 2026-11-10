import json
from pathlib import Path

import pytest

from filevet import __version__
from filevet.cli import main


def test_scan_prints_json_report(benign_pdf: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scan", str(benign_pdf)]) == 0

    report = json.loads(capsys.readouterr().out)
    assert report["artifact"]["name"] == "benign.pdf"


def test_scan_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["scan", str(tmp_path / "missing.pdf")])
    assert exc.value.code == 2


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == f"filevet {__version__}"
