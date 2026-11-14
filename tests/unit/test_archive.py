import hashlib
import io
import zipfile
from pathlib import Path

import pytest

from filevet.analyzers.parser.archive import Archive
from filevet.core.analyzer import AnalysisContext
from filevet.core.limits import DEFAULT_LIMITS, Limits
from tests.corpus import generators
from tests.helpers import artifact, rules, run


def test_benign_archive_extracts_entries(sample_dir: Path) -> None:
    path = generators.zip_entries(
        sample_dir, entries={"statement.csv": ["csv"], "docs/invoice.pdf": ["pdf"]}
    )
    result = run(Archive(), path)
    assert rules(result) == {}
    assert sorted(c.name for c in result.children) == ["docs/invoice.pdf", "statement.csv"]


def test_high_ratio_entry_is_a_bomb_and_not_extracted(sample_dir: Path) -> None:
    result = run(Archive(), generators.nested_zip(sample_dir, inner_size=4 << 20))
    assert rules(result) == {"parser.archive_bomb": "high"}
    assert result.children == []


def test_small_compressible_entry_is_fine(sample_dir: Path) -> None:
    result = run(Archive(), generators.nested_zip(sample_dir, inner_size=100_000))
    assert rules(result) == {}


def test_entry_over_input_limit_is_skipped(sample_dir: Path) -> None:
    path = generators.zip_entries(sample_dir, entries={"a.csv": ["csv"] * 50})
    result = run(Archive(), path, limits=Limits(max_input_bytes=100))
    assert rules(result) == {"parser.archive_bomb": "high"}


def test_too_many_entries(sample_dir: Path) -> None:
    path = generators.zip_entries(sample_dir, entries={"s.csv": ["csv"]}, copies=6)
    result = run(Archive(), path, limits=Limits(max_children=5))
    assert rules(result) == {"parser.archive_bomb": "high"}
    assert len(result.children) == 5


def test_overlapping_entries(sample_dir: Path) -> None:
    path = generators.zip_entries(sample_dir, entries={"s.csv": ["csv"]}, overlap=True)
    assert rules(run(Archive(), path))["parser.archive_bomb"] == "critical"


def test_nested_archive_past_depth(sample_dir: Path) -> None:
    path = generators.nested_zip(sample_dir, depth=2)
    assert rules(run(Archive(), path, depth=1)) == {}
    assert rules(run(Archive(), path, depth=2)) == {"parser.archive_bomb": "high"}


def test_quine(sample_dir: Path) -> None:
    path = generators.zip_entries(sample_dir, entries={"self.zip": ["csv"]})
    entry = hashlib.sha256(b"date,amount\n2026-01-02,10.00\n").hexdigest()
    copy = artifact(path).model_copy(update={"sha256": entry})
    result = Archive().analyze(copy, AnalysisContext(limits=DEFAULT_LIMITS))
    assert rules(result) == {"parser.archive_bomb": "critical"}


@pytest.mark.parametrize(
    "name", ["../../etc/cron.d/x", "a/../../x", "/etc/x.csv", "\\windows\\x", "C:/x.csv"]
)
def test_path_traversal(name: str, sample_dir: Path) -> None:
    path = generators.zip_entries(sample_dir, entries={name: ["csv"]})
    result = run(Archive(), path)
    assert rules(result) == {"parser.path_traversal": "high"}
    assert result.findings[0].location.archive_path == name  # type: ignore[union-attr]


def test_symlink_is_flagged_and_not_extracted(sample_dir: Path) -> None:
    path = generators.zip_entries(
        sample_dir, entries={"a.csv": ["csv"]}, symlinks={"b.csv": "/etc/passwd"}
    )
    result = run(Archive(), path)
    assert rules(result) == {"parser.path_traversal": "high"}
    assert [c.name for c in result.children] == ["a.csv"]


def test_dotted_names_are_not_traversal(sample_dir: Path) -> None:
    path = generators.zip_entries(sample_dir, entries={"v1..2/notes..txt": ["csv"]})
    assert rules(run(Archive(), path)) == {}


def test_broken_zip_is_malformed(sample_dir: Path) -> None:
    path = generators.disguised(sample_dir, name="a.zip", parts=["zip_broken"])
    assert rules(run(Archive(), path)) == {"parser.malformed": "medium"}


def test_corrupt_entry_is_malformed(sample_dir: Path) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("a.csv", "x" * 1000)
    data = bytearray(buf.getvalue())
    data[40:44] = b"\xff\xff\xff\xff"
    path = sample_dir / "corrupt.zip"
    path.write_bytes(bytes(data))
    result = run(Archive(), path)
    assert rules(result) == {"parser.malformed": "medium"}
    assert result.children == []
