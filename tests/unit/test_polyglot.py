from pathlib import Path

import pytest

from filevet.analyzers.parser.polyglot import Polyglot
from tests.corpus import generators
from tests.helpers import rules, run


@pytest.mark.parametrize(
    ("parts", "child"),
    [
        (["pdf", "zip"], "zip"),
        (["jpeg", "zip"], "zip"),
        (["html", "pdf"], "pdf"),
        (["png", "rar_stub"], "rar"),
        (["zip", "pdf"], "pdf"),
    ],
)
def test_polyglots(parts: list[str], child: str, sample_dir: Path) -> None:
    result = run(Polyglot(), generators.disguised(sample_dir, name="f", parts=parts))
    assert rules(result) == {"parser.polyglot": "medium"}
    assert [c.name.rsplit(".", 1)[1] for c in result.children] == [child]


@pytest.mark.parametrize("parts", [["pdf"], ["zip"], ["jpeg"], ["csv"]])
def test_single_formats_are_quiet(parts: list[str], sample_dir: Path) -> None:
    assert rules(run(Polyglot(), generators.disguised(sample_dir, name="f", parts=parts))) == {}


def test_zip_signature_without_directory_is_quiet(sample_dir: Path) -> None:
    path = sample_dir / "noise.jpg"
    path.write_bytes(b"\xff\xd8\xff\xe0" + b"PK\x03\x04" + bytes(32))
    assert rules(run(Polyglot(), path)) == {}
