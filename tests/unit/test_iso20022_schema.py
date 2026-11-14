from pathlib import Path

import pytest

from filevet.analyzers.format.iso20022_schema import MAX_ERRORS, Iso20022Schema
from tests.corpus import generators
from tests.helpers import rules, run


@pytest.fixture
def xsd_dir(sample_dir: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    for message in ("camt.053.001.08", "pain.001.001.09"):
        generators.iso20022_xsd(sample_dir, message=message)
    monkeypatch.setenv("FILEVET_XSD_DIR", str(sample_dir))
    return sample_dir


@pytest.mark.parametrize("message", ["camt.053.001.08", "pain.001.001.09"])
def test_valid_message(message: str, xsd_dir: Path) -> None:
    path = generators.camt053(xsd_dir, message=message, entries=3)
    assert rules(run(Iso20022Schema(), path)) == {}


@pytest.mark.parametrize(("field", "value"), [("msg_id", "M" * 36), ("created", "yesterday")])
def test_violation_is_low(field: str, value: str, xsd_dir: Path) -> None:
    result = run(Iso20022Schema(), generators.camt053(xsd_dir, **{field: value}))
    assert rules(result) == {"format.iso20022_schema": "low"}
    assert "GrpHdr" in (result.findings[0].location.xpath or "")  # type: ignore[union-attr]


def test_errors_are_capped(xsd_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = generators.camt053(xsd_dir, remittance_xml="x")
    xsd = xsd_dir / "camt.053.001.08.xsd"
    xsd.write_text(xsd.read_text().replace('processContents="skip"', 'processContents="strict"'))
    path.write_text(path.read_text().replace("<Stmt>", "<Stmt><X/>" * 20, 1))
    assert len(run(Iso20022Schema(), path).findings) <= MAX_ERRORS


def test_missing_xsd_is_reported(xsd_dir: Path) -> None:
    path = generators.camt053(xsd_dir, message="pacs.008.001.08")
    assert rules(run(Iso20022Schema(), path)) == {"format.iso20022_schema_unavailable": "info"}


@pytest.mark.parametrize(
    "kwargs",
    [{"doctype": '<!DOCTYPE Document [<!ENTITY e "x">]>'}, {"remittance_xml": "<Broken>"}],
)
def test_unparseable_xml_is_left_to_other_analyzers(kwargs: dict[str, str], xsd_dir: Path) -> None:
    assert rules(run(Iso20022Schema(), generators.camt053(xsd_dir, **kwargs))) == {}


def test_other_xml_is_ignored(xsd_dir: Path) -> None:
    path = generators.disguised(xsd_dir, name="invoice.xml", parts=["xml"])
    assert rules(run(Iso20022Schema(), path)) == {}
