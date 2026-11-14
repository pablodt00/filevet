from pathlib import Path

import pytest

from filevet.analyzers.parser.xml_unsafe import MAX_DEPTH, XmlUnsafe
from tests.corpus import generators
from tests.helpers import rules, run

LOL = '<!DOCTYPE d [<!ENTITY a "lol"><!ENTITY b "&a;&a;">]>'


@pytest.mark.parametrize(
    ("doctype", "severity"),
    [
        ('<!DOCTYPE Document [<!ENTITY e "x">]>', "high"),
        ('<!DOCTYPE Document [<!ENTITY e SYSTEM "file:///etc/hostname">]>', "critical"),
        ('<!DOCTYPE Document SYSTEM "https://example.invalid/d.dtd">', "critical"),
        ('<!DOCTYPE Document [<!ENTITY % p "x">]>', "critical"),
        (LOL, "critical"),
        ("<!DOCTYPE Document>", "high"),
    ],
)
def test_dtd_in_payment_file(doctype: str, severity: str, sample_dir: Path) -> None:
    path = generators.camt053(sample_dir, doctype=doctype)
    assert rules(run(XmlUnsafe(), path)) == {"parser.xml_unsafe": severity}


def test_dtd_outside_payment_file_is_medium(sample_dir: Path) -> None:
    path = sample_dir / "note.xml"
    path.write_bytes(b'<?xml version="1.0"?>\n<!DOCTYPE note [<!ENTITY e "x">]><note>&e;</note>')
    assert rules(run(XmlUnsafe(), path)) == {"parser.xml_unsafe": "medium"}


def test_utf16_dtd(sample_dir: Path) -> None:
    path = generators.camt053(sample_dir, encoding="utf-16", doctype="<!DOCTYPE Document>")
    assert rules(run(XmlUnsafe(), path)) == {"parser.xml_unsafe": "high"}


def test_xinclude(sample_dir: Path) -> None:
    include = '<xi:include xmlns:xi="http://www.w3.org/2001/XInclude" href="x"/>'
    path = generators.camt053(sample_dir, remittance_xml=include)
    assert rules(run(XmlUnsafe(), path)) == {"parser.xml_unsafe": "high"}


def test_deep_nesting(sample_dir: Path) -> None:
    assert rules(run(XmlUnsafe(), generators.camt053(sample_dir, nesting=MAX_DEPTH))) == {
        "parser.xml_unsafe": "medium"
    }
    shallow = generators.camt053(sample_dir, name="ok.xml", nesting=10)
    assert rules(run(XmlUnsafe(), shallow)) == {}


@pytest.mark.parametrize("message", ["camt.053.001.08", "pain.001.001.09", "pacs.008.001.08"])
def test_benign_messages(message: str, sample_dir: Path) -> None:
    path = generators.camt053(sample_dir, message=message, remittance_xml="A &amp; B")
    assert rules(run(XmlUnsafe(), path)) == {}


def test_not_well_formed(sample_dir: Path) -> None:
    path = generators.camt053(sample_dir, remittance_xml="<Broken>")
    assert rules(run(XmlUnsafe(), path)) == {"parser.malformed": "medium"}
