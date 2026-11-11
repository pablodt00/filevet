import pytest

from filevet.core.identify import TYPES, declared_type, detect_type


@pytest.mark.parametrize(
    ("head", "expected"),
    [
        (b"", "empty"),
        (b"%PDF-1.7\n", "pdf"),
        (b"PK\x03\x04rest", "zip"),
        (b"M" + b"Z" + bytes(10), "pe"),
        (b"\x7f" + b"ELF\x02", "elf"),
        (b"\xcf\xfa\xed\xfe", "macho"),
        (b"#!/bin/sh\n", "script"),
        (b"\x89PNG\r\n\x1a\n", "png"),
        (b"\xef\xbb\xbf  <?xml version='1.0'?>", "xml"),
        (b"\n<!DOCTYPE HTML><html>", "html"),
        (b"date;amount\r\n2026-01-02;10,00\t\n", "text"),
        (b"M\xfcller;10\n", "text"),
        (b"\x00\x01\x02", "unknown"),
    ],
)
def test_detect_type(head: bytes, expected: str) -> None:
    assert detect_type(head) == expected
    assert expected in TYPES


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("invoice.PDF", "pdf"),
        ("statement.xlsx", "zip"),
        ("export.csv", "text"),
        ("invoice.pdf.exe", "pe"),
        ("run.ps1", "script"),
        ("README", None),
        ("data.bin", None),
        ("", None),
    ],
)
def test_declared_type(name: str, expected: str | None) -> None:
    assert declared_type(name) == expected
