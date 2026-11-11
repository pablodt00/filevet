from pathlib import PurePath

SNIFF_BYTES = 512
EXECUTABLE = frozenset({"pe", "elf", "macho", "script"})

_SIGNATURES = (
    (b"%PDF-", "pdf"),
    (b"PK\x03\x04", "zip"),
    (b"PK\x05\x06", "zip"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"GIF8", "gif"),
    (b"\x1f\x8b", "gzip"),
    (b"Rar!\x1a\x07", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"MZ", "pe"),
    (b"\x7fELF", "elf"),
    (b"\xfe\xed\xfa\xce", "macho"),
    (b"\xfe\xed\xfa\xcf", "macho"),
    (b"\xce\xfa\xed\xfe", "macho"),
    (b"\xcf\xfa\xed\xfe", "macho"),
    (b"\xca\xfe\xba\xbe", "macho"),
    (b"#!", "script"),
)

_EXTENSIONS = {
    ext: label
    for label, exts in {
        "pdf": "pdf",
        "zip": "zip docx docm xlsx xlsm pptx pptm odt ods",
        "ole": "doc xls ppt msg",
        "png": "png",
        "jpeg": "jpg jpeg",
        "gif": "gif",
        "gzip": "gz tgz",
        "rar": "rar",
        "7z": "7z",
        "xml": "xml",
        "html": "html htm",
        "text": "csv txt json sta mt940",
        "pe": "exe dll scr sys cpl",
        "elf": "so elf",
        "macho": "dylib",
        "script": "sh ps1 bat cmd vbs js hta wsf py",
    }.items()
    for ext in exts.split()
}

_ALLOWED_CONTROL = frozenset(b"\t\n\r\f")
_ALSO_FITS = {"script": {"text"}, "html": {"xml"}}

TYPES = tuple(
    sorted({label for _, label in _SIGNATURES} | {"xml", "html", "text", "empty", "unknown"})
)


def declared_type(name: str) -> str | None:
    return _EXTENSIONS.get(PurePath(name).suffix.lower().lstrip("."))


def fits(declared: str, detected: str) -> bool:
    return detected in {declared, "empty", *_ALSO_FITS.get(declared, ())}


def detect_type(head: bytes) -> str:
    if not head:
        return "empty"
    for magic, label in _SIGNATURES:
        if head.startswith(magic):
            return label
    if any(b < 0x20 and b not in _ALLOWED_CONTROL for b in head):
        return "unknown"
    text = head.removeprefix(b"\xef\xbb\xbf").lstrip().lower()
    if text.startswith((b"<!doctype html", b"<html")):
        return "html"
    if text.startswith(b"<"):
        return "xml"
    return "text"
