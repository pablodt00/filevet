import io
import re
import zipfile
from dataclasses import dataclass
from typing import Literal
from xml.etree.ElementTree import Element

from filevet.core.extract_finance import _children, _xml, decode, local
from filevet.core.finding import Location
from filevet.core.pdf import Box, Page, Pdf, Text

Kind = Literal["body", "metadata", "comment"]
MAX_RUNS = 100_000
MAX_TEXTS_PER_PAGE = 20_000
TINY_POINTS = 1.0
TRANSPARENT = 0.1
METADATA_KEYS = (b"Title", b"Subject", b"Keywords", b"Author", b"Creator", b"Producer")
XMP_VALUES = re.compile(r'="([^"]*)"|>([^<]+)<')
CELL = re.compile(r"([A-Z]+)\d+")
WHITE = frozenset({"FFFFFF", "FFFFFFFF"})
ZERO_WIDTH = "\u200b\u200c\u200d\u2060\ufeff"
INVISIBLE = re.compile(f"[{ZERO_WIDTH}\u202a-\u202e\u2066-\u2069\U000e0000-\U000e007f]")


@dataclass(frozen=True)
class Run:
    text: str
    kind: Kind = "body"
    hidden: str | None = None
    location: Location | None = None


def runs(data: bytes, detected_type: str, budget: int) -> list[Run]:
    if detected_type == "pdf":
        found = _pdf(data, budget)
    elif detected_type == "zip":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                found = _ooxml(zf, budget)
        except (zipfile.BadZipFile, OSError, EOFError):
            found = []
    elif detected_type in {"text", "xml", "html"}:
        found = [Run(decode(data))]
    else:
        found = []
    return [r for r in found if r.text.strip()][:MAX_RUNS]


def visible(found: list[Run]) -> str:
    return "\n".join(
        INVISIBLE.sub("", r.text) for r in found if r.kind == "body" and r.hidden is None
    )


def _pdf(data: bytes, budget: int) -> list[Run]:
    pdf = Pdf(data, budget)
    if pdf.encrypted:
        return []
    revision = len(pdf.ends) - 1
    found = [
        Run(text.text, hidden=_pdf_hidden(text, page), location=Location(page=page.number))
        for page in pdf.pages(revision)
        for text in page.texts[:MAX_TEXTS_PER_PAGE]
    ]
    for key, value in pdf.info(revision, METADATA_KEYS).items():
        found.append(Run(value, "metadata", "metadata", Location(xpath=f"/Info/{key}")))
    xmp = pdf.xmp(revision).decode("utf-8", "replace")
    values = " ".join(a or b for a, b in XMP_VALUES.findall(xmp))
    found.append(Run(values, "metadata", "metadata", Location(xpath="/Metadata")))
    return found


def _pdf_hidden(text: Text, page: Page) -> str | None:
    cx, cy = text.x + text.width / 2, text.y + text.height / 3
    if page.box and not (page.box[0] <= cx <= page.box[2] and page.box[1] <= cy <= page.box[3]):
        return "outside the page"
    if text.height < TINY_POINTS:
        return "font smaller than 1 pt"
    if text.alpha < TRANSPARENT:
        return "transparent"
    under = any(_inside(cx, cy, image) for image in page.images if image.order < text.order)
    if text.mode in {3, 7} and not under:
        return "invisible rendering mode"
    if text.white and not under:
        return "white text"
    if any(_inside(cx, cy, image) for image in page.images if image.order > text.order):
        return "covered by an image"
    return None


def _inside(x: float, y: float, box: Box) -> bool:
    return box.x <= x <= box.x + box.width and box.y <= y <= box.y + box.height


def _ooxml(zf: zipfile.ZipFile, budget: int) -> list[Run]:
    names = set(zf.namelist())
    if "[Content_Types].xml" not in names:
        return []
    found: list[Run] = []
    if "word/document.xml" in names:
        found += _docx(_xml(zf, "word/document.xml", budget))
    if "xl/workbook.xml" in names:
        found += _xlsx(zf, names, budget)
    for name in sorted(names):
        where = Location(archive_path=name)
        if name.startswith("docProps/") and name.endswith(".xml"):
            found += [Run(t, "metadata", "metadata", where) for t in _texts(zf, name, budget)]
        elif re.fullmatch(r"word/comments\.xml|xl/comments\d*\.xml", name):
            found += [Run(t, "comment", "comment", where) for t in _texts(zf, name, budget)]
        elif re.fullmatch(r"customXml/item\d*\.xml", name):
            found += [
                Run(t, hidden="custom XML part", location=where) for t in _texts(zf, name, budget)
            ]
    return found


def _texts(zf: zipfile.ZipFile, name: str, budget: int) -> list[str]:
    return [e.text for e in _xml(zf, name, budget).iter() if e.text and e.text.strip()]


def _docx(root: Element) -> list[Run]:
    found = []
    for number, paragraph in enumerate(_children(root, "p"), 1):
        for run in _children(paragraph, "r"):
            text = "".join(t.text or "" for t in _children(run, "t"))
            props = {local(e): _attr(e, "val") for p in _children(run, "rPr") for e in p}
            hidden = None
            if "vanish" in props and props["vanish"] not in {"0", "false"}:
                hidden = "hidden run (vanish)"
            elif (props.get("color") or "").upper() in WHITE:
                hidden = "white text"
            found.append(Run(text, hidden=hidden, location=Location(offset=number)))
    return found


def _xlsx(zf: zipfile.ZipFile, names: set[str], budget: int) -> list[Run]:
    def part(name: str) -> Element:
        return _xml(zf, name, budget) if name in names else Element("none")

    strings = [
        "".join(t.text or "" for t in _children(si, "t"))
        for si in _children(part("xl/sharedStrings.xml"), "si")
    ]
    styles = part("xl/styles.xml")
    fonts = [
        any((_attr(c, "rgb") or "").upper() in WHITE for c in _children(font, "color"))
        for font in _children(styles, "font")
    ]
    xfs = next(_children(styles, "cellXfs"), Element("none"))
    white = {
        i
        for i, xf in enumerate(e for e in xfs if local(e) == "xf")
        if _int(xf.get("fontId")) < len(fonts) and fonts[_int(xf.get("fontId"))]
    }
    targets = {
        r.get("Id"): "xl/" + (r.get("Target") or "").removeprefix("/xl/")
        for r in _children(part("xl/_rels/workbook.xml.rels"), "Relationship")
    }
    found: list[Run] = []
    for sheet in _children(_xml(zf, "xl/workbook.xml", budget), "sheet"):
        target = targets.get(_attr(sheet, "id"), "")
        if target not in names:
            continue
        title = sheet.get("name", "")
        state = sheet.get("state", "visible")
        root = part(target)
        cols = [
            (_int(c.get("min")), _int(c.get("max")))
            for c in _children(root, "col")
            if c.get("hidden") in {"1", "true"}
        ]
        for row in _children(root, "row"):
            for cell in _children(row, "c"):
                text = _cell(cell, strings)
                ref = cell.get("r", "")
                hidden = None
                if state != "visible":
                    hidden = f"{state} sheet"
                elif row.get("hidden") in {"1", "true"}:
                    hidden = "hidden row"
                elif _column(ref) and any(lo <= _column(ref) <= hi for lo, hi in cols):
                    hidden = "hidden column"
                elif _int(cell.get("s")) in white:
                    hidden = "white text"
                found.append(Run(text, hidden=hidden, location=Location(sheet=title, cell=ref)))
                if len(found) >= MAX_RUNS:
                    return found
    return found


def _cell(cell: Element, strings: list[str]) -> str:
    v = next(_children(cell, "v"), None)
    raw = (v.text or "") if v is not None else ""
    if cell.get("t") == "inlineStr":
        return "".join(t.text or "" for t in _children(cell, "t"))
    if cell.get("t") == "s":
        index = int(raw) if raw.isdigit() else -1
        return strings[index] if 0 <= index < len(strings) else ""
    return raw


def _column(ref: str) -> int:
    match = CELL.fullmatch(ref)
    number = 0
    for letter in match[1] if match else "":
        number = number * 26 + ord(letter) - 64
    return number


def _int(value: str | None) -> int:
    return int(value) if value and value.isdigit() else 0


def _attr(element: Element, name: str) -> str | None:
    return next((v for k, v in element.attrib.items() if k.rsplit("}", 1)[-1] == name), None)
