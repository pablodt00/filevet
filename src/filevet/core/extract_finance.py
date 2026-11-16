import csv
import io
import re
import zipfile
from collections.abc import Iterator
from datetime import date
from decimal import Decimal
from typing import NamedTuple
from xml.etree.ElementTree import Element

from charset_normalizer import from_bytes
from defusedxml.ElementTree import fromstring

from filevet.core.errors import XML_ERRORS, ZIP_ERRORS
from filevet.core.finding import Location

IBAN_LENGTHS = {
    m[1]: int(m[2])
    for m in re.finditer(
        r"([A-Z]{2})(\d\d)",
        "AD24 AE23 AL28 AT20 AZ28 BA20 BE16 BG22 BH22 BI27 BR29 BY28 CH21 CR22 CY28 CZ24 DE22 "
        "DJ27 DK18 DO28 EE20 EG29 ES24 FI18 FK18 FO18 FR27 GB22 GE22 GI23 GL18 GR27 GT28 HN28 "
        "HR21 HU28 IE22 IL23 IQ23 IS26 IT27 JO30 KW30 KZ20 LB28 LC32 LI21 LT20 LU20 LV21 LY25 "
        "MC27 MD24 ME22 MK19 MN20 MR27 MT31 MU30 NI28 NL18 NO15 OM23 PK24 PL28 PS29 PT25 QA29 "
        "RO24 RS22 RU33 SA24 SC31 SD18 SE24 SI19 SK24 SM27 SO23 ST25 SV28 TL23 TN24 TR26 UA29 "
        "VA22 VG24 XK20 YE30",
    )
}
COUNTRIES = frozenset(
    re.findall(
        r"[A-Z]{2}",
        "AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ "
        "BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM "
        "DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS "
        "GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN "
        "KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ "
        "MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM "
        "PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV "
        "SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI "
        "VN VU WF WS XK YE YT ZA ZM ZW",
    )
)
MAX_ROWS = 100_000
MAX_COLUMNS = 1_000

IBAN = re.compile(
    r"(?<![A-Z0-9])([A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?)(?![A-Z0-9])"
)
IBAN_LABEL = re.compile(r"(?i)\biban\b\W{0,5}$")
BIC = re.compile(r"(?i)\b(?:bic|swift)(?:[\s/-]*code)?\W{0,5}([A-Z0-9]{6,12})\b")
BIC_SHAPE = re.compile(r"[A-Z]{4}([A-Z]{2})[A-Z0-9]{2}(?:[A-Z0-9]{3})?")
AMOUNT = re.compile(
    r"(?<![\d.,])(-?)(\d{1,3}(?:([.,' ])\d{3})(?:\3\d{3})*|\d+)([.,])(\d{2})"
    r"(?![\d%]|[.,]\d|\s?%)(-?)"
)
DATE = re.compile(r"(?<!\d)(?:(\d{4})-(\d{2})-(\d{2})|(\d{2})([./])(\d{2})\5(\d{4}))(?!\d)")


_LETTERS = str.maketrans({chr(c): str(c - 55) for c in range(65, 91)})


class Found(NamedTuple):
    value: str
    location: Location
    labeled: bool


def compact(iban: str) -> str:
    return iban.replace(" ", "").upper()


def iban_problem(iban: str) -> str | None:
    iban = compact(iban)
    expected = IBAN_LENGTHS.get(iban[:2])
    if expected is None:
        return f"unknown IBAN country code {iban[:2]}"
    if len(iban) != expected:
        return f"{len(iban)} characters, {iban[:2]} IBANs have {expected}"
    if not iban.isalnum() or not iban[2:4].isdigit():
        return "invalid characters"
    digits = (iban[4:] + iban[:4]).translate(_LETTERS)
    return None if int(digits) % 97 == 1 else "check digits are wrong (mod-97)"


def bic_problem(bic: str) -> str | None:
    shape = BIC_SHAPE.fullmatch(bic.upper())
    if shape is None:
        return "not 8 or 11 characters in the ISO 9362 layout"
    return None if shape[1] in COUNTRIES else f"unknown country code {shape[1]}"


def mask(text: str) -> str:
    def hide(match: re.Match[str]) -> str:
        iban = compact(match[1])
        groups = [iban[i : i + 4] for i in range(0, len(iban), 4)]
        middle = ["*" * len(g) for g in groups[1:-1]]
        return " ".join([groups[0], *middle, groups[-1]]) if len(groups) > 1 else iban

    return IBAN.sub(hide, text)


def amounts(text: str) -> list[Decimal]:
    return [_amount(m) for m in AMOUNT.finditer(text)]


def _amount(match: re.Match[str]) -> Decimal:
    whole = re.sub(r"[.,' ]", "", match[2])
    value = Decimal(f"{whole}.{match[5]}")
    return -value if match[1] or match[6] else value


def dates(text: str) -> Iterator[tuple[str, date | None]]:
    for match in DATE.finditer(text):
        if match[1]:
            yield match[0], _date(match[1], match[2], match[3])
        else:
            parsed = _date(match[7], match[6], match[4])
            if parsed is None and match[5] == "/":
                parsed = _date(match[7], match[4], match[6])
            yield match[0], parsed


def _date(year: str, month: str, day: str) -> date | None:
    try:
        return date(int(year), int(month), int(day))
    except ValueError:
        return None


def from_text(text: str, location: Location) -> tuple[list[Found], list[Found]]:
    ibans = []
    for match in IBAN.finditer(text):
        iban = compact(match[1])
        expected = IBAN_LENGTHS.get(iban[:2])
        if expected and len(iban) > expected and iban_problem(iban[:expected]) is None:
            iban = iban[:expected]
        labeled = IBAN_LABEL.search(text[max(0, match.start() - 12) : match.start()]) is not None
        if labeled or expected:
            ibans.append(Found(iban, location, labeled))
    bics = [Found(m[1].upper(), location, True) for m in BIC.finditer(text)]
    return ibans, bics


def from_table(rows: list[list[str]], sheet: str | None = None) -> tuple[list[Found], list[Found]]:
    header = [h.lower() for h in rows[0]] if rows else []
    ibans, bics = [], []
    for r, row in enumerate(rows[1:], 2):
        for c, value in enumerate(row):
            name = header[c] if c < len(header) else ""
            if not value.strip():
                continue
            labeled = "iban" in name or "bic" in name or "swift" in name
            if not labeled and not (IBAN.search(value) or BIC.search(value)):
                continue
            location = Location(sheet=sheet, cell=f"{column(c + 1)}{r}")
            if "iban" in name:
                ibans.append(Found(compact(value), location, True))
            elif labeled:
                bics.append(Found(value.strip().upper(), location, True))
            else:
                found_ibans, found_bics = from_text(value, location)
                ibans += found_ibans
                bics += found_bics
    return ibans, bics


def from_iso20022(root: Element) -> tuple[list[Found], list[Found]]:
    ibans, bics = [], []
    for path, element in walk(root):
        text = (element.text or "").strip()
        if not text:
            continue
        tag = local(element)
        if tag == "IBAN":
            ibans.append(Found(compact(text), Location(xpath=path), True))
        elif tag in {"BIC", "BICFI", "AnyBIC", "BICOrBEI"}:
            bics.append(Found(text.upper(), Location(xpath=path), True))
    return ibans, bics


def local(element: Element) -> str:
    return element.tag.rsplit("}", 1)[-1]


def walk(root: Element) -> Iterator[tuple[str, Element]]:
    stack = [(f"/{local(root)}", root)]
    while stack:
        path, element = stack.pop()
        yield path, element
        stack += reversed([(f"{path}/{local(child)}", child) for child in element])


def decode(data: bytes) -> str:
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        best = from_bytes(data[: 1 << 20]).best()
        return data.decode(best.encoding if best else "latin-1", "replace")


def read_csv(data: bytes) -> list[list[str]]:
    text = decode(data)
    try:
        dialect: type[csv.Dialect] | csv.Dialect = csv.Sniffer().sniff(text[: 1 << 14], ",;\t|")
    except csv.Error:
        dialect = csv.excel
    rows = []
    for row in csv.reader(io.StringIO(text, newline=""), dialect):
        rows.append(row[:MAX_COLUMNS])
        if len(rows) == MAX_ROWS:
            break
    return rows


def read_xlsx(zf: zipfile.ZipFile, limit: int) -> dict[str, list[list[str]]]:
    names = set(zf.namelist())
    strings = []
    if "xl/sharedStrings.xml" in names:
        for si in _children(_xml(zf, "xl/sharedStrings.xml", limit), "si"):
            strings.append("".join(t.text or "" for t in _children(si, "t")))
    sheets = {}
    for part in sorted(n for n in names if n.startswith("xl/worksheets/") and n.endswith(".xml")):
        rows = []
        for row in _children(_xml(zf, part, limit), "row"):
            values = []
            for cell in _children(row, "c"):
                v = next(_children(cell, "v"), None)
                raw = v.text or "" if v is not None else ""
                if cell.get("t") == "inlineStr":
                    raw = "".join(t.text or "" for t in _children(cell, "t"))
                elif cell.get("t") == "s":
                    index = int(raw) if raw.isdigit() else -1
                    raw = strings[index] if 0 <= index < len(strings) else ""
                values.append(raw)
            rows.append(values[:MAX_COLUMNS])
            if len(rows) == MAX_ROWS:
                break
        sheets[part.rsplit("/", 1)[1].removesuffix(".xml")] = rows
    return sheets


def _xml(zf: zipfile.ZipFile, part: str, limit: int) -> Element:
    try:
        with zf.open(part) as f:
            root: Element = fromstring(f.read(limit), forbid_dtd=True)
            return root
    except (*XML_ERRORS, *ZIP_ERRORS):
        return Element("empty")


def _children(element: Element, name: str) -> Iterator[Element]:
    return (e for e in element.iter() if local(e) == name)


def column(number: int) -> str:
    letters = ""
    while number:
        number, rest = divmod(number - 1, 26)
        letters = chr(65 + rest) + letters
    return letters
