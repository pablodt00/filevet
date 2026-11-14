import re
import zlib
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field

OBJECT = re.compile(rb"(?<!\d)(\d+)\s+(\d+)\s+obj\b(.*?)\bendobj", re.S)
STREAM = re.compile(rb">>\s*stream\r?\n(.*?)\r?\n?endstream", re.S)
REVISION_END = re.compile(rb"startxref\s+\d+\s+%%EOF[ \t]*(?:\r\n|\r|\n)?")
HEX = re.compile(rb"#([0-9A-Fa-f]{2})")
REF = re.compile(rb"(\d+)\s+\d+\s+R\b")
MAX_OBJECTS = 100_000
MAX_DEPTH = 32
MAX_OPS = 2_000_000
WHITE = 0.95


@dataclass
class Obj:
    body: bytes
    stream: bytes | None = None


@dataclass
class Text:
    page: int
    x: float
    y: float
    width: float
    height: float
    font: str
    text: str
    order: int


@dataclass
class Box:
    page: int
    x: float
    y: float
    width: float
    height: float
    order: int


@dataclass
class Page:
    number: int
    texts: list[Text] = field(default_factory=list)
    boxes: list[Box] = field(default_factory=list)
    fonts: dict[str, str] = field(default_factory=dict)


class Pdf:
    def __init__(self, data: bytes, budget: int) -> None:
        self.data = data
        self.budget = budget
        self.ends = [m.end() for m in REVISION_END.finditer(data)] or [len(data)]
        if len(self.ends) > 1 and b"/Linearized" in data[: self.ends[0]]:
            del self.ends[0]
        self.segments: list[dict[int, Obj]] = []
        start = 0
        for end in self.ends:
            self.segments.append(self._parse(data[start:end]))
            start = end
        self.encrypted = b"/Encrypt" in data

    def _parse(self, chunk: bytes) -> dict[int, Obj]:
        objects: dict[int, Obj] = {}
        for match in OBJECT.finditer(chunk):
            if len(objects) >= MAX_OBJECTS:
                break
            raw = match[3]
            stream = STREAM.search(raw)
            body = _unhex(raw[: stream.start() + 2] if stream else raw)
            obj = Obj(body, stream[1] if stream else None)
            objects[int(match[1])] = obj
            if stream and b"/ObjStm" in body:
                objects.update(self._object_stream(obj))
        return objects

    def _object_stream(self, obj: Obj) -> dict[int, Obj]:
        data = self.decode(obj)
        first = number(obj.body, b"First")
        if first is None:
            return {}
        header = data[: int(first)].split()
        found = {}
        offsets = [(int(n), int(o)) for n, o in zip(header[::2], header[1::2], strict=False)]
        for i, (num, offset) in enumerate(offsets[:MAX_OBJECTS]):
            end = offsets[i + 1][1] if i + 1 < len(offsets) else len(data)
            found[num] = Obj(_unhex(data[int(first) + offset : int(first) + end]))
        return found

    def decode(self, obj: Obj) -> bytes:
        raw = obj.stream or b""
        if self.budget <= 0:
            return b""
        if b"/FlateDecode" in obj.body or b"/Fl " in obj.body or b"/Fl]" in obj.body:
            try:
                raw = zlib.decompressobj().decompress(raw, self.budget)
            except zlib.error:
                return b""
        raw = raw[: self.budget]
        self.budget -= len(raw)
        return raw

    def objects(self, revision: int) -> dict[int, Obj]:
        merged: dict[int, Obj] = {}
        for segment in self.segments[: revision + 1]:
            merged.update(segment)
        return merged

    def trailer_ref(self, revision: int, key: bytes) -> int | None:
        found = list(
            re.finditer(rb"/" + key + rb"\s+(\d+)\s+\d+\s+R", self.data[: self.ends[revision]])
        )
        return int(found[-1][1]) if found else None

    def pages(self, revision: int) -> list[Page]:
        objs = self.objects(revision)
        numbers = self._page_numbers(objs, revision)
        pages = []
        for index, num in enumerate(numbers, 1):
            page = Page(index)
            page.fonts = self._fonts(objs, num)
            content = b"\n".join(
                self.decode(objs[ref]) for ref in refs(objs[num].body, b"Contents") if ref in objs
            )
            maps = {key: self._cmap(objs, ref) for key, ref in self._font_refs(objs, num).items()}
            _interpret(content, page, maps)
            pages.append(page)
        return pages

    def _page_numbers(self, objs: dict[int, Obj], revision: int) -> list[int]:
        root = self.trailer_ref(revision, b"Root")
        start = ref(objs[root].body, b"Pages") if root in objs else None
        found, stack, seen = [], [start], set[int]()
        while stack and len(seen) < MAX_OBJECTS:
            num = stack.pop()
            if num is None or num in seen or num not in objs:
                continue
            seen.add(num)
            body = objs[num].body
            if is_type(body, b"Page"):
                found.append(num)
            else:
                stack += reversed(refs(body, b"Kids"))
        return found or [n for n, o in sorted(objs.items()) if is_type(o.body, b"Page")]

    def _resources(self, objs: dict[int, Obj], num: int) -> bytes:
        for _ in range(MAX_DEPTH):
            body = objs[num].body if num in objs else b""
            target = ref(body, b"Resources")
            if target in objs:
                return objs[target].body
            inline = re.search(rb"/Resources\s*<<", body)
            if inline:
                return body[inline.end() :]
            parent = ref(body, b"Parent")
            if parent is None:
                break
            num = parent
        return b""

    def _font_refs(self, objs: dict[int, Obj], num: int) -> dict[str, int]:
        resources = self._resources(objs, num)
        match = re.search(rb"/Font\s*(?:(\d+)\s+\d+\s+R|<<(.*?)>>)", resources, re.S)
        if match is None:
            return {}
        table = objs[int(match[1])].body if match[1] and int(match[1]) in objs else match[2] or b""
        pairs = re.findall(rb"/([^\s/<>\[\]()]+)\s+(\d+)\s+\d+\s+R", table)
        return {key.decode("latin-1"): int(target) for key, target in pairs}

    def _fonts(self, objs: dict[int, Obj], num: int) -> dict[str, str]:
        fonts = {}
        for key, target in self._font_refs(objs, num).items():
            base = name(objs[target].body, b"BaseFont") if target in objs else None
            fonts[key] = (base or b"").decode("latin-1")
        return fonts

    def _cmap(self, objs: dict[int, Obj], num: int) -> dict[bytes, str]:
        target = ref(objs[num].body, b"ToUnicode") if num in objs else None
        return parse_cmap(self.decode(objs[target])) if target in objs else {}

    def info(self, revision: int) -> dict[str, str]:
        objs = self.objects(revision)
        target = self.trailer_ref(revision, b"Info")
        body = objs[target].body if target in objs else b""
        keys = (b"Producer", b"Creator", b"CreationDate", b"ModDate")
        found = {key.decode(): string(body, key) for key in keys}
        return {key: value for key, value in found.items() if value}

    def xmp(self, revision: int) -> bytes:
        objs = self.objects(revision)
        root = self.trailer_ref(revision, b"Root")
        target = ref(objs[root].body, b"Metadata") if root in objs else None
        return self.decode(objs[target]) if target in objs else b""


def _unhex(raw: bytes) -> bytes:
    return HEX.sub(lambda m: bytes([int(m[1], 16)]), raw)


def ref(body: bytes, key: bytes) -> int | None:
    match = re.search(rb"/" + key + rb"\s+(\d+)\s+\d+\s+R", body)
    return int(match[1]) if match else None


def refs(body: bytes, key: bytes) -> list[int]:
    match = re.search(rb"/" + key + rb"\s*(\[[^\]]*\]|\d+\s+\d+\s+R)", body)
    return [int(n) for n in REF.findall(match[1])] if match else []


def name(body: bytes, key: bytes) -> bytes | None:
    match = re.search(rb"/" + key + rb"\s*/([^\s/<>\[\]()]+)", body)
    return match[1] if match else None


def number(body: bytes, key: bytes) -> float | None:
    match = re.search(rb"/" + key + rb"\s+([+-]?\d+(?:\.\d+)?)(?!\s+\d+\s+R)", body)
    return float(match[1]) if match else None


def is_type(body: bytes, kind: bytes) -> bool:
    return re.search(rb"/Type\s*/" + kind + rb"(?![A-Za-z])", body) is not None


def string(body: bytes, key: bytes) -> str | None:
    match = re.search(rb"/" + key + rb"\s*(\(|<(?!<))", body)
    if match is None:
        return None
    raw, _ = _literal(body, match.end()) if match[1] == b"(" else _hexstring(body, match.end())
    return text_string(raw)


def text_string(raw: bytes) -> str:
    if raw.startswith(b"\xfe\xff"):
        return raw[2:].decode("utf-16-be", "replace")
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw[3:].decode("utf-8", "replace")
    return raw.decode("latin-1")


_ESCAPES = {ord("n"): b"\n", ord("r"): b"\r", ord("t"): b"\t", ord("b"): b"\b", ord("f"): b"\f"}


def _literal(data: bytes, i: int) -> tuple[bytes, int]:
    out, depth = bytearray(), 1
    while i < len(data):
        c = data[i]
        i += 1
        if c == 0x5C and i < len(data):
            nxt = data[i]
            octal = re.match(rb"[0-7]{1,3}", data[i : i + 3])
            if octal:
                out.append(int(octal[0], 8) & 0xFF)
                i += len(octal[0])
            elif nxt in b"\r\n":
                i += 2 if data[i : i + 2] == b"\r\n" else 1
            else:
                out += _ESCAPES.get(nxt, bytes([nxt]))
                i += 1
            continue
        if c == 0x28:
            depth += 1
        elif c == 0x29:
            depth -= 1
            if depth == 0:
                break
        out.append(c)
    return bytes(out), i


def _hexstring(data: bytes, i: int) -> tuple[bytes, int]:
    end = data.find(b">", i)
    end = len(data) if end < 0 else end
    digits = re.sub(rb"[^0-9A-Fa-f]", b"", data[i:end])
    return bytes.fromhex((digits + b"0" * (len(digits) % 2)).decode()), end + 1


def parse_cmap(data: bytes) -> dict[bytes, str]:
    mapping: dict[bytes, str] = {}
    for block in re.findall(rb"beginbfchar(.*?)endbfchar", data, re.S):
        for src, dst in re.findall(rb"<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]*)>", block):
            mapping[bytes.fromhex(src.decode())] = _utf16(dst)
    for block in re.findall(rb"beginbfrange(.*?)endbfrange", data, re.S):
        for lo, hi, dst in re.findall(
            rb"<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>\s*(<[0-9A-Fa-f]*>|\[[^\]]*\])", block
        ):
            low, high, width = int(lo, 16), int(hi, 16), len(lo) // 2
            targets = re.findall(rb"<([0-9A-Fa-f]*)>", dst)
            for offset, code in enumerate(range(low, min(high, low + 0xFFFF) + 1)):
                key = code.to_bytes(width, "big")
                if dst.startswith(b"["):
                    if offset < len(targets):
                        mapping[key] = _utf16(targets[offset])
                elif targets:
                    start = int(targets[0] or b"0", 16) + offset
                    mapping[key] = chr(start) if start < 0x110000 else ""
    return mapping


def _utf16(hexdigits: bytes) -> str:
    raw = bytes.fromhex(hexdigits.decode()) if len(hexdigits) % 2 == 0 else b""
    return raw.decode("utf-16-be", "replace")


def _show(raw: bytes, cmap: dict[bytes, str]) -> str:
    if not cmap:
        return raw.decode("latin-1")
    width = len(next(iter(cmap)))
    return "".join(cmap.get(raw[i : i + width], "") for i in range(0, len(raw), width))


EOL = re.compile(rb"[\r\n]")
DELIMITER = re.compile(rb"[\s()<>\[\]{}/%]")
END_IMAGE = re.compile(rb"\sEI(?=\s|$)")


def tokens(data: bytes) -> Iterator[tuple[str, object]]:
    i, n = 0, len(data)
    while i < n:
        c = data[i]
        if c in b" \t\r\n\f\0":
            i += 1
        elif c == 0x25:
            end = EOL.search(data, i)
            i = end.end() if end else n
        elif c == 0x28:
            raw, i = _literal(data, i + 1)
            yield "str", raw
        elif data.startswith(b"<<", i) or data.startswith(b">>", i):
            i += 2
        elif c == 0x3C:
            raw, i = _hexstring(data, i + 1)
            yield "str", raw
        elif c in b"[]":
            i += 1
            yield ("[" if c == 0x5B else "]"), None
        elif c == 0x2F:
            end = DELIMITER.search(data, i + 1)
            j = end.start() if end else n
            yield "name", data[i + 1 : j].decode("latin-1")
            i = j
        else:
            end = DELIMITER.search(data, i + 1)
            j = end.start() if end else n
            word = data[i:j] if j > i else data[i : i + 1]
            i = max(j, i + 1)
            try:
                yield "num", float(word)
            except ValueError:
                yield "op", word.decode("latin-1")
                if word == b"ID":
                    end_image = END_IMAGE.search(data, i)
                    i = end_image.end() if end_image else n


Matrix = tuple[float, float, float, float, float, float]
IDENTITY: Matrix = (1, 0, 0, 1, 0, 0)


def _mul(m: Matrix, n: Matrix) -> Matrix:
    a, b, c, d, e, f = m
    p, q, r, s, t, u = n
    return (
        a * p + b * r,
        a * q + b * s,
        c * p + d * r,
        c * q + d * s,
        e * p + f * r + t,
        e * q + f * s + u,
    )


def _interpret(content: bytes, page: Page, cmaps: dict[str, dict[bytes, str]]) -> None:
    ctm, white = IDENTITY, False
    saved: list[tuple[Matrix, bool]] = []
    tm = tlm = IDENTITY
    font, size, leading = "", 0.0, 0.0
    operands: list[object] = []
    array: list[object] | None = None
    rects: list[tuple[float, float, float, float]] = []
    order = 0

    def show(items: Sequence[object]) -> None:
        nonlocal tm, order
        cmap = cmaps.get(font, {})
        text, advance = "", 0.0
        for item in items:
            if isinstance(item, bytes):
                shown = _show(item, cmap)
                text += shown
                advance += 0.5 * size * len(shown)
            elif isinstance(item, float):
                advance -= item / 1000 * size
                if item < -200:
                    text += " "
        full = _mul(tm, ctm)
        scale = (full[2] ** 2 + full[3] ** 2) ** 0.5 or 1.0
        width = advance * ((full[0] ** 2 + full[1] ** 2) ** 0.5)
        if text.strip():
            order += 1
            page.texts.append(
                Text(page.number, full[4], full[5], width, scale * size, font, text, order)
            )
        tm = _mul((1, 0, 0, 1, advance, 0), tm)

    for count, (kind, value) in enumerate(tokens(content)):
        if count > MAX_OPS:
            break
        if kind == "[":
            array = []
            continue
        if kind == "]":
            operands.append(array or [])
            array = None
            continue
        if kind != "op":
            (array if array is not None else operands).append(value)
            continue
        op = str(value)
        nums = [v for v in operands if isinstance(v, float)]
        if op == "q":
            saved.append((ctm, white))
        elif op == "Q" and saved:
            ctm, white = saved.pop()
        elif op == "cm" and len(nums) == 6:
            ctm = _mul((nums[0], nums[1], nums[2], nums[3], nums[4], nums[5]), ctm)
        elif op in {"rg", "g", "sc", "scn"} and nums:
            white = all(v >= WHITE for v in nums)
        elif op == "k" and len(nums) == 4:
            white = all(v <= 1 - WHITE for v in nums)
        elif op == "re" and len(nums) == 4:
            rects.append((nums[0], nums[1], nums[2], nums[3]))
        elif op in {"f", "F", "f*", "B", "B*", "b", "b*"}:
            if white:
                for x, y, w, h in rects:
                    x0, y0 = _point(ctm, x, y)
                    x1, y1 = _point(ctm, x + w, y + h)
                    order += 1
                    box = Box(
                        page.number, min(x0, x1), min(y0, y1), abs(x1 - x0), abs(y1 - y0), order
                    )
                    page.boxes.append(box)
            rects = []
        elif op in {"n", "S", "s"}:
            rects = []
        elif op == "BT":
            tm = tlm = IDENTITY
        elif op == "Tf" and nums and operands and isinstance(operands[0], str):
            font, size = operands[0], nums[-1]
        elif op == "TL" and nums:
            leading = nums[0]
        elif op in {"Td", "TD"} and len(nums) == 2:
            if op == "TD":
                leading = -nums[1]
            tlm = _mul((1, 0, 0, 1, nums[0], nums[1]), tlm)
            tm = tlm
        elif op == "Tm" and len(nums) == 6:
            tm = tlm = (nums[0], nums[1], nums[2], nums[3], nums[4], nums[5])
        elif op in {"T*", "'", '"'}:
            tlm = _mul((1, 0, 0, 1, 0, -leading), tlm)
            tm = tlm
            if op != "T*":
                show([v for v in operands if isinstance(v, bytes)][-1:])
        elif op == "Tj":
            show([v for v in operands if isinstance(v, bytes)][-1:])
        elif op == "TJ":
            show(next((v for v in operands if isinstance(v, list)), []))
        operands = []


def _point(m: Matrix, x: float, y: float) -> tuple[float, float]:
    return m[0] * x + m[2] * y + m[4], m[1] * x + m[3] * y + m[5]


def lines(pages: list[Page]) -> list[str]:
    out = []
    for page in pages:
        rows: dict[int, list[Text]] = {}
        for text in page.texts:
            rows.setdefault(round(text.y), []).append(text)
        for y in sorted(rows, reverse=True):
            row = " ".join(t.text.strip() for t in sorted(rows[y], key=lambda t: t.x))
            out.append(f"{page.number}\t{' '.join(row.split())}")
    return out
