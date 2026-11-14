import hashlib
import itertools
import re
import stat
import zipfile
import zlib
from collections.abc import Iterator

from filevet.core.analyzer import AnalysisContext, AnalyzerResult, ExtractedFile
from filevet.core.artifact import Artifact
from filevet.core.finding import Finding, Location, Severity
from filevet.core.limits import Limits

MAX_RATIO = 100
RATIO_MIN_BYTES = 1 << 20
MAX_NESTING = 2
CHUNK = 1 << 16
ARCHIVE_MAGIC = (b"PK\x03\x04", b"Rar!\x1a\x07", b"7z\xbc\xaf\x27\x1c", b"\x1f\x8b")
CWE_409 = "https://cwe.mitre.org/data/definitions/409.html"
CWE_22 = "https://cwe.mitre.org/data/definitions/22.html"
DRIVE = re.compile(r"^[A-Za-z]:")


class Archive:
    name = "parser.archive"
    version = "0.1.0"

    def supports(self, artifact: Artifact) -> bool:
        return artifact.detected_type == "zip"

    def analyze(self, artifact: Artifact, ctx: AnalysisContext) -> AnalyzerResult:
        try:
            with zipfile.ZipFile(artifact.path) as zf:
                return _extract(zf, artifact, ctx.limits)
        except (zipfile.BadZipFile, ValueError, OSError, EOFError) as exc:
            return AnalyzerResult(findings=[_malformed(type(exc).__name__)])


def _extract(zf: zipfile.ZipFile, artifact: Artifact, limits: Limits) -> AnalyzerResult:
    infos = zf.infolist()
    findings = list(_overlaps(infos))
    if len(infos) > limits.max_children:
        findings.append(_bomb(f"{len(infos)} entries, over the limit of {limits.max_children}"))
    children: list[ExtractedFile] = []
    budget = limits.max_total_expanded_bytes
    for info in infos[: limits.max_children]:
        where = Location(archive_path=info.filename)
        if (traversal := _traversal(info)) is not None:
            findings.append(traversal.model_copy(update={"location": where}))
        if info.is_dir() or stat.S_ISLNK(info.external_attr >> 16):
            continue
        ratio = info.file_size / max(info.compress_size, 1)
        if info.file_size > RATIO_MIN_BYTES and ratio > MAX_RATIO:
            findings.append(_bomb(f"compression ratio {ratio:.0f}:1", where))
            continue
        if info.file_size > min(limits.max_input_bytes, budget):
            findings.append(_bomb(f"expands to {info.file_size} bytes", where))
            continue
        try:
            data, digest = _read(zf, info)
        except (zipfile.BadZipFile, RuntimeError, NotImplementedError, EOFError, zlib.error):
            findings.append(_malformed(f"entry could not be read: {info.filename}", where))
            continue
        if digest == artifact.sha256:
            findings.append(_bomb("contains a copy of itself (quine)", where, Severity.CRITICAL))
            continue
        if artifact.depth >= MAX_NESTING and data.startswith(ARCHIVE_MAGIC):
            findings.append(_bomb(f"archive nested {artifact.depth + 2} levels deep", where))
        budget -= len(data)
        children.append(ExtractedFile(name=info.filename, data=data))
    return AnalyzerResult(findings=findings, children=children)


def _read(zf: zipfile.ZipFile, info: zipfile.ZipInfo) -> tuple[bytes, str]:
    data, digest = bytearray(), hashlib.sha256()
    with zf.open(info) as entry:
        while chunk := entry.read(CHUNK):
            data += chunk
            digest.update(chunk)
    return bytes(data), digest.hexdigest()


def _overlaps(infos: list[zipfile.ZipInfo]) -> Iterator[Finding]:
    ordered = sorted(infos, key=lambda i: i.header_offset)
    for before, after in itertools.pairwise(ordered):
        if after.header_offset < before.header_offset + 30 + before.compress_size:
            where = Location(archive_path=after.filename)
            yield _bomb(f"entry overlaps {before.filename}", where, Severity.CRITICAL)
            return


def _traversal(info: zipfile.ZipInfo) -> Finding | None:
    name = info.filename
    if stat.S_ISLNK(info.external_attr >> 16):
        reason = "is a symbolic link"
    elif name.startswith(("/", "\\")):
        reason = "is an absolute path"
    elif DRIVE.match(name):
        reason = "starts with a drive letter"
    elif ".." in re.split(r"[/\\]", name):
        reason = "climbs out of the extraction directory"
    else:
        return None
    return Finding(
        rule_id="parser.path_traversal",
        title="Archive entry escapes the extraction directory",
        description=f"The entry name {reason}. Extracting it can overwrite files elsewhere.",
        severity=Severity.HIGH,
        evidence=name,
        references=[CWE_22],
    )


def _bomb(
    reason: str, where: Location | None = None, severity: Severity = Severity.HIGH
) -> Finding:
    return Finding(
        rule_id="parser.archive_bomb",
        title="Archive looks like a decompression bomb",
        description=f"The archive {reason}. That entry was not extracted.",
        severity=severity,
        location=where,
        evidence=reason,
        references=[CWE_409],
    )


def _malformed(reason: str, where: Location | None = None) -> Finding:
    return Finding(
        rule_id="parser.malformed",
        title="Archive could not be parsed",
        description=f"The ZIP structure is broken ({reason}).",
        severity=Severity.MEDIUM,
        location=where,
        evidence=reason,
    )
