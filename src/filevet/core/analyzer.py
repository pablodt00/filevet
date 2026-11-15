from importlib.metadata import entry_points
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, ConfigDict

from filevet.core.artifact import Artifact
from filevet.core.finding import Finding
from filevet.core.identify import TYPES
from filevet.core.limits import Limits


class ExtractedFile(BaseModel):
    model_config = ConfigDict(frozen=True, ser_json_bytes="base64", val_json_bytes="base64")

    name: str
    data: bytes


class AnalyzerResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    findings: list[Finding] = []
    children: list[ExtractedFile] = []


class Party(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    ibans: list[str] = []
    producers: list[str] = []


class Expected(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    parties: dict[str, Party] = {}
    trust_roots: list[str] = []


class AnalysisContext(BaseModel):
    model_config = ConfigDict(frozen=True)

    limits: Limits
    expected: Expected = Expected()
    mask: bool = True


class Analyzer(Protocol):
    name: str
    version: str

    def supports(self, artifact: Artifact) -> bool: ...

    def analyze(self, artifact: Artifact, ctx: AnalysisContext) -> AnalyzerResult: ...


def load_analyzers() -> list[Analyzer]:
    found = sorted(entry_points(group="filevet.analyzers"), key=lambda ep: ep.name)
    return [ep.load()() for ep in found]


def supported_types(analyzer: Analyzer) -> list[str]:
    probe = Artifact(
        name="", size=0, sha256="", md5="", declared_type=None, detected_type="", path=Path()
    )
    return [t for t in TYPES if analyzer.supports(probe.model_copy(update={"detected_type": t}))]
