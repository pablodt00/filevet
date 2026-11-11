from importlib.metadata import entry_points
from typing import Protocol

from pydantic import BaseModel, ConfigDict

from filevet.core.artifact import Artifact
from filevet.core.finding import Finding
from filevet.core.limits import Limits


class ExtractedFile(BaseModel):
    model_config = ConfigDict(frozen=True, ser_json_bytes="base64", val_json_bytes="base64")

    name: str
    data: bytes


class AnalyzerResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    findings: list[Finding] = []
    children: list[ExtractedFile] = []


class AnalysisContext(BaseModel):
    model_config = ConfigDict(frozen=True)

    limits: Limits


class Analyzer(Protocol):
    name: str
    version: str

    def supports(self, artifact: Artifact) -> bool: ...

    def analyze(self, artifact: Artifact, ctx: AnalysisContext) -> AnalyzerResult: ...


def load_analyzers() -> list[Analyzer]:
    found = sorted(entry_points(group="filevet.analyzers"), key=lambda ep: ep.name)
    return [ep.load()() for ep in found]
