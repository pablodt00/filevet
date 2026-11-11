import os
import time
import zipfile

from filevet.core.analyzer import AnalysisContext, AnalyzerResult, ExtractedFile
from filevet.core.artifact import Artifact
from filevet.core.finding import Finding


class Fake:
    version = "0.0.0"

    def __init__(self, name: str = "test.fake") -> None:
        self.name = name

    def supports(self, artifact: Artifact) -> bool:
        return True

    def analyze(self, artifact: Artifact, ctx: AnalysisContext) -> AnalyzerResult:
        return AnalyzerResult(findings=[Finding(rule_id="test.ran", title="ran", severity="info")])


class Sleeps(Fake):
    def analyze(self, artifact: Artifact, ctx: AnalysisContext) -> AnalyzerResult:
        time.sleep(60)
        return AnalyzerResult()


class AllocatesTooMuch(Fake):
    def analyze(self, artifact: Artifact, ctx: AnalysisContext) -> AnalyzerResult:
        bytearray(2 * ctx.limits.memory_bytes)
        return AnalyzerResult()


class Raises(Fake):
    def analyze(self, artifact: Artifact, ctx: AnalysisContext) -> AnalyzerResult:
        raise ValueError(artifact.path.read_text())


class Exits(Fake):
    def analyze(self, artifact: Artifact, ctx: AnalysisContext) -> AnalyzerResult:
        os._exit(3)


class ReturnsGarbage(Fake):
    def analyze(self, artifact: Artifact, ctx: AnalysisContext) -> AnalyzerResult:
        return "not a result"  # type: ignore[return-value]


class SupportsRaises(Fake):
    def supports(self, artifact: Artifact) -> bool:
        raise RuntimeError


class Children(Fake):
    def __init__(self, count: int, size: int) -> None:
        super().__init__("test.children")
        self.count, self.size = count, size

    def supports(self, artifact: Artifact) -> bool:
        return artifact.depth == 0

    def analyze(self, artifact: Artifact, ctx: AnalysisContext) -> AnalyzerResult:
        children = [
            ExtractedFile(name=f"{i}.txt", data=b"x" * self.size) for i in range(self.count)
        ]
        return AnalyzerResult(children=children)


class Unzips(Fake):
    def __init__(self) -> None:
        super().__init__("test.unzip")

    def supports(self, artifact: Artifact) -> bool:
        return artifact.detected_type == "zip"

    def analyze(self, artifact: Artifact, ctx: AnalysisContext) -> AnalyzerResult:
        with zipfile.ZipFile(artifact.path) as zf:
            children = [
                ExtractedFile(name=info.filename, data=zf.read(info))
                for info in zf.infolist()
                if info.file_size <= ctx.limits.max_input_bytes
            ]
        return AnalyzerResult(children=children)
