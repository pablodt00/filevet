import os
import socket
import time
import zipfile
from pathlib import Path

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


class Attempt(Fake):
    def attempt(self, artifact: Artifact) -> bool:
        raise NotImplementedError

    def analyze(self, artifact: Artifact, ctx: AnalysisContext) -> AnalyzerResult:
        try:
            escaped = self.attempt(artifact)
        except OSError:
            escaped = False
        rule_id = "test.escaped" if escaped else "test.blocked"
        return AnalyzerResult(findings=[Finding(rule_id=rule_id, title=self.name, severity="info")])


class OpensSocket(Attempt):
    def __init__(self, port: int) -> None:
        super().__init__("test.socket")
        self.port = port

    def attempt(self, artifact: Artifact) -> bool:
        socket.create_connection(("127.0.0.1", self.port), timeout=1).close()
        return True


class ReadsHostFile(Attempt):
    def __init__(self) -> None:
        super().__init__("test.read_host")

    def attempt(self, artifact: Artifact) -> bool:
        return bool(Path("/etc/passwd").read_bytes())


class WritesOutside(Attempt):
    def __init__(self, target: str) -> None:
        super().__init__("test.write_outside")
        self.target = target

    def attempt(self, artifact: Artifact) -> bool:
        Path(self.target).write_bytes(b"x")
        return True


class ForkBomb(Attempt):
    def __init__(self, attempts: int) -> None:
        super().__init__("test.fork_bomb")
        self.attempts = attempts

    def attempt(self, artifact: Artifact) -> bool:
        forked = 0
        for _ in range(self.attempts):
            try:
                pid = os.fork()
            except OSError:
                break
            if pid == 0:
                time.sleep(2)
                os._exit(0)
            forked += 1
        return forked >= self.attempts
