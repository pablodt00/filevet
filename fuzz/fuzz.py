import json
import sys
import tempfile
from pathlib import Path

import atheris
import jsonschema

with atheris.instrument_imports(include=["filevet"]):
    from filevet.core.analyzer import AnalysisContext, AnalyzerResult, load_analyzers
    from filevet.core.artifact import Artifact
    from filevet.core.errors import ScanError
    from filevet.core.limits import Limits
    from filevet.core.pipeline import scan

    ANALYZERS = [a for a in load_analyzers() if a.name != "malware.clamav"]

TARGETS = {"pdf": "pdf", "ooxml": "zip", "ole": "ole", "csv": "text", "xml": "xml", "zip": "zip"}
SCHEMA = json.loads((Path(__file__).parents[1] / "docs/schema/report.schema.json").read_text())
LIMITS = Limits(max_input_bytes=1 << 20, max_total_expanded_bytes=8 << 20, timeout_s=10)
CTX = AnalysisContext(limits=LIMITS)


def main() -> None:
    target = sys.argv.pop(1)
    if target != "pipeline" and target not in TARGETS:
        sys.exit(f"target must be pipeline or one of {', '.join(TARGETS)}")
    sample = Path(tempfile.mkdtemp(prefix="filevet-fuzz-")) / "sample"

    def one_input(data: bytes) -> None:
        if target == "pipeline":
            try:
                report = scan(data, LIMITS, ANALYZERS).model_dump_json()
                jsonschema.validate(json.loads(report), SCHEMA)
            except ScanError:
                pass
            return
        sample.write_bytes(data)
        artifact = Artifact(
            name=f"sample.{target}",
            size=len(data),
            sha256="",
            md5="",
            declared_type=None,
            detected_type=TARGETS[target],
            path=sample,
        )
        for analyzer in ANALYZERS:
            if analyzer.supports(artifact):
                AnalyzerResult.model_validate(analyzer.analyze(artifact, CTX))

    atheris.Setup(sys.argv, one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
