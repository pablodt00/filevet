import sys
from collections.abc import Iterator
from pathlib import Path

from filevet import Policy, extract_text, scan

POLICY = Policy.load("ai-ingestion")
CHUNK = 1000


def safe_text(path: Path) -> str | None:
    report = scan(path, policy=POLICY)
    if report.verdict in {"block", "review"}:
        print(f"skipped {path.name}: {report.decision.reason}", file=sys.stderr)
        return None
    return extract_text(path, visible_only=True)


def chunks(text: str) -> Iterator[str]:
    for start in range(0, len(text), CHUNK):
        yield text[start : start + CHUNK]


if __name__ == "__main__":
    for arg in sys.argv[1:]:
        text = safe_text(Path(arg))
        for chunk in chunks(text or ""):
            print(chunk)
