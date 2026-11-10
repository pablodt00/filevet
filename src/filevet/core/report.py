import hashlib
import os
from pathlib import Path
from typing import Any

from filevet import __version__

SEVERITIES = ("critical", "high", "medium", "low", "info")


def scan(path: Path) -> dict[str, Any]:
    with path.open("rb") as f:
        size = os.fstat(f.fileno()).st_size
        digest = hashlib.file_digest(f, "sha256")
    return {
        "filevet_version": __version__,
        "artifact": {
            "name": path.name,
            "size": size,
            "sha256": digest.hexdigest(),
        },
        "findings": [],
        "summary": dict.fromkeys(SEVERITIES, 0),
        "verdict": "pass",
    }
