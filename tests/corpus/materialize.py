import shutil
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tests.corpus import generators  # noqa: E402

OUT = ROOT / "tmp-samples" / "corpus"


def main() -> None:
    shutil.rmtree(OUT, ignore_errors=True)
    OUT.mkdir(parents=True)
    for case in sorted((ROOT / "tests" / "corpus" / "cases").glob("*/expected.yaml")):
        spec = yaml.safe_load(case.read_text())
        path = getattr(generators, spec["generator"])(OUT, **spec["args"])
        path.rename(OUT / f"{case.parent.name}-{path.name}")
    print(OUT)


if __name__ == "__main__":
    main()
