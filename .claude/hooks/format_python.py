import json
import shutil
import subprocess
import sys

path = json.load(sys.stdin).get("tool_input", {}).get("file_path", "")
uv = shutil.which("uv")
if path.endswith(".py") and uv:
    subprocess.run([uv, "run", "--frozen", "ruff", "format", "--quiet", path], check=False)  # noqa: S603
