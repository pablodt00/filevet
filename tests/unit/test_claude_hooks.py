import json
import subprocess
import sys
from pathlib import Path

import pytest

HOOK = Path(__file__).parents[2] / ".claude" / "hooks" / "check_write.py"
EICAR_MARKER = "EICAR-STANDARD-" + "ANTIVIRUS-TEST-FILE"


def run_hook(tool_input: dict[str, object]) -> int:
    event = json.dumps({"tool_name": "Write", "tool_input": tool_input})
    return subprocess.run([sys.executable, "-I", HOOK], input=event, text=True).returncode


@pytest.mark.parametrize(
    ("tool_input", "code"),
    [
        ({"file_path": "a.py", "content": "print('hi')\n"}, 0),
        ({"file_path": "a.py", "old_string": "x", "new_string": "y"}, 0),
        ({"file_path": "a.txt", "content": f"X5O {EICAR_MARKER}"}, 2),
        ({"file_path": "a.py", "old_string": "x", "new_string": EICAR_MARKER}, 2),
        ({"file_path": "a.exe", "content": "MZ\x90\x00"}, 2),
        ({"file_path": "a.bin", "content": "\x7fELF\x02"}, 2),
    ],
)
def test_check_write_hook(tool_input: dict[str, object], code: int) -> None:
    assert run_hook(tool_input) == code
