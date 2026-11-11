import json
import sys

EICAR_MARKER = "EICAR-STANDARD-" + "ANTIVIRUS-TEST-FILE"
EXECUTABLE_MAGIC = ("MZ", "\x7fELF", "\xfe\xed\xfa", "\xce\xfa\xed\xfe", "\xcf\xfa\xed\xfe")


def problem(tool_input: dict[str, object]) -> str | None:
    content = tool_input.get("content")
    text = content if isinstance(content, str) else str(tool_input.get("new_string", ""))
    if EICAR_MARKER in text:
        return "contains the EICAR test string; build it at run time in tests/corpus/generators/"
    if isinstance(content, str) and content.startswith(EXECUTABLE_MAGIC):
        return "looks like an executable; generate hostile samples into tmp-samples/ instead"
    return None


def main() -> int:
    tool_input = json.load(sys.stdin).get("tool_input", {})
    reason = problem(tool_input)
    if reason is None:
        return 0
    print(f"Blocked write to {tool_input.get('file_path')}: {reason}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
