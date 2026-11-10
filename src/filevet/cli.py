import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from filevet import __version__
from filevet.core.report import scan


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="filevet")
    parser.add_argument("--version", action="version", version=f"filevet {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    scan_parser = commands.add_parser("scan", help="scan a file and print a JSON report")
    scan_parser.add_argument("path", type=Path)
    args = parser.parse_args(argv)

    if not args.path.is_file():
        parser.error(f"not a file: {args.path}")
    json.dump(scan(args.path), sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0
