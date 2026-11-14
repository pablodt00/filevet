import argparse
import contextlib
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import NoReturn, TextIO
from uuid import UUID

import yaml
from pydantic import ValidationError
from rich.console import Console
from rich.table import Table
from rich.text import Text

from filevet import __version__
from filevet.core.analyzer import Expected, load_analyzers
from filevet.core.artifact import Artifact
from filevet.core.errors import ScanError
from filevet.core.identify import TYPES
from filevet.core.limits import DEFAULT_LIMITS, Limits
from filevet.core.pipeline import scan
from filevet.core.report import Report

EXIT_CODES = {"pass": 0, "review": 1, "block": 2}
USAGE_ERROR = 3
INTERNAL_ERROR = 4
MAX_CONTEXT_BYTES = 1 << 20


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        self.exit(USAGE_ERROR, f"{self.prog}: error: {message}\n")


def main(argv: Sequence[str] | None = None) -> int:
    parser = _Parser(prog="filevet")
    commands = parser.add_subparsers(dest="command", required=True)
    scan_parser = commands.add_parser("scan", help="scan a file and print a report")
    scan_parser.add_argument("path", type=Path)
    scan_parser.add_argument("--format", choices=["json", "table"], default="json")
    scan_parser.add_argument("--output", type=Path, help="write the report here, not to stdout")
    scan_parser.add_argument("--max-depth", type=int, default=DEFAULT_LIMITS.max_depth)
    scan_parser.add_argument(
        "--timeout", type=float, default=DEFAULT_LIMITS.timeout_s, help="seconds per analyzer"
    )
    scan_parser.add_argument(
        "--context", type=Path, help="YAML file of known IBANs, PDF producers and trust roots"
    )
    scan_parser.add_argument(
        "--no-mask", action="store_true", help="show IBANs in full in the report evidence"
    )
    commands.add_parser("analyzers", help="list registered analyzers and the types they support")
    commands.add_parser("version", help="print the filevet version")
    commands.add_parser("schema", help="print the JSON schema of the report")
    args = parser.parse_args(argv)

    try:
        if args.command == "scan":
            return _scan(parser, args)
        if args.command == "analyzers":
            _list_analyzers()
        elif args.command == "version":
            print(f"filevet {__version__}")
        else:
            print(json.dumps(Report.model_json_schema(mode="serialization"), indent=2))
    except Exception as exc:
        print(f"filevet: internal error: {type(exc).__name__}", file=sys.stderr)
        return INTERNAL_ERROR
    return 0


def _scan(parser: _Parser, args: argparse.Namespace) -> int:
    if not args.path.is_file():
        parser.error(f"not a file: {args.path}")
    try:
        limits = Limits(max_depth=args.max_depth, timeout_s=args.timeout)
    except ValidationError as exc:
        parser.error(f"invalid limit: {exc.errors()[0]['loc'][0]} {exc.errors()[0]['msg']}")
    expected = _context(parser, args.context) if args.context else None
    try:
        report = scan(args.path, limits, expected=expected, mask=not args.no_mask)
    except ScanError as exc:
        parser.error(str(exc))
    output = args.output.open("w") if args.output else contextlib.nullcontext(sys.stdout)
    with output as out:
        if args.format == "json":
            out.write(report.model_dump_json(indent=2) + "\n")
        else:
            _print_table(report, out)
    return EXIT_CODES[report.verdict]


def _context(parser: _Parser, path: Path) -> Expected:
    try:
        with path.open("rb") as f:
            data = f.read(MAX_CONTEXT_BYTES + 1)
        if len(data) > MAX_CONTEXT_BYTES:
            parser.error(f"context file is larger than {MAX_CONTEXT_BYTES} bytes")
        return Expected.model_validate(yaml.safe_load(data) or {})
    except OSError:
        parser.error(f"cannot read context file: {path}")
    except yaml.YAMLError:
        parser.error("context file is not valid YAML")
    except ValidationError as exc:
        parser.error(f"invalid context file: {exc.errors()[0]['msg']}")


def _print_table(report: Report, out: TextIO) -> None:
    names: dict[UUID | None, str] = {a.id: a.name for a in report.artifacts}
    summary = ", ".join(f"{severity}: {count}" for severity, count in report.summary.items())
    table = Table(title=f"filevet verdict: {report.verdict}", caption=summary)
    for column in ("Severity", "Rule", "File", "Title", "Evidence"):
        table.add_column(column, no_wrap=column in {"Severity", "Rule"})
    for f in sorted(report.findings, key=lambda f: -f.severity.rank):
        cells = (f.severity, f.rule_id, names.get(f.artifact_id, ""), f.title, f.evidence)
        table.add_row(*(Text(str(cell)) for cell in cells))
    Console(file=out).print(table)


def _list_analyzers() -> None:
    for analyzer in load_analyzers():
        types = [t for t in TYPES if analyzer.supports(_probe(t))]
        listed = "all" if len(types) == len(TYPES) else ", ".join(types) or "none"
        print(f"{analyzer.name} {analyzer.version}: {listed}")


def _probe(detected_type: str) -> Artifact:
    return Artifact(
        name="",
        size=0,
        sha256="",
        md5="",
        declared_type=None,
        detected_type=detected_type,
        path=Path(),
    )
