import argparse
import contextlib
import json
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import NoReturn, TextIO, TypeVar
from uuid import UUID

import yaml
from pydantic import ValidationError
from rich.console import Console
from rich.table import Table
from rich.text import Text

from filevet import __version__
from filevet.core.analyzer import Expected, load_analyzers, supported_types
from filevet.core.errors import ScanError
from filevet.core.finding import Severity
from filevet.core.identify import TYPES
from filevet.core.limits import DEFAULT_LIMITS, Limits
from filevet.core.pipeline import extract_text, sanitize, scan
from filevet.core.report import Report
from filevet.interfaces import formats
from filevet.llm import load_verifier, second_opinion
from filevet.policies import Policy, Suppression, load_suppressions

EXIT_CODES = {"pass": 0, "pass_with_findings": 0, "review": 1, "block": 2}
USAGE_ERROR = 3
INTERNAL_ERROR = 4
MAX_CONTEXT_BYTES = 1 << 20
FAIL_ON = [*Severity, *EXIT_CODES]
RAW = Policy(policy_version=1, name="raw")
T = TypeVar("T")


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        self.exit(USAGE_ERROR, f"{self.prog}: error: {message}\n")


def main(argv: Sequence[str] | None = None) -> int:
    parser = _Parser(prog="filevet")
    commands = parser.add_subparsers(dest="command", required=True)
    scan_parser = commands.add_parser("scan", help="scan files and print a report")
    scan_parser.add_argument("paths", type=Path, nargs="+", metavar="path")
    scan_parser.add_argument(
        "--format", choices=["json", "table", "sarif", "junit", "markdown"], default="json"
    )
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
    scan_parser.add_argument(
        "--policy", default="default", help="default, strict, ai-ingestion or a policy file"
    )
    scan_parser.add_argument("--suppressions", type=Path, help="YAML file of suppressions")
    scan_parser.add_argument(
        "--fail-on", choices=FAIL_ON, help="exit 1 at this severity or verdict, else 0"
    )
    scan_parser.add_argument(
        "--llm-verify", metavar="NAME", help="installed LLM verifier for a second opinion"
    )
    policy_parser = commands.add_parser("policy", help="work with verdict policies")
    policy_commands = policy_parser.add_subparsers(dest="policy_command", required=True)
    test_parser = policy_commands.add_parser(
        "test", help="show how verdicts change under a policy, compared with default"
    )
    test_parser.add_argument("policy")
    test_parser.add_argument("--corpus", type=Path, required=True, help="directory of files")
    extract_parser = commands.add_parser("extract", help="print the text of a file")
    extract_parser.add_argument("path", type=Path)
    extract_parser.add_argument(
        "--visible-only", action="store_true", help="only text a person would see"
    )
    sanitize_parser = commands.add_parser(
        "sanitize", help="write a copy without active content and report what was removed"
    )
    sanitize_parser.add_argument("path", type=Path)
    sanitize_parser.add_argument("--output", type=Path, required=True)
    serve_parser = commands.add_parser("serve", help="run the REST API")
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8000)
    commands.add_parser("worker", help="run an async scan worker")
    commands.add_parser("analyzers", help="list registered analyzers and the types they support")
    commands.add_parser("version", help="print the filevet version")
    schema_parser = commands.add_parser("schema", help="print a JSON schema")
    schema_parser.add_argument("kind", nargs="?", choices=["report", "policy"], default="report")
    args = parser.parse_args(argv)

    try:
        if args.command == "scan":
            return _scan(parser, args)
        if args.command == "policy":
            _policy_test(parser, _policy(parser, args.policy), args.corpus)
        elif args.command == "extract":
            _extract(parser, args)
        elif args.command == "sanitize":
            _sanitize(parser, args)
        elif args.command in {"serve", "worker"}:
            _run_service(parser, args)
        elif args.command == "analyzers":
            _list_analyzers()
        elif args.command == "version":
            print(f"filevet {__version__}")
        else:
            model = Report if args.kind == "report" else Policy
            print(json.dumps(model.model_json_schema(mode="serialization"), indent=2))
    except Exception as exc:
        print(f"filevet: internal error: {type(exc).__name__}", file=sys.stderr)
        return INTERNAL_ERROR
    return 0


def _scan(parser: _Parser, args: argparse.Namespace) -> int:
    for path in args.paths:
        if path.is_symlink() or not path.is_file():
            parser.error(f"not a regular file: {path}")
    try:
        limits = Limits(max_depth=args.max_depth, timeout_s=args.timeout)
    except ValidationError as exc:
        parser.error(f"invalid limit: {exc.errors()[0]['loc'][0]} {exc.errors()[0]['msg']}")
    expected = _context(parser, args.context) if args.context else None
    policy = _policy(parser, args.policy)
    suppressions = _suppressions(parser, args.suppressions) if args.suppressions else []
    verifier = None
    if args.llm_verify:
        try:
            verifier = load_verifier(args.llm_verify)
        except LookupError as exc:
            parser.error(str(exc))
    scanned = []
    for path in args.paths:
        try:
            report = scan(
                path,
                limits,
                expected=expected,
                mask=not args.no_mask,
                policy=policy,
                suppressions=suppressions,
            )
        except ScanError as exc:
            parser.error(str(exc))
        if verifier:
            report = second_opinion(report, verifier)
        for warning in report.warnings:
            print(f"filevet: warning: {warning}", file=sys.stderr)
        scanned.append((str(path), report))
    output = args.output.open("w") if args.output else contextlib.nullcontext(sys.stdout)
    with output as out:
        _write(out, args.format, scanned)
    if args.fail_on:
        return int(any(formats.fails(r, args.fail_on) for _, r in scanned))
    return max(EXIT_CODES[r.verdict] for _, r in scanned)


def _write(out: TextIO, fmt: str, scanned: list[tuple[str, Report]]) -> None:
    if fmt == "json":
        reports = [r.model_dump(mode="json") for _, r in scanned]
        out.write(json.dumps(reports[0] if len(reports) == 1 else reports, indent=2) + "\n")
    elif fmt == "table":
        for _, report in scanned:
            _print_table(report, out)
    else:
        out.write(getattr(formats, fmt)(scanned) + "\n")


def _policy(parser: _Parser, name: str) -> Policy:
    return _load(parser, f"policy {name}", lambda: Policy.load(name))


def _suppressions(parser: _Parser, path: Path) -> list[Suppression]:
    return _load(parser, f"suppressions file {path}", lambda: load_suppressions(path))


def _load(parser: _Parser, what: str, load: Callable[[], T]) -> T:
    try:
        return load()
    except OSError:
        parser.error(f"cannot read {what}")
    except yaml.YAMLError:
        parser.error(f"{what} is not valid YAML")
    except ValidationError as exc:
        parser.error(f"invalid {what}: {exc.errors()[0]['msg']}")
    except ValueError as exc:
        parser.error(str(exc))


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


def _policy_test(parser: _Parser, policy: Policy, corpus: Path) -> None:
    if not corpus.is_dir():
        parser.error(f"not a directory: {corpus}")
    baseline = Policy.load("default")
    table = Table(title=f"Verdicts under default and {policy.name}")
    for column in ("File", "default", policy.name, "Rule"):
        table.add_column(column)
    changed = total = 0
    for path in sorted(p for p in corpus.rglob("*") if p.is_file()):
        try:
            raw = scan(path, policy=RAW)
        except ScanError:
            continue
        parts = raw.artifacts, raw.findings, raw.analyzer_runs
        before, after = baseline.apply(*parts), policy.apply(*parts)
        total += 1
        if before.verdict != after.verdict:
            changed += 1
        rule = "" if after.decision.rule is None else str(after.decision.rule)
        cells = (str(path.relative_to(corpus)), before.verdict, after.verdict, rule)
        table.add_row(*(Text(c) for c in cells), style="bold" if cells[1] != cells[2] else None)
    table.caption = f"{changed} of {total} files change verdict"
    Console().print(table)


def _run_service(parser: _Parser, args: argparse.Namespace) -> None:
    from filevet.interfaces import api, jobs

    try:
        if args.command == "serve":
            api.serve(args.host, args.port)
        else:
            jobs.work_forever(jobs.from_env())
    except ValueError as exc:
        parser.error(str(exc))


def _extract(parser: _Parser, args: argparse.Namespace) -> None:
    if not args.path.is_file():
        parser.error(f"not a file: {args.path}")
    try:
        sys.stdout.write(extract_text(args.path, visible_only=args.visible_only) + "\n")
    except ScanError as exc:
        parser.error(str(exc))


def _sanitize(parser: _Parser, args: argparse.Namespace) -> None:
    if not args.path.is_file():
        parser.error(f"not a file: {args.path}")
    if args.output.resolve() == args.path.resolve():
        parser.error("--output must not be the input file")
    try:
        clean, removed = sanitize(args.path)
    except ScanError as exc:
        parser.error(str(exc))
    args.output.write_bytes(clean)
    report = {
        "input": args.path.name,
        "output": str(args.output),
        "removed": [f.model_dump(include={"rule_id", "title", "description"}) for f in removed],
    }
    print(json.dumps(report, indent=2))


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
        types = supported_types(analyzer)
        listed = "all" if len(types) == len(TYPES) else ", ".join(types) or "none"
        print(f"{analyzer.name} {analyzer.version}: {listed}")
