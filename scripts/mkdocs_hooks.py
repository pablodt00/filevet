import posixpath
import re
from pathlib import Path
from typing import Any

from mkdocs.config.defaults import MkDocsConfig
from mkdocs.structure.files import File, Files
from mkdocs.structure.pages import Page

from filevet.core.analyzer import load_analyzers, supported_types
from filevet.core.identify import TYPES

REPO = "https://github.com/pablodt00/filevet/blob/master/"
LINK = re.compile(r"\]\((\.\./[^)\s]+)\)")
DIR_LINK = re.compile(r"\]\(([\w./-]+/)\)")


def on_files(files: Files, config: MkDocsConfig) -> Files:
    docs = Path(config.docs_dir)
    files.append(File.generated(config, "rules/index.md", content=rules_page(docs / "rules")))
    files.append(File.generated(config, "adr/index.md", content=adr_page(docs / "adr")))
    return files


def on_page_markdown(markdown: str, page: Page, **kwargs: Any) -> str:
    base = posixpath.dirname(page.file.src_uri)

    def outside(m: re.Match[str]) -> str:
        target = posixpath.normpath(posixpath.join(base, m[1]))
        return f"]({REPO}{target.removeprefix('../')})" if target.startswith("../") else m[0]

    return DIR_LINK.sub(r"](\1index.md)", LINK.sub(outside, markdown))


def rules_page(path: Path) -> str:
    rows = []
    for page in sorted(path.glob("*.md")):
        lines = page.read_text(encoding="utf-8").splitlines()
        severity = next((x[10:] for x in lines if x.startswith("Severity: ")), "")
        rows.append(f"| [`{page.stem}`]({page.name}) | {severity} |")
    analyzers = []
    for analyzer in load_analyzers():
        types = supported_types(analyzer)
        listed = "all" if len(types) == len(TYPES) else ", ".join(types) or "none"
        analyzers.append(f"| `{analyzer.name}` | {analyzer.version} | {listed} |")
    return "\n".join(
        [
            "# Rule reference",
            "",
            "Each rule page explains what the finding means, why it matters for finance files,"
            " how to fix the file and when it can be a false positive.",
            "",
            "| Rule ID | Severity |",
            "| --- | --- |",
            *rows,
            "",
            "## Analyzers",
            "",
            "The analyzers registered in this build and the detected types each one reads."
            " `filevet analyzers` prints the same list.",
            "",
            "| Analyzer | Version | Types |",
            "| --- | --- | --- |",
            *analyzers,
            "",
        ]
    )


def adr_page(path: Path) -> str:
    rows = []
    for page in sorted(path.glob("0*.md")):
        title = page.read_text(encoding="utf-8").splitlines()[0].removeprefix("# ")
        rows.append(f"- [{title}]({page.name})")
    return "\n".join(["# Decisions", "", "Architecture decision records, oldest first.", "", *rows])
