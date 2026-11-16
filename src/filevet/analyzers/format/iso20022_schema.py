import itertools
import os
from pathlib import Path

import xmlschema
from defusedxml.ElementTree import fromstring

from filevet.core.analyzer import AnalysisContext, AnalyzerResult
from filevet.core.artifact import Artifact
from filevet.core.errors import XML_ERRORS
from filevet.core.finding import Finding, Location, Severity
from filevet.core.identify import iso20022_message

MAX_ERRORS = 10
BUNDLED = Path(__file__).with_name("xsd")


class Iso20022Schema:
    name = "format.iso20022_schema"
    version = "0.1.0"

    def supports(self, artifact: Artifact) -> bool:
        return artifact.detected_type == "xml"

    def analyze(self, artifact: Artifact, ctx: AnalysisContext) -> AnalyzerResult:
        try:
            root = fromstring(artifact.read(ctx.limits.max_input_bytes), forbid_dtd=True)
        except XML_ERRORS:
            return AnalyzerResult()
        message = iso20022_message(root.tag)
        if message is None:
            return AnalyzerResult()
        xsd = Path(os.environ.get("FILEVET_XSD_DIR", BUNDLED)) / f"{message}.xsd"
        if not xsd.is_file():
            return AnalyzerResult(
                findings=[
                    Finding(
                        rule_id="format.iso20022_schema_unavailable",
                        title=f"No XSD for {message}",
                        description=f"{xsd.name} was not found, so the message was not validated.",
                        severity=Severity.INFO,
                        evidence=message,
                    )
                ]
            )
        schema = xmlschema.XMLSchema(
            str(xsd), base_url=str(xsd.parent), allow="sandbox", defuse="always"
        )
        errors = itertools.islice(schema.iter_errors(root), MAX_ERRORS)
        return AnalyzerResult(
            findings=[
                Finding(
                    rule_id="format.iso20022_schema",
                    title=f"Message does not match the {message} schema",
                    description="The message breaks its XSD, so importing systems may reject it.",
                    severity=Severity.LOW,
                    location=Location(xpath=error.path),
                    evidence=error.reason or "",
                )
                for error in errors
            ]
        )
