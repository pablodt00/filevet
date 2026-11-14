import io

from asn1crypto import pem, x509
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.diff_analysis import ModificationLevel
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko.sign.validation.status import PdfSignatureStatus, SignatureCoverageLevel
from pyhanko_certvalidator import ValidationContext

from filevet.core.analyzer import AnalysisContext, AnalyzerResult
from filevet.core.artifact import Artifact
from filevet.core.finding import Finding, Severity

MAX_SIGNATURES = 20
REFERENCES = ["https://cwe.mitre.org/data/definitions/347.html"]


class PdfSignature:
    name = "integrity.pdf_signature"
    version = "0.1.0"

    def supports(self, artifact: Artifact) -> bool:
        return artifact.detected_type == "pdf"

    def analyze(self, artifact: Artifact, ctx: AnalysisContext) -> AnalyzerResult:
        data = artifact.read(ctx.limits.max_input_bytes)
        if b"/ByteRange" not in data:
            return AnalyzerResult()
        try:
            roots = [_certificate(text) for text in ctx.expected.trust_roots]
            signatures = PdfFileReader(io.BytesIO(data), strict=False).embedded_signatures
            findings = []
            for signature in signatures[:MAX_SIGNATURES]:
                context = ValidationContext(trust_roots=roots, allow_fetching=False)
                findings.append(_judge(validate_pdf_signature(signature, context)))
        except Exception as exc:
            reason = type(exc).__name__
            findings = [
                _finding("PDF signature could not be checked", reason, Severity.HIGH, reason)
            ]
        return AnalyzerResult(findings=findings)


def _certificate(text: str) -> x509.Certificate:
    raw = text.encode()
    if pem.detect(raw):
        _, _, raw = pem.unarmor(raw)
    return x509.Certificate.load(raw)


def _judge(status: PdfSignatureStatus) -> Finding:
    level = status.modification_level
    signer = status.signing_cert.subject.human_friendly
    if not (status.intact and status.valid):
        why = "The signed bytes were changed or the signature does not match the certificate."
        return _finding("PDF signature is invalid", why, Severity.HIGH, signer)
    if status.coverage != SignatureCoverageLevel.ENTIRE_FILE:
        if level is None or level > ModificationLevel.ANNOTATIONS:
            why = "Content was added to the document after it was signed."
            return _finding("PDF changed after signing", why, Severity.HIGH, signer)
        why = "Form fields or annotations were added after the document was signed."
        return _finding("PDF signed, then annotated", why, Severity.LOW, signer)
    if not status.trusted:
        why = "The signature is intact, but its certificate is untrusted or has expired."
        return _finding("PDF signed with an untrusted certificate", why, Severity.LOW, signer)
    why = "The signature is valid, trusted and covers the whole document."
    return _finding("PDF signature is valid", why, Severity.INFO, signer)


def _finding(title: str, description: str, severity: Severity, evidence: str) -> Finding:
    return Finding(
        rule_id="integrity.pdf_digital_signature",
        title=title,
        description=description,
        severity=severity,
        evidence=evidence,
        references=REFERENCES,
    )
