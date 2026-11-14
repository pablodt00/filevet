from pathlib import Path

from filevet.analyzers.integrity.pdf_signature import PdfSignature
from filevet.core.analyzer import AnalysisContext, Expected
from filevet.core.finding import Severity
from filevet.core.limits import DEFAULT_LIMITS
from tests.corpus.generators import pdf, signed_pdf
from tests.helpers import artifact, run

RULE = "integrity.pdf_digital_signature"


def _severities(path: Path, trust: list[str] | None = None) -> list[Severity]:
    ctx = AnalysisContext(limits=DEFAULT_LIMITS, expected=Expected(trust_roots=trust or []))
    findings = PdfSignature().analyze(artifact(path), ctx).findings
    assert {f.rule_id for f in findings} <= {RULE}
    return [f.severity for f in findings]


def test_unsigned_pdf_is_skipped(sample_dir: Path) -> None:
    assert run(PdfSignature(), pdf(sample_dir)).findings == []


def test_self_signed_is_untrusted(sample_dir: Path) -> None:
    assert _severities(signed_pdf(sample_dir)) == [Severity.LOW]


def test_trusted_signature_is_info(sample_dir: Path) -> None:
    path = signed_pdf(sample_dir, cert_name="signer.pem")
    trust = [(sample_dir / "signer.pem").read_text()]
    assert _severities(path, trust) == [Severity.INFO]


def test_content_added_after_signing(sample_dir: Path) -> None:
    path = signed_pdf(sample_dir, modified_text="Invoice 2026-0001 paid to another account")
    assert _severities(path) == [Severity.HIGH]


def test_broken_signature(sample_dir: Path) -> None:
    assert _severities(signed_pdf(sample_dir, broken=True)) == [Severity.HIGH]


def test_unreadable_signed_pdf_is_a_finding(sample_dir: Path) -> None:
    path = sample_dir / "bad.pdf"
    path.write_bytes(b"%PDF-1.7\n1 0 obj << /ByteRange [0 1 2 3] >> endobj\n")
    assert _severities(path) == [Severity.HIGH]
