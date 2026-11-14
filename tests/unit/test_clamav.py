import os
import socketserver
import tempfile
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

from filevet.analyzers.malware.clamav import ClamAV
from filevet.core.pipeline import scan
from tests.corpus import generators
from tests.helpers import artifact, rules, run


class FakeClamd(socketserver.BaseRequestHandler):
    reply = b"stream: OK"
    received = b""

    def handle(self) -> None:
        data = b""
        while not data.endswith(bytes(4)) and (chunk := self.request.recv(65536)):
            data += chunk
        type(self).received = data
        self.request.sendall(self.reply + b"\0")


@pytest.fixture
def clamd(monkeypatch: pytest.MonkeyPatch) -> Iterator[type[FakeClamd]]:
    with tempfile.TemporaryDirectory() as tmp:
        handler = type("Handler", (FakeClamd,), {})
        server = socketserver.UnixStreamServer(f"{tmp}/clamd.sock", handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        monkeypatch.setenv("FILEVET_CLAMD", f"unix:{tmp}/clamd.sock")
        yield handler
        server.shutdown()
        server.server_close()


def test_clean_file_streams_contents(clamd: type[FakeClamd], benign_pdf: Path) -> None:
    assert rules(run(ClamAV(), benign_pdf)) == {}
    assert clamd.received.startswith(b"zINSTREAM\0\0\0\0\x0f%PDF-1.4")
    assert clamd.received.endswith(bytes(4))


def test_signature_match_is_critical(clamd: type[FakeClamd], benign_pdf: Path) -> None:
    clamd.reply = b"stream: Win.Test.EICAR_HDB-1 FOUND"
    [finding] = run(ClamAV(), benign_pdf).findings
    assert (finding.rule_id, finding.severity) == ("malware.clamav", "critical")
    assert finding.evidence == "Win.Test.EICAR_HDB-1"


def test_clamd_error_is_reported(clamd: type[FakeClamd], benign_pdf: Path) -> None:
    clamd.reply = b"INSTREAM size limit exceeded. ERROR"
    assert rules(run(ClamAV(), benign_pdf)) == {"malware.clamav_unavailable": "info"}


def test_children_are_left_to_the_parent_scan(clamd: type[FakeClamd], benign_pdf: Path) -> None:
    assert rules(run(ClamAV(), benign_pdf, depth=1)) == {}
    assert clamd.received == b""


@pytest.mark.parametrize("address", ["unix:/nonexistent/clamd.sock", "tcp:127.0.0.1:1", "smb:x"])
def test_unreachable_clamd(address: str, benign_pdf: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FILEVET_CLAMD", address)
    assert rules(run(ClamAV(), benign_pdf)) == {"malware.clamav_unavailable": "info"}


def test_runs_only_when_configured(benign_pdf: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FILEVET_CLAMD", raising=False)
    assert not ClamAV().supports(artifact(benign_pdf))
    monkeypatch.setenv("FILEVET_CLAMD", "unix:/nonexistent")
    assert ClamAV().supports(artifact(benign_pdf))


@pytest.mark.requires_clamav
def test_real_clamd_finds_eicar(sample_dir: Path) -> None:
    assert os.environ["FILEVET_CLAMD"]
    report = scan(generators.eicar(sample_dir))
    assert "malware.clamav" in {f.rule_id for f in report.findings}
