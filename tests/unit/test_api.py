import hashlib
import json
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from filevet.interfaces import api, jobs
from filevet.policies import Policy
from tests.corpus import generators

OPENAPI = Path(__file__).resolve().parents[2] / "docs" / "openapi.json"
KEY = "test-key"
HEADERS = {"Authorization": f"Bearer {KEY}"}


def _queue() -> jobs.Queue:
    return jobs.Queue(jobs.MemoryBackend(), Fernet.generate_key(), 60, Policy.load("default"))


def _client(**settings: object) -> tuple[TestClient, jobs.Queue]:
    q = _queue()
    values = {"api_keys": {hashlib.sha256(KEY.encode()).hexdigest()}, **settings}
    app = api.create_app(api.Settings.model_validate(values), q, worker=False)
    return TestClient(app), q


def test_needs_keys_or_explicit_no_auth() -> None:
    with pytest.raises(ValueError, match="FILEVET_API_KEYS"):
        api.create_app(api.Settings(), _queue(), worker=False)


@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer wrong"}, {"X-API-Key": ""}])
def test_unknown_key_is_rejected(headers: dict[str, str]) -> None:
    client, _ = _client()
    assert client.post("/v1/scans", content=b"x", headers=headers).status_code == 401


def test_small_upload_gets_a_report(benign_pdf: Path) -> None:
    client, _ = _client()
    response = client.post(
        "/v1/scans?name=benign.pdf", content=benign_pdf.read_bytes(), headers={"X-API-Key": KEY}
    )
    assert response.status_code == 200
    body = response.json()
    assert (body["status"], body["report"]["verdict"]) == ("done", "pass")
    assert body["report"]["artifacts"][0]["name"] == "benign.pdf"
    assert 'filevet_scans_total{verdict="pass"} 1' in client.get("/metrics").text


def test_multipart_upload(sample_dir: Path) -> None:
    client, _ = _client()
    path = generators.disguised(sample_dir, name="invoice.pdf", parts=["pe_stub"])
    files = {"file": ("invoice.pdf", path.read_bytes())}
    response = client.post("/v1/scans", files=files, headers=HEADERS)
    assert response.json()["report"]["verdict"] == "block"
    assert (
        client.post("/v1/scans", files={"other": ("a", b"x")}, headers=HEADERS).status_code == 400
    )


def test_large_upload_is_queued_then_scanned(benign_pdf: Path) -> None:
    client, q = _client(sync_max_bytes=4)
    response = client.post("/v1/scans", content=benign_pdf.read_bytes(), headers=HEADERS)
    assert response.status_code == 202
    scan_id = response.json()["id"]
    assert response.headers["location"] == f"/v1/scans/{scan_id}"
    assert client.get(f"/v1/scans/{scan_id}", headers=HEADERS).json()["status"] == "queued"
    assert q.work_once(1)
    body = client.get(f"/v1/scans/{scan_id}", headers=HEADERS).json()
    assert (body["status"], body["report"]["verdict"]) == ("done", "pass")


def test_unknown_scan_is_404() -> None:
    client, _ = _client()
    assert client.get(f"/v1/scans/{'0' * 32}", headers=HEADERS).status_code == 404
    assert client.get("/v1/scans/not-an-id", headers=HEADERS).status_code == 422


def test_upload_over_the_limit_is_413() -> None:
    client, _ = _client(max_upload_bytes=8)
    assert client.post("/v1/scans", content=b"x" * 9, headers=HEADERS).status_code == 413
    huge = b"x" * (api.MULTIPART_OVERHEAD + 64)
    assert client.post("/v1/scans", content=huge, headers=HEADERS).status_code == 413


def test_rate_limit() -> None:
    client, _ = _client(rate_per_minute=2)
    codes = [client.get("/v1/policies", headers=HEADERS).status_code for _ in range(3)]
    assert codes == [200, 200, 429]


def test_callback_must_be_allowed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FILEVET_WEBHOOK_HOSTS", raising=False)
    client, _ = _client()
    url = "/v1/scans?callback=https://example.invalid/hook"
    assert client.post(url, content=b"x", headers=HEADERS).status_code == 400


def test_info_endpoints(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FILEVET_CLAMD", raising=False)
    client, _ = _client()
    assert client.get("/healthz").json() == {"status": "ok"}
    assert client.get("/readyz").json() == {"queue": True}
    names = {a["name"] for a in client.get("/v1/analyzers", headers=HEADERS).json()}
    assert "ai.hidden_content" in names
    policies = client.get("/v1/policies", headers=HEADERS).json()
    assert policies == {"active": "default", "built_in": ["default", "strict", "ai-ingestion"]}
    assert "access-control-allow-origin" not in client.get("/healthz").headers


def test_readyz_reports_clamav_down(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("FILEVET_CLAMD", f"unix:{tmp_path / 'none.sock'}")
    client, _ = _client()
    response = client.get("/readyz")
    assert (response.status_code, response.json()["clamav"]) == (503, False)


def test_cors_only_when_configured() -> None:
    client, _ = _client(cors_origins=["https://app.example"])
    response = client.get("/healthz", headers={"Origin": "https://app.example"})
    assert response.headers["access-control-allow-origin"] == "https://app.example"


def test_settings_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FILEVET_API_KEYS", "a, b")
    monkeypatch.setenv("FILEVET_SYNC_MAX_BYTES", "10")
    settings = api.Settings.from_env()
    assert (settings.api_keys, settings.sync_max_bytes) == (frozenset({"a", "b"}), 10)


def test_committed_openapi_is_current() -> None:
    client, _ = _client()
    assert json.loads(OPENAPI.read_text()) == client.get("/openapi.json").json()


def test_busy_scan_slots_return_503(monkeypatch: pytest.MonkeyPatch) -> None:
    client, _ = _client()
    monkeypatch.setattr(api.asyncio.Semaphore, "locked", lambda self: True)
    assert client.post("/v1/scans", content=b"x", headers=HEADERS).status_code == 503
