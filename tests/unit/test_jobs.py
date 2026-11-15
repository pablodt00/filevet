import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.fernet import Fernet

from filevet.interfaces import jobs
from filevet.policies import Policy


class FakeRedis:
    def __init__(self) -> None:
        self.data: dict[str, Any] = {}
        self.lists: dict[str, list[bytes]] = {}

    def pipeline(self) -> "FakeRedis":
        return self

    def execute(self) -> None:
        pass

    def set(self, key: str, value: str | bytes, ex: int) -> None:
        self.data[key] = value.encode() if isinstance(value, str) else value

    def get(self, key: str) -> bytes | None:
        return self.data.get(key)

    def getdel(self, key: str) -> bytes | None:
        return self.data.pop(key, None)

    def lpush(self, key: str, value: str) -> None:
        self.lists.setdefault(key, []).insert(0, value.encode())

    def brpop(self, keys: list[str], timeout: int) -> tuple[bytes, bytes] | None:
        items = self.lists.get(keys[0])
        return (keys[0].encode(), items.pop()) if items else None

    def hincrbyfloat(self, key: str, field: str, amount: float) -> None:
        hash_ = self.data.setdefault(key, {})
        hash_[field.encode()] = str(float(hash_.get(field.encode(), 0)) + amount).encode()

    def hgetall(self, key: str) -> dict[bytes, bytes]:
        return self.data.get(key, {})

    def ping(self) -> bool:
        return True


def _queue(backend: jobs.Backend) -> jobs.Queue:
    return jobs.Queue(backend, Fernet.generate_key(), 60, Policy.load("default"))


def _redis() -> jobs.RedisBackend:
    backend = jobs.RedisBackend.__new__(jobs.RedisBackend)
    backend.redis = FakeRedis()  # type: ignore[assignment]
    return backend


@pytest.mark.parametrize("make", [jobs.MemoryBackend, _redis])
def test_round_trip(make: Any, benign_pdf: Path) -> None:
    q = _queue(make())
    q.submit("1" * 32, "benign.pdf", benign_pdf.read_bytes(), None)
    assert q.work_once(0.1)
    state = json.loads(q.backend.load("1" * 32) or "{}")
    assert (state["status"], state["report"]["artifacts"][0]["name"]) == ("done", "benign.pdf")
    assert q.backend.counters()['filevet_scans_total{verdict="pass"}'] == 1
    assert not q.work_once(0.1)
    assert q.backend.ping()


def test_spooled_upload_is_encrypted() -> None:
    backend = jobs.MemoryBackend()
    _queue(backend).submit("2" * 32, "secret.csv", b"IBAN DE89370400440532013000", None)
    stored = repr(backend.values)
    assert "DE89" not in stored and "secret.csv" not in stored


def test_expired_upload_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = jobs.MemoryBackend()
    q = jobs.Queue(backend, Fernet.generate_key(), 0, Policy.load("default"))
    q.submit("3" * 32, "a", b"x", None)
    q.retention_s = 60
    assert q.work_once(0.1)
    assert json.loads(backend.load("3" * 32) or "{}")["status"] == "error"


def test_result_expires() -> None:
    backend = jobs.MemoryBackend()
    backend.store("4" * 32, "{}", 0)
    assert backend.load("4" * 32) is None


def test_exposition_format() -> None:
    text = jobs.exposition({'filevet_scans_total{verdict="block"}': 2.0})
    assert "# TYPE filevet_scans_total counter" in text
    assert 'filevet_scans_total{verdict="block"} 2\n' in text


def test_label_escaping() -> None:
    assert jobs._label('a"b\\c\nd') == 'a\\"b\\\\c d'


def test_webhook_is_signed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FILEVET_WEBHOOK_HOSTS", "hooks.example")
    monkeypatch.setenv("FILEVET_WEBHOOK_SECRET", "s3cret")
    sent: list[Any] = []

    class Response:
        def __enter__(self) -> "Response":
            return self

        def __exit__(self, *args: object) -> None:
            pass

    monkeypatch.setattr(jobs._OPENER, "open", lambda r, timeout: sent.append(r) or Response())
    jobs.deliver("https://hooks.example/scan", '{"status":"done"}')
    jobs.deliver("http://hooks.example/scan", "{}")
    jobs.deliver("https://other.example/scan", "{}")
    [request] = sent
    expected = hmac.new(b"s3cret", b'{"status":"done"}', hashlib.sha256).hexdigest()
    assert request.get_header("X-filevet-signature") == f"sha256={expected}"


def test_webhook_needs_a_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FILEVET_WEBHOOK_HOSTS", "hooks.example")
    monkeypatch.delenv("FILEVET_WEBHOOK_SECRET", raising=False)
    assert not jobs.webhook_allowed("https://hooks.example/x")


def test_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FILEVET_REDIS_URL", "redis://localhost:1")
    monkeypatch.delenv("FILEVET_SPOOL_KEY", raising=False)
    with pytest.raises(ValueError, match="FILEVET_SPOOL_KEY"):
        jobs.from_env()
    monkeypatch.delenv("FILEVET_REDIS_URL")
    q = jobs.from_env()
    assert isinstance(q.backend, jobs.MemoryBackend)
    with pytest.raises(ValueError, match="FILEVET_REDIS_URL"):
        jobs.work_forever(q)


def test_bad_job_does_not_stop_the_worker() -> None:
    backend = jobs.MemoryBackend()
    backend.submit("5" * 32, b"not a fernet token", 60)
    q = _queue(backend)
    assert q.work_once(0.1)
    assert json.loads(backend.load("5" * 32) or "{}")["status"] == "error"


def test_work_safely_survives_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    q = _queue(jobs.MemoryBackend())
    monkeypatch.setattr(q, "work_once", lambda timeout: 1 / 0)
    monkeypatch.setattr(jobs.time, "sleep", lambda s: None)
    jobs.work_safely(q, 0)


def test_malformed_port_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FILEVET_WEBHOOK_HOSTS", "hooks.example")
    monkeypatch.setenv("FILEVET_WEBHOOK_SECRET", "s")
    assert jobs.webhook_allowed("https://hooks.example/x")
    assert not jobs.webhook_allowed("https://hooks.example:x/")


def test_webhook_errors_are_swallowed(monkeypatch: pytest.MonkeyPatch) -> None:
    import http.client

    monkeypatch.setenv("FILEVET_WEBHOOK_HOSTS", "hooks.example")
    monkeypatch.setenv("FILEVET_WEBHOOK_SECRET", "s")

    def fail(request: Any, timeout: float) -> None:
        raise http.client.BadStatusLine("x")

    monkeypatch.setattr(jobs._OPENER, "open", fail)
    jobs.deliver("https://hooks.example/x", "{}")


def test_webhooks_do_not_follow_redirects() -> None:
    import urllib.request

    request = urllib.request.Request("https://hooks.example/x", data=b"{}", method="POST")
    handler = jobs._NoRedirect()
    assert (
        handler.redirect_request(request, None, 302, "Found", {}, "http://169.254.169.254/") is None
    )
