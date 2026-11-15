import hashlib
import hmac
import json
import logging
import os
import queue
import threading
import time
import urllib.request
from typing import Any, Protocol
from urllib.parse import urlsplit

from cryptography.fernet import Fernet

from filevet.core.errors import ScanError
from filevet.core.pipeline import scan
from filevet.core.report import Report
from filevet.policies import Policy

log = logging.getLogger("filevet")
WEBHOOK_TIMEOUT_S = 10


class Backend(Protocol):
    def submit(self, scan_id: str, token: bytes, ttl: int) -> None: ...
    def take(self, timeout: float) -> tuple[str, bytes | None] | None: ...
    def store(self, scan_id: str, state: str, ttl: int) -> None: ...
    def load(self, scan_id: str) -> str | None: ...
    def count(self, key: str, amount: float) -> None: ...
    def counters(self) -> dict[str, float]: ...
    def ping(self) -> bool: ...


class MemoryBackend:
    def __init__(self) -> None:
        self.jobs: queue.Queue[str] = queue.Queue()
        self.values: dict[str, tuple[float, Any]] = {}
        self.metrics: dict[str, float] = {}
        self.lock = threading.Lock()

    def submit(self, scan_id: str, token: bytes, ttl: int) -> None:
        with self.lock:
            self.values[f"blob:{scan_id}"] = (time.monotonic() + ttl, token)
        self.store(scan_id, json.dumps({"id": scan_id, "status": "queued"}), ttl)
        self.jobs.put(scan_id)

    def take(self, timeout: float) -> tuple[str, bytes | None] | None:
        try:
            scan_id = self.jobs.get(timeout=timeout)
        except queue.Empty:
            return None
        with self.lock:
            expires, token = self.values.pop(f"blob:{scan_id}", (0.0, None))
        return scan_id, token if expires > time.monotonic() else None

    def store(self, scan_id: str, state: str, ttl: int) -> None:
        with self.lock:
            now = time.monotonic()
            self.values = {k: v for k, v in self.values.items() if v[0] > now}
            self.values[f"scan:{scan_id}"] = (now + ttl, state)

    def load(self, scan_id: str) -> str | None:
        with self.lock:
            expires, state = self.values.get(f"scan:{scan_id}", (0.0, None))
        return state if expires > time.monotonic() else None

    def count(self, key: str, amount: float) -> None:
        with self.lock:
            self.metrics[key] = self.metrics.get(key, 0) + amount

    def counters(self) -> dict[str, float]:
        with self.lock:
            return dict(self.metrics)

    def ping(self) -> bool:
        return True


class RedisBackend:
    def __init__(self, url: str) -> None:
        import redis

        self.redis = redis.Redis.from_url(url, socket_timeout=30)

    def submit(self, scan_id: str, token: bytes, ttl: int) -> None:
        state = json.dumps({"id": scan_id, "status": "queued"})
        pipe = self.redis.pipeline()
        pipe.set(f"filevet:blob:{scan_id}", token, ex=ttl)
        pipe.set(f"filevet:scan:{scan_id}", state, ex=ttl)
        pipe.lpush("filevet:queue", scan_id)
        pipe.execute()

    def take(self, timeout: float) -> tuple[str, bytes | None] | None:
        popped = self.redis.brpop(["filevet:queue"], timeout=max(1, int(timeout)))
        if popped is None:
            return None
        scan_id = _text(popped[1])
        token = self.redis.getdel(f"filevet:blob:{scan_id}")
        return scan_id, token.encode() if isinstance(token, str) else token

    def store(self, scan_id: str, state: str, ttl: int) -> None:
        self.redis.set(f"filevet:scan:{scan_id}", state, ex=ttl)

    def load(self, scan_id: str) -> str | None:
        value = self.redis.get(f"filevet:scan:{scan_id}")
        return _text(value) if value is not None else None

    def count(self, key: str, amount: float) -> None:
        self.redis.hincrbyfloat("filevet:metrics", key, amount)

    def counters(self) -> dict[str, float]:
        return {_text(k): float(v) for k, v in self.redis.hgetall("filevet:metrics").items()}

    def ping(self) -> bool:
        try:
            return bool(self.redis.ping())
        except Exception:
            return False


class Queue:
    def __init__(self, backend: Backend, key: bytes, retention_s: int, policy: Policy) -> None:
        self.backend = backend
        self.fernet = Fernet(key)
        self.retention_s = retention_s
        self.policy = policy

    def submit(self, scan_id: str, name: str, data: bytes, callback: str | None) -> None:
        header = json.dumps({"name": name, "callback": callback}).encode()
        token = self.fernet.encrypt(header + b"\n" + data)
        self.backend.submit(scan_id, token, self.retention_s)

    def work_once(self, timeout: float = 5) -> bool:
        job = self.backend.take(timeout)
        if job is None:
            return False
        scan_id, token = job
        if token is None:
            self._store(scan_id, "error", error="the upload expired before a worker took it")
            return True
        try:
            header, _, data = self.fernet.decrypt(token).partition(b"\n")
            meta = json.loads(header)
            report = scan(data, name=meta["name"], policy=self.policy)
        except ScanError as exc:
            self._store(scan_id, "error", error=str(exc))
            return True
        except Exception as exc:
            self._store(scan_id, "error", error=f"internal error: {type(exc).__name__}")
            return True
        record(self.backend, report)
        body = self._store(scan_id, "done", report=report.model_dump(mode="json"))
        if meta["callback"]:
            deliver(meta["callback"], body)
        return True

    def _store(self, scan_id: str, status: str, **fields: object) -> str:
        state = json.dumps({"id": scan_id, "status": status, **fields})
        self.backend.store(scan_id, state, self.retention_s)
        return state


def record(backend: Backend, report: Report) -> None:
    backend.count(f'filevet_scans_total{{verdict="{report.verdict}"}}', 1)
    for run in report.analyzer_runs:
        name = _label(run.analyzer)
        backend.count(f'filevet_analyzer_runs_total{{analyzer="{name}",status="{run.status}"}}', 1)
        backend.count(
            f'filevet_analyzer_duration_seconds_sum{{analyzer="{name}"}}', run.duration_ms / 1000
        )
        backend.count(f'filevet_analyzer_duration_seconds_count{{analyzer="{name}"}}', 1)


def exposition(counters: dict[str, float]) -> str:
    kinds = {
        "filevet_scans_total": "counter",
        "filevet_analyzer_runs_total": "counter",
        "filevet_analyzer_duration_seconds": "summary",
    }
    lines = [f"# TYPE {metric} {kind}" for metric, kind in kinds.items()]
    lines += [f"{key} {value:g}" for key, value in sorted(counters.items())]
    return "\n".join(lines) + "\n"


def webhook_allowed(url: str) -> bool:
    hosts = {h.strip() for h in os.environ.get("FILEVET_WEBHOOK_HOSTS", "").split(",") if h.strip()}
    try:
        parts = urlsplit(url)
        parts.port  # noqa: B018 - raises ValueError on a malformed port
    except ValueError:
        return False
    return (
        bool(os.environ.get("FILEVET_WEBHOOK_SECRET"))
        and parts.scheme == "https"
        and parts.hostname in hosts
    )


def deliver(url: str, body: str) -> None:
    if not webhook_allowed(url):
        return
    secret = os.environ["FILEVET_WEBHOOK_SECRET"].encode()
    signature = hmac.new(secret, body.encode(), hashlib.sha256).hexdigest()
    request = urllib.request.Request(  # noqa: S310 - webhook_allowed limits it to https on listed hosts
        url,
        data=body.encode(),
        headers={"Content-Type": "application/json", "X-Filevet-Signature": f"sha256={signature}"},
        method="POST",
    )
    try:
        with _OPENER.open(request, timeout=WEBHOOK_TIMEOUT_S):
            pass
    except Exception as exc:
        log.warning(json.dumps({"event": "webhook_failed", "error": type(exc).__name__}))


def from_env() -> Queue:
    url = os.environ.get("FILEVET_REDIS_URL")
    key = os.environ.get("FILEVET_SPOOL_KEY")
    if url and not key:
        raise ValueError("FILEVET_SPOOL_KEY is required with FILEVET_REDIS_URL")
    backend: Backend = RedisBackend(url) if url else MemoryBackend()
    return Queue(
        backend,
        key.encode() if key else Fernet.generate_key(),
        int(os.environ.get("FILEVET_RETENTION_S", "3600")),
        Policy.load(os.environ.get("FILEVET_POLICY", "default")),
    )


def work_forever(q: Queue) -> None:
    if isinstance(q.backend, MemoryBackend):
        raise ValueError("set FILEVET_REDIS_URL so the worker shares a queue with the API")
    while True:
        work_safely(q, 5)


def work_safely(q: Queue, timeout: float) -> None:
    try:
        q.work_once(timeout)
    except Exception as exc:
        log.warning(json.dumps({"event": "worker_error", "error": type(exc).__name__}))
        time.sleep(1)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _label(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def _text(value: bytes | str) -> str:
    return value.decode() if isinstance(value, bytes) else value
