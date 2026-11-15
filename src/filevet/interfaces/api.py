import asyncio
import hashlib
import hmac
import json
import os
import threading
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated, Any
from uuid import uuid4

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Path, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel
from starlette.datastructures import UploadFile
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from filevet.analyzers.malware.clamav import ping as clamd_ping
from filevet.core.analyzer import load_analyzers, supported_types
from filevet.core.errors import ScanError
from filevet.core.limits import DEFAULT_LIMITS
from filevet.core.pipeline import scan
from filevet.interfaces import jobs
from filevet.policies import BUILT_IN

MULTIPART_OVERHEAD = 1 << 16
SCAN_ID = r"^[0-9a-f]{32}$"
MAX_CLIENTS = 10_000


class Settings(BaseModel):
    api_keys: frozenset[str] = frozenset()
    no_auth: bool = False
    sync_max_bytes: int = 5 << 20
    max_upload_bytes: int = DEFAULT_LIMITS.max_input_bytes
    rate_per_minute: int = 60
    request_timeout_s: float = 120
    cors_origins: list[str] = []

    @classmethod
    def from_env(cls) -> "Settings":
        env = os.environ
        values: dict[str, Any] = {
            "api_keys": _split(env.get("FILEVET_API_KEYS", "")),
            "no_auth": env.get("FILEVET_API_NO_AUTH") == "1",
            "cors_origins": _split(env.get("FILEVET_CORS_ORIGINS", "")),
        }
        for field, var in [
            ("sync_max_bytes", "FILEVET_SYNC_MAX_BYTES"),
            ("max_upload_bytes", "FILEVET_MAX_UPLOAD_BYTES"),
            ("rate_per_minute", "FILEVET_RATE_LIMIT"),
            ("request_timeout_s", "FILEVET_REQUEST_TIMEOUT_S"),
        ]:
            if var in env:
                values[field] = env[var]
        return cls.model_validate(values)


def create_app(
    settings: Settings | None = None, queue: jobs.Queue | None = None, worker: bool | None = None
) -> FastAPI:
    settings = settings or Settings.from_env()
    if not settings.api_keys and not settings.no_auth:
        raise ValueError("set FILEVET_API_KEYS, or FILEVET_API_NO_AUTH=1 behind an mTLS proxy")
    q = queue or jobs.from_env()
    if worker is None:
        worker = isinstance(q.backend, jobs.MemoryBackend)
    windows: dict[str, tuple[int, int]] = {}
    slots = asyncio.Semaphore(os.cpu_count() or 1)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        stop = threading.Event()
        if worker:
            threading.Thread(target=_work, args=(q, stop), daemon=True).start()
        yield
        stop.set()

    app = FastAPI(title="filevet", version="1", lifespan=lifespan, docs_url=None, redoc_url=None)
    app.add_middleware(
        _Guard,
        max_bytes=settings.max_upload_bytes + MULTIPART_OVERHEAD,
        timeout=settings.request_timeout_s,
    )
    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_methods=["GET", "POST"],
            allow_headers=["Authorization", "Content-Type", "X-API-Key"],
        )

    async def authorize(request: Request) -> str:
        if settings.no_auth:
            who = request.client.host if request.client else "anonymous"
        else:
            key = request.headers.get("x-api-key") or request.headers.get("authorization", "")
            key = key.removeprefix("Bearer ").strip()
            who = hashlib.sha256(key.encode()).hexdigest()
            if not key or not any(hmac.compare_digest(who, k) for k in settings.api_keys):
                raise HTTPException(401, "missing or unknown API key")
        window = int(time.monotonic() // 60)
        start, count = windows.get(who, (window, 0))
        count = count + 1 if start == window else 1
        if len(windows) > MAX_CLIENTS:
            windows.clear()
        windows[who] = (window, count)
        if count > settings.rate_per_minute:
            raise HTTPException(429, "rate limit exceeded")
        return who

    Auth = Annotated[str, Depends(authorize)]

    @app.post("/v1/scans", responses={202: {"description": "Queued for an async worker"}})
    async def create_scan(
        request: Request, _: Auth, name: str = "", callback: str | None = None
    ) -> JSONResponse:
        if callback and not jobs.webhook_allowed(callback):
            raise HTTPException(400, "callback must be https on a host in FILEVET_WEBHOOK_HOSTS")
        if request.headers.get("content-type", "").startswith("multipart/form-data"):
            async with request.form(max_files=1, max_fields=1) as form:
                upload = form.get("file")
                if not isinstance(upload, UploadFile):
                    raise HTTPException(400, "send the file in a form field named file")
                data = await upload.read(settings.max_upload_bytes + 1)
                name = name or upload.filename or ""
        else:
            data = await request.body()
        if len(data) > settings.max_upload_bytes:
            raise HTTPException(413, "upload too large")
        if len(data) > settings.sync_max_bytes:
            scan_id = uuid4().hex
            q.submit(scan_id, name, data, callback)
            return JSONResponse(
                {"id": scan_id, "status": "queued"},
                status_code=202,
                headers={"Location": f"/v1/scans/{scan_id}"},
            )
        if slots.locked():
            raise HTTPException(503, "all scan slots are busy, retry later")
        async with slots:
            try:
                report = await run_in_threadpool(scan, data, name=name, policy=q.policy)
            except ScanError as exc:
                raise HTTPException(413, str(exc)) from None
        jobs.record(q.backend, report)
        return JSONResponse(
            {"id": None, "status": "done", "report": report.model_dump(mode="json")}
        )

    @app.get("/v1/scans/{scan_id}")
    async def get_scan(scan_id: Annotated[str, Path(pattern=SCAN_ID)], _: Auth) -> JSONResponse:
        state = q.backend.load(scan_id)
        if state is None:
            raise HTTPException(404, "no such scan, or its result has expired")
        return JSONResponse(json.loads(state))

    @app.get("/v1/analyzers")
    async def analyzers(_: Auth) -> list[dict[str, Any]]:
        return [
            {"name": a.name, "version": a.version, "types": supported_types(a)}
            for a in load_analyzers()
        ]

    @app.get("/v1/policies")
    async def policies(_: Auth) -> dict[str, Any]:
        return {"active": q.policy.name, "built_in": list(BUILT_IN)}

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz")
    async def readyz() -> JSONResponse:
        checks = {"queue": await run_in_threadpool(q.backend.ping)}
        if address := os.environ.get("FILEVET_CLAMD"):
            checks["clamav"] = await run_in_threadpool(clamd_ping, address, 2)
        return JSONResponse(checks, status_code=200 if all(checks.values()) else 503)

    @app.get("/metrics", response_class=PlainTextResponse)
    async def metrics() -> PlainTextResponse:
        counters = await run_in_threadpool(q.backend.counters)
        return PlainTextResponse(jobs.exposition(counters), media_type="text/plain; version=0.0.4")

    return app


class _Guard:
    def __init__(self, app: ASGIApp, max_bytes: int, timeout: float) -> None:
        self.app, self.max_bytes, self.timeout = app, max_bytes, timeout

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        seen, started = 0, False

        async def limited() -> Message:
            nonlocal seen
            message = await receive()
            seen += len(message.get("body", b""))
            if seen > self.max_bytes:
                raise HTTPException(413, "upload too large")
            return message

        async def tracked(message: Message) -> None:
            nonlocal started
            started = started or message["type"] == "http.response.start"
            await send(message)

        try:
            await asyncio.wait_for(self.app(scope, limited, tracked), self.timeout)
        except TimeoutError:
            if not started:
                await JSONResponse({"detail": "request timed out"}, 504)(scope, receive, send)


def _work(q: jobs.Queue, stop: threading.Event) -> None:
    while not stop.is_set():
        jobs.work_safely(q, 1)


def _split(value: str) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


def serve(host: str, port: int) -> None:
    uvicorn.run(create_app(), host=host, port=port, server_header=False, timeout_keep_alive=5)
