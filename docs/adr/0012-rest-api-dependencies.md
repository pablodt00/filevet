# 12. Serve the REST API with FastAPI and queue async scans on Redis

Date: 2026-11-15

## Status

Accepted

## Context

Phase 3 turns filevet into a service: `filevet serve` takes uploads over HTTP, answers small files right away, and hands large ones to workers through a queue. The issue names FastAPI and uvicorn for the API and Redis as the default queue, with the queue behind an interface so Kafka or SQS can be added later.

Most of Phase 3 needs nothing new. The policy engine reads YAML with PyYAML ([ADR 11](0011-integrity-dependencies.md)). SARIF, JUnit XML and Markdown are written with the standard library. Uploads waiting for a worker are encrypted with Fernet from `cryptography`, which pyHanko already brings in. Prometheus metrics are a few counters in the text exposition format, so `prometheus_client` isn't needed either.

People who embed filevet as a library shouldn't have to install a web server.

## Decision

The server dependencies go in an optional extra, `filevet[server]`:

| Package | License | Used for |
| --- | --- | --- |
| `fastapi` | MIT | The `/v1` API, request validation and the OpenAPI spec |
| `uvicorn` | BSD-3-Clause | The ASGI server behind `filevet serve` |
| `python-multipart` | Apache-2.0 | `multipart/form-data` uploads |
| `redis` | MIT | The Redis queue backend used by `filevet worker` |

FastAPI brings `starlette`, `anyio`, `idna`, `typing-inspection` and `opentelemetry-api`, and uvicorn brings `click` and `h11`. Their licenses (MIT, BSD-3-Clause, Apache-2.0) are already on the allow list. The license gate in `.github/workflows/security.yml` now installs all extras, so it checks these too. The dev group includes the extra, and `httpx` is added there for FastAPI's test client.

The queue is a small `Backend` protocol in `filevet/interfaces/jobs.py` with two implementations. `RedisBackend` uses plain Redis lists and keys with expiry times. `MemoryBackend` runs in the API process for development and tests. We don't use `rq` or `arq`, because both serialize jobs with `pickle` by default, and filevet never unpickles anything. A Redis list of scan IDs is enough.

## Consequences

`pip install filevet` stays as before. `pip install filevet[server]` and the Docker image add about 10 MB. Workers and the API must share `FILEVET_SPOOL_KEY` to decrypt queued uploads. Adding Kafka or SQS means writing another `Backend` with the same six methods.
