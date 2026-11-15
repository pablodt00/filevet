# REST API

`filevet serve` runs an HTTP API. Install it with the `server` extra:

```sh
pip install 'filevet[server]'
export FILEVET_API_KEYS="$(printf %s "$MY_KEY" | sha256sum | cut -d' ' -f1)"
filevet serve --host 0.0.0.0 --port 8000
```

The OpenAPI spec is in [openapi.json](openapi.json) and at `/openapi.json` on a running server.

## Endpoints

| Method and path | Auth | Does |
| --- | --- | --- |
| `POST /v1/scans` | yes | Scans an upload, sent as a raw body or as a `multipart/form-data` field named `file`. `?name=` sets the file name for a raw body, and `?callback=` asks for a webhook |
| `GET /v1/scans/{id}` | yes | Status (`queued`, `done` or `error`) and the report of an async scan |
| `GET /v1/analyzers` | yes | Registered analyzers and the types they support |
| `GET /v1/policies` | yes | The active policy and the built-in ones |
| `GET /healthz` | no | The process is up |
| `GET /readyz` | no | The queue answers, and so does ClamAV when `FILEVET_CLAMD` is set. `503` if not |
| `GET /metrics` | no | Prometheus metrics |

Uploads up to `FILEVET_SYNC_MAX_BYTES` are scanned straight away and answered with `200` and the report. The API runs at most one synchronous scan per CPU and answers `503` when all of them are busy. Larger uploads get `202`, a scan ID and a `Location` header. A worker scans them, and `GET /v1/scans/{id}` returns the report until it expires.

```sh
curl -H "Authorization: Bearer $MY_KEY" --data-binary @invoice.pdf \
  "http://localhost:8000/v1/scans?name=invoice.pdf"
```

## Async mode

```sh
docker compose up -d api worker redis clamav
```

The API puts each large upload in Redis, encrypted with Fernet under `FILEVET_SPOOL_KEY`, and pushes its ID onto a queue. A `filevet worker` takes the ID, deletes the upload from Redis as it reads it, scans it in its own temp directory, and stores the report for `FILEVET_RETENTION_S` seconds. The API never parses an async upload. Run as many workers as you need.

Without `FILEVET_REDIS_URL` the API keeps the queue in memory and runs one worker thread in its own process. That's meant for development.

The queue is the `Backend` protocol in `filevet/interfaces/jobs.py`. Another backend, such as Kafka or SQS, implements the same methods.

## Webhooks

With `?callback=https://…`, the worker POSTs the finished result to that URL. The body is signed with HMAC-SHA256 and the signature is sent as `X-Filevet-Signature: sha256=<hex>`. Check it with `FILEVET_WEBHOOK_SECRET` before trusting the body. Only `https` URLs on hosts listed in `FILEVET_WEBHOOK_HOSTS` are accepted, and redirects aren't followed, so the API can't be used to make requests to arbitrary hosts. In the Compose file the worker sits on an internal network with no route out, so webhooks need a network with egress added to the `worker` service.

## Metrics

| Metric | Labels |
| --- | --- |
| `filevet_scans_total` | `verdict` |
| `filevet_analyzer_runs_total` | `analyzer`, `status` (`ok`, `error`, `timeout`) |
| `filevet_analyzer_duration_seconds` (summary, `_sum` and `_count`) | `analyzer` |

With Redis, the counters live in Redis, so every API replica reports the totals for all workers.

## Configuration

| Variable | Default | Effect |
| --- | --- | --- |
| `FILEVET_API_KEYS` | | Comma-separated SHA-256 hashes of the API keys. Keys are sent as `Authorization: Bearer <key>` or `X-API-Key` |
| `FILEVET_API_NO_AUTH` | | `1` turns API keys off, for use behind a proxy that does mTLS. The server won't start with neither set |
| `FILEVET_SYNC_MAX_BYTES` | 5 MiB | Uploads up to this size are scanned synchronously |
| `FILEVET_MAX_UPLOAD_BYTES` | 50 MiB | Larger uploads get `413` |
| `FILEVET_RATE_LIMIT` | 60 | Requests per minute per API key (per client address without keys) |
| `FILEVET_REQUEST_TIMEOUT_S` | 120 | Every request is cut off with `504` after this |
| `FILEVET_CORS_ORIGINS` | | Comma-separated origins. CORS is off when empty |
| `FILEVET_POLICY` | `default` | Policy name or file for every scan |
| `FILEVET_REDIS_URL` | | Redis for the async queue, for example `redis://redis:6379/0` |
| `FILEVET_SPOOL_KEY` | | Fernet key shared by the API and the workers. Required with Redis. Generate one with `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |
| `FILEVET_RETENTION_S` | 3600 | How long results and queued uploads are kept |
| `FILEVET_WEBHOOK_HOSTS` | | Hosts that callbacks may go to |
| `FILEVET_WEBHOOK_SECRET` | | HMAC key for webhook signatures. Webhooks are off without it |

## Security notes

- API keys are stored only as SHA-256 hashes and compared in constant time.
- Request bodies are counted as they arrive and cut off past the upload limit, with or without a `Content-Length`.
- Nothing is written to disk by the API except the scan's private temp directory, which is deleted afterwards. Queued uploads stay encrypted in Redis until a worker takes them.
- The interactive docs pages (`/docs`, `/redoc`) are off, because they load scripts from a CDN.
- The rate limit is per process. Put a proxy in front for limits shared across replicas.
- The Compose file publishes the API on `127.0.0.1` only, and Redis is capped at 2 GB without eviction, so a flood of queued uploads gets errors instead of pushing results out.
- The request timeout ends the HTTP request. A synchronous scan that's already running finishes in the background, within the per-analyzer timeouts.
