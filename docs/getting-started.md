# Getting started

filevet needs Python 3.11 or newer on Linux or macOS. The stronger sandbox backends need Linux.

## CLI

```sh
pipx install filevet
# or
uv tool install filevet

filevet scan statement.pdf
```

The report goes to stdout as JSON. For a quick look at a terminal, use the table format:

```sh
filevet scan --format table invoice.pdf receipts.zip
```

The exit code follows the verdict, so scripts and CI jobs don't have to parse the report:

| Code | Meaning |
| --- | --- |
| `0` | `pass` or `pass_with_findings` |
| `1` | `review` |
| `2` | `block` |
| `3` | Usage error, such as a missing file, a file over the size limit or an invalid policy |
| `4` | Internal error in filevet |

`--policy strict` or `--policy ./our-policy.yaml` picks another [policy](policies.md). `filevet --help` lists every command.

## Docker

Run the image without network access and with the file mounted read-only:

```sh
docker run --rm --network none --read-only --tmpfs /tmp \
  -v "$PWD:/in:ro" ghcr.io/pablodt00/filevet scan /in/statement.pdf
```

The Compose file in the repository adds ClamAV as a sidecar and shares its socket with filevet:

```sh
docker compose --profile clamav up -d clamav
docker compose run --rm filevet scan /in/statement.pdf
```

filevet alone needs about 200 MB of RAM. ClamAV needs 1 to 2 GB more for its signature database.

## REST API

Install the `server` extra, set an API key and start the server:

```sh
pip install 'filevet[server]'
export FILEVET_API_KEYS="$(printf %s "$MY_KEY" | sha256sum | cut -d' ' -f1)"
filevet serve --host 127.0.0.1 --port 8000

curl -H "Authorization: Bearer $MY_KEY" --data-binary @invoice.pdf \
  "http://localhost:8000/v1/scans?name=invoice.pdf"
```

Small uploads are answered with the report. Larger ones are queued for a `filevet worker`. [REST API](api.md) covers the endpoints, the queue and every setting.

## Kubernetes

The Helm chart runs the API, the workers, Redis and optionally ClamAV, with worker egress blocked by a `NetworkPolicy`. [Kubernetes](kubernetes.md) has the install steps and a local quickstart with `kind`.

## Python

```python
from filevet import Policy, scan

report = scan("invoice.pdf", policy=Policy.load("strict"))
print(report.verdict, report.decision.reason)
```

`ascan` does the same without blocking an event loop, and `extract_text(path, visible_only=True)` returns only the text a person would see.
