# Integrations

## GitHub Action

The repository is a GitHub Action. It scans the documents a pull request adds or changes and uploads the findings to code scanning as SARIF.

```yaml
jobs:
  filevet:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: pablodt00/filevet@v1  # pin to a release tag or commit
        with:
          policy: strict
```

| Input | Default | Effect |
| --- | --- | --- |
| `pattern` | common document extensions | Extended regular expression for the paths to scan |
| `policy` | `default` | Built-in policy name or path to a policy file |
| `fail-on` | `block` | Severity or verdict that fails the step |
| `version` | latest | filevet version to install from PyPI |

The action skips symbolic links and deleted files, and passes file names after `--` so a name can't be read as an option.

## pre-commit

```yaml
repos:
  - repo: https://github.com/pablodt00/filevet
    rev: v1.0.0
    hooks:
      - id: filevet
```

The hook fails the commit when a staged document gets a `block` verdict.

## Other CI systems

Any CI can run the CLI. Pick the output with `--format`:

| Format | For |
| --- | --- |
| `sarif` | GitHub code scanning and other SARIF 2.1.0 tools. Each rule links to its page in the rule reference |
| `junit` | CI dashboards. One test case per file, failed on `review` or `block` |
| `markdown` | Pull request comments |
| `table` | People at a terminal |

```sh
filevet scan --format junit --output filevet.xml --fail-on review -- docs/*.pdf
```

`--fail-on <severity|verdict>` makes the exit code `1` when any file reaches that severity or verdict and `0` otherwise.

## Python applications

The `examples/` directory in the repository has three small integrations:

| Example | Does |
| --- | --- |
| `fastapi_upload.py` | An upload endpoint that scans with `ascan` and refuses blocked files |
| `s3_quarantine.py` | An S3 event handler that moves blocked or reviewed files to a quarantine bucket |
| `rag_ingestion.py` | Scans with the `ai-ingestion` policy and indexes only the visible text |

## Docker Compose

`docker-compose.yml` runs the API, a worker, Redis and ClamAV. The worker and Redis sit on an internal network with no route out.

```sh
export FILEVET_SPOOL_KEY=... FILEVET_API_KEYS=...
docker compose up -d
```

See [REST API](api.md) for the settings and [Kubernetes](kubernetes.md) for the Helm chart.
