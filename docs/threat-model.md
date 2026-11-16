# Threat model

This covers the threats filevet looks for in files and the threats against filevet itself. Every file filevet reads may be hostile, so its own parsers are a target.

## Assets

- The host running filevet: its filesystem, network access, credentials and other workloads.
- The scanned files: they often hold personal and financial data, so their contents must not leak through logs, reports or temp files.
- The integrity of the report: a downstream system trusts the verdict. An attacker who can suppress findings or change the verdict can push a malicious file through.
- The release supply chain: the PyPI package, the container image and their signatures.

## Attackers

- The file author is the main attacker. They fully control the bytes of the file, and possibly the file name and declared type. They don't control filevet's configuration or the host. They may know exactly which version of filevet is running and craft files to target it.
- A supply chain attacker tries to get malicious code into filevet's dependencies, build or release.
- A malicious contributor submits a PR that weakens a check or adds a backdoor.

## Trust boundaries

```mermaid
flowchart LR
    subgraph Untrusted
        F[Uploaded file]
    end
    subgraph Pipeline["filevet pipeline (trusted)"]
        I[Ingest and identify]
        A[Aggregate and policy]
    end
    subgraph Sandbox["Analyzer workers (handle hostile data)"]
        P[Parsers and analyzers]
    end
    F --> I --> P -- findings --> A --> R[Report]
```

1. File → pipeline. Everything about the file is untrusted, including its name, size, declared type and every byte.
2. Pipeline → analyzer workers. Parsers are the most exposed code, so they run in isolated workers with time and memory limits. We assume a parser can be compromised by a crafted file.
3. Workers → aggregation. Findings coming back from a worker are data. They're validated against the `Finding` model, and their evidence is truncated and escaped before it reaches the report.

## What filevet must defend against

| Threat | Mitigation |
| --- | --- |
| Parser exploits (memory corruption in native libraries, logic bugs) | Each analyzer in its own process, one task per worker; the `nsjail` and `gvisor` backends add namespaces, a seccomp allow-list, a read-only root and dropped privileges, checked by escape tests in CI ([security model](security-model.md)); nightly coverage-guided fuzzing ([fuzzing](fuzzing.md)) |
| Denial of service: zip bombs, entity expansion, huge or deeply nested structures | Input size limit, per-analyzer timeout and memory cap, recursion depth, child count and expanded-size limits checked while streaming |
| XXE and network access from parsers | `defusedxml` or `lxml` with entities and network off; no network in the container; no network interfaces in the `nsjail` and `gvisor` sandboxes; a NetworkPolicy that denies worker egress in Kubernetes |
| Path traversal and symlinks during extraction | Entries are checked before extraction, symlinks are rejected, children are written only inside the private temp directory |
| Execution of embedded content | filevet never runs, renders or opens a file with an external program |
| Data leaking through logs or reports | Logs hold hashes, rule IDs and timings only; evidence is truncated and escaped (see [architecture](architecture.md#core-contracts)) |
| Injection into whatever reads the report (terminal escapes, HTML, CSV formulas) | Evidence is escaped; the table view strips control characters |
| Evasion: making an analyzer crash or time out to hide findings | A crash or timeout becomes a `high` severity finding, never a silent pass |
| Leftover files on disk | Temp files are deleted after every scan, including on error |
| Supply chain compromise | Locked dependencies, license and vulnerability checks in CI, signed releases with SBOMs, trusted publishing without stored tokens |
| Malicious PRs | Code owner review on every change, required CI checks, no real malware in the repository |
| Hidden instructions for AI pipelines (invisible text, metadata, Unicode smuggling) | `ai.*` rules on hidden and metadata text, `filevet extract --visible-only` for ingestion, the `ai-ingestion` policy |
| Pushing a file through by suppressing its findings | Suppressions name one rule and one file hash, need a reason and expire. Expired ones are ignored with a warning, and suppressed findings stay in the report |
| Abuse of the REST API: unauthenticated use, floods, oversized or slow uploads | API keys stored as hashes, per-key rate limit, body size counted while streaming, a timeout on every request, at most one synchronous scan per CPU |
| Uploads exposed at rest while queued | Encrypted with a key the API and workers share, deleted when a worker takes them, expired after the retention time; Redis runs without persistence in the Compose file |
| Server-side request forgery through webhooks | Callbacks only to `https` URLs on configured hosts, only when a signing secret is set, and without following redirects |
| A pull request steering the GitHub Action through file names or symlinks | Paths are passed after `--`, symlinks are skipped by the Action and refused by `filevet scan` |
| Active content surviving `filevet sanitize` | Sanitizing parses the file inside the sandbox, removes whole classes of content (all actions and annotations, not a list of bad ones), fails closed when it can't parse the file, and always reports what it removed ([sanitize](sanitize.md)) |
| Injection into SARIF, JUnit or Markdown consumers | Text is JSON-encoded, XML-escaped with control characters removed, or Markdown- and HTML-escaped |

## Out of scope

- An attacker who already controls the host or filevet's configuration.
- Malware that filevet has no rule for. A missed detection is a bug to fix, but filevet never claims to catch everything.
- What happens to the file after filevet hands back its report.
