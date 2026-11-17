# filevet

filevet is a self-hosted scanner for the files finance teams receive: invoices, bank statements, KYC documents and payment files. It checks them for security risks before anyone opens them or feeds them to another system.

Several independent analyzers read each file. They look for active content and known malware, attacks on the parsers that will read the file, signs that a document was edited after it was issued, financial data that doesn't add up, and text hidden from people but read by an LLM. Their findings go into one JSON report, and a policy turns them into a verdict: `block`, `review`, `pass_with_findings` or `pass`.

filevet runs as a CLI, a Python library, a REST API with async workers, or a Helm release on Kubernetes. It never runs, renders or uploads the files it scans, and each analyzer works in its own sandboxed worker.

```sh
pipx install filevet
filevet scan statement.pdf
```

## Where to go next

- [Getting started](getting-started.md) installs filevet and runs a first scan with the CLI, Docker, the API or Helm.
- [Pipeline and findings](architecture.md) explains how a scan works and what a finding contains.
- [Policies](policies.md) and the [policy cookbook](cookbook.md) show how to tune verdicts.
- The [rule reference](rules/index.md) has a page for every rule.
- The [security model](security-model.md) describes what the sandbox guarantees and where it stops.
- [API stability](stability.md) lists what 1.x promises not to break.
