# Security policy

filevet's job is to open hostile files, so a bug in filevet itself can expose the machine it runs on. Thanks for reporting security problems privately.

## Supported versions

While filevet is pre-1.0, only the latest minor release gets security fixes.

| Version | Supported |
| --- | --- |
| Latest 0.x minor | Yes |
| Older releases | No |

## Reporting a vulnerability

Use GitHub private vulnerability reporting: open the [Security tab](https://github.com/pablodt00/filevet/security) and click **Report a vulnerability**, or go straight to the [report form](https://github.com/pablodt00/filevet/security/advisories/new).

Please don't report vulnerabilities in public issues, discussions or pull requests.

## What to include

- The filevet version (`filevet version`) and how you installed it (pip, pipx, uv, Docker).
- The file type involved.
- A minimal way to reproduce the problem.
- What you expected and what happened.

Don't attach real malware or files with real personal or financial data. Describe how to build the test case instead, for example as a short script that generates it.

## What to expect

| Step | Target |
| --- | --- |
| Acknowledge your report | Within 7 days |
| Assess it and tell you whether we accept it | Within 14 days |
| Release a fix | Within 90 days |

We'll keep you updated, agree on a disclosure date with you, and credit you in the advisory unless you'd rather stay anonymous.

## Scope

The [threat model](docs/threat-model.md) explains what filevet defends against. These count as vulnerabilities:

- A crafted file escapes the sandbox or isolation around the parsers.
- A crafted file crashes or hangs the scanner, or exhausts its memory or disk (denial of service).
- A crafted file makes filevet read, write or send host files, or reach the network.
- filevet leaks file contents into logs or reports beyond the documented, truncated evidence.
- Problems in our release process that could let someone tamper with published packages or images.

These are normal bugs, so please open a regular issue:

- A missed detection: a malicious file that filevet doesn't flag.
- A false positive: a legitimate file that gets flagged.
