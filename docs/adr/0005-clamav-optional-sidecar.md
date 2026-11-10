# 5. Run ClamAV as an optional sidecar

Date: 2026-11-10

## Status

Accepted

## Context

Signature-based detection of known malware is useful, and ClamAV is the established open-source engine for it. It's licensed under the GPL, which we can't bundle into an Apache-2.0 package. It also needs 1 to 2 GB of RAM for its signature database, and the database needs regular updates through `freshclam`. Many users only want the structural checks and shouldn't pay that cost.

## Decision

ClamAV isn't a dependency of filevet. The `malware.clamav` analyzer talks to a separate `clamd` process over a unix or TCP socket using the `INSTREAM` command. The Docker Compose setup and later the Helm chart run it as an optional sidecar. If `clamd` can't be reached, the analyzer emits an `info` finding, `malware.clamav_unavailable`, and the scan carries on.

## Consequences

filevet stays Apache-2.0 and lightweight (about 200 MB of RAM without ClamAV). Users who want signature detection run one extra container. Reports always show whether ClamAV took part in a scan, so its absence is visible. ClamAV tests need a running `clamd` and are skipped when it isn't available.
