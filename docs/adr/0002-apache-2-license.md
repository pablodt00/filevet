# 2. License under Apache-2.0

Date: 2026-11-10

## Status

Accepted

## Context

filevet's users are fintechs and finance teams, whose legal departments often restrict which open-source licenses they accept. Copyleft licenses such as the GPL and AGPL are frequently blocked for internal and SaaS use. A security tool also benefits from a clear patent grant, so users and contributors know they won't be sued over patents in the code.

## Decision

filevet is licensed under Apache-2.0, with a `NOTICE` file holding the copyright line. Runtime dependencies must use licenses compatible with Apache-2.0. CI enforces this with an allow-list.

## Consequences

Companies can use filevet and build on it without legal friction, including in closed products. Contributions come with an explicit patent license. Some dependencies are off-limits: GPL-only libraries can't be bundled. ClamAV is GPL, so it runs as a separate service (see ADR 5) and is never linked.
