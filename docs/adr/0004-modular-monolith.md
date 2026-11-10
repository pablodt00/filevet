# 4. Build a modular monolith

Date: 2026-11-10

## Status

Accepted

## Context

filevet has to run as a CLI, inside CI jobs, as a Docker container and later as a REST API with workers. Small teams will self-host it. Splitting analyzers into separate services would add network calls, deployment work and more ways to fail, without making parsing safer, since isolation can be handled per process.

## Decision

filevet is one Python package with clear internal modules: `core` (contracts and pipeline), `analyzers`, `interfaces` (CLI, later the API) and `policies`. Analyzers depend only on the contracts in `core` and never on each other. They're loaded through entry points. Isolation comes from running each analyzer in its own subprocess, not from separate services.

## Consequences

One install and one image cover every use case, and a scan is a function call. The module boundaries keep the code ready to split later if needed. Analyzers share the package's dependency set, so a heavy dependency affects everyone; optional extras can limit that. A service that needs its own lifecycle, like ClamAV, stays outside the monolith (see ADR 5).
