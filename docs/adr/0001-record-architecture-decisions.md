# 1. Record architecture decisions

Date: 2026-11-10

## Status

Accepted

## Context

filevet is a security tool that outside contributors will review and extend. They need to know why it's built the way it is, not only how.

## Decision

We record significant decisions as Architecture Decision Records in `docs/adr/`, in the short format from Michael Nygard's [Documenting Architecture Decisions](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions): context, decision, consequences. Files are numbered in order. An accepted ADR isn't edited; when a decision changes, a new ADR supersedes it.

## Consequences

Decisions are reviewed in PRs like code. Adding a runtime dependency or changing a core design choice means writing or updating an ADR.
