# 8. Discover analyzers through entry points

Date: 2026-11-11

## Status

Accepted

## Context

Teams will want analyzers for their own formats and rules, some of them private. They shouldn't have to fork filevet or send everything upstream to get them.

## Decision

Analyzers are found through the `filevet.analyzers` entry point group with `importlib.metadata`. Each entry point names a class, and the pipeline creates one instance per scan. Built-in analyzers register the same way in filevet's own `pyproject.toml`, so third-party analyzers get exactly the same treatment.

## Consequences

Installing a package is enough to add an analyzer, and `filevet analyzers` shows what's active. Anything installed in the environment runs during a scan, so installing an analyzer means trusting its code just like any other dependency. The isolation in ADR 6 limits the damage from bugs, not from malicious plugins. If an entry point fails to import, the scan stops with an internal error rather than running quietly without that analyzer.
