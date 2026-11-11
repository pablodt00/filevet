# 9. Detect file types with a built-in signature table

Date: 2026-11-11

## Status

Accepted

## Context

The pipeline needs each file's real type to dispatch analyzers and to catch files whose extension lies. The usual options are `python-magic`, which needs the native `libmagic` library and its database, and `puremagic`, a pure-Python port with a large signature list and fuzzy matching. filevet only has to tell apart the formats it handles (PDF, ZIP and OOXML, OLE, images, XML, HTML, text) and the executable formats it has to flag.

## Decision

`core/identify.py` holds a short table of magic-byte prefixes, checked against the first 512 bytes. Text gets a few checks after that: no control bytes, then XML or HTML by the first tag, otherwise plain text. Types are short labels such as `pdf`, `zip`, `pe` or `text`, and the declared type comes from the same labels keyed by file extension. We add no dependency for this.

## Consequences

The detection logic fits on one screen and has no native code, so it behaves the same on every platform. It recognises fewer formats than libmagic, so an unlisted binary format shows up as `unknown`, and CSV can't be told apart from other text. Container formats need their own analyzers to look inside: OOXML is detected as `zip`, and a polyglot is reported by its first signature only until `parser.polyglot` exists. A new format means one new row in the table.
