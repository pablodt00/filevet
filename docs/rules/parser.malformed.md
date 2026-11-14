# parser.malformed

Severity: `medium`

## What it means

filevet couldn't parse the file's structure: a ZIP with a broken directory, an unreadable entry, a PDF without its end marker or with a cross-reference offset that points nowhere, XML that isn't well formed, an OLE file that can't be read, or a CSV that stops parsing or exceeds the row, column or field limits.

## Why it matters for finance files

Broken structure is a common evasion trick. Viewers repair files in their own way, so a damaged file can look clean to a scanner and still open in Acrobat or Excel with different content. It also means filevet's other checks may not have seen the whole file.

## How to fix the file

Ask the sender for a fresh export. If they can't send one, open the file in a sandbox, not on a workstation.

## False positives

Truncated uploads and files cut off by mail gateways produce this too. The cause is harmless, but the file still wasn't fully checked.
