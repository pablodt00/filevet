# basic.executable

Severity: `high`

## What it means

The file is a program or a script: a Windows PE, an ELF or Mach-O binary, a Windows shortcut (`.lnk`), or a script such as `.ps1`, `.vbs`, `.js` or `.sh`.

## Why it matters for finance files

None of the files a finance team expects (invoices, statements, KYC documents, payment files) is a program. An executable in that channel is either a mistake or an attack.

## How to fix the file

Reject it and ask the sender for the document itself.

## False positives

None in a finance intake flow. If the channel also carries software, scan those files somewhere else.
