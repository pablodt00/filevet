# FAQ

## Does filevet replace an antivirus?

No. It can use ClamAV as one of its analyzers, but most of its checks are about things an antivirus doesn't look at: active content in documents, parser attacks, tampering, inconsistent financial data and text hidden from people. Run it next to your existing controls.

## Does filevet send my files anywhere?

No. It makes no network calls while scanning. The only outbound requests are optional webhooks from the API workers, which are off unless you configure them. The optional `--llm-verify` hook calls whatever verifier you install and name.

## Can a scanned file harm the machine running filevet?

That's the main risk filevet is built around. Each analyzer runs in its own worker with a timeout and memory limit, and the `nsjail` and `gvisor` backends add no network, a read-only filesystem, a seccomp filter and dropped privileges. The [security model](security-model.md) lists the guarantees of each backend and their limits.

## A legitimate file was flagged. What do I do?

Check the rule's page in the [rule reference](rules/index.md), which lists its known false positives. For a single known file, add a suppression with a reason and an expiry date. If a rule is wrong for your traffic in general, change its action in your [policy](cookbook.md). If you think the rule itself is wrong, open an issue with a script that builds a similar file, never the file itself.

## Does an integrity finding mean the document is forged?

No. Integrity findings are signals for review. A PDF saved twice or an IBAN that isn't on record has innocent explanations too. [Integrity checks](integrity.md) explains each technique and its limits.

## Which file types does it read?

PDF, CSV and text, OOXML (XLSX, XLSM, DOCX, DOCM), legacy Office (XLS, DOC), XML including ISO 20022 messages, and ZIP archives. Other types are still identified, so an executable renamed to `.pdf` is caught.

## How big can a file be?

50 MB by default, with limits on recursion depth, extracted children and total expanded size. All of them are set in `Limits`.

## Will an upgrade break my integration?

Not within 1.x. The CLI, report schema, policy schema, Python API, analyzer protocol and REST API v1 follow the rules in [API stability](stability.md).
