# Capacity planning

These numbers come from one laptop CPU (Intel Core i5-5350U, 2 cores at 1.8 GHz) running the `subprocess` sandbox, Python 3.12 and every built-in analyzer except ClamAV. A current server core is roughly twice as fast. Treat them as a starting point and run the benchmarks on your own hardware:

```console
uv run pytest benchmarks
```

## Time per file

Analyzers run one after another for each artifact, so the time for a file is the sum of its analyzer runs. One worker process handles one file at a time.

| File | Size | Scan time | Slowest analyzers |
| --- | --- | --- | --- |
| PDF invoice with JavaScript | 1 KB | 0.5 s | `malware.yara`, `integrity.pdf_tampering`, `malware.pdf_active_content` |
| Bank statement CSV, 1,000 rows | 84 KB | 0.6 s | `ai.hidden_content`, `parser.csv_formula_injection` |
| camt.053 statement, 1,000 entries | 216 KB | 0.5 s | `ai.hidden_content`, `integrity.financial_data` |
| XLSX, 5,000 rows | 73 KB | 5.9 s | `ai.hidden_content` (it runs on the workbook and its parts), `integrity.financial_data` |
| Bank statement CSV, 50,000 rows | 4.3 MB | 7.1 s | `ai.hidden_content` 3.7 s, `integrity.financial_data` 2.2 s |

Text-heavy files cost about 1.5 s per MB, most of it the Unicode and prompt-injection checks in `ai.hidden_content`. XLSX costs more per byte than CSV, because the compressed sheets expand and their text is read by several analyzers. Small PDFs cost a fixed 0.5 s or so, which is mostly the per-analyzer process start.

## Sandbox overhead

| Backend | Cost per analyzer run |
| --- | --- |
| `subprocess` | About 20 ms (one fork) |
| `nsjail`, `gvisor` | 0.3 to 1 s (a new Python process and the analyzer's imports; `integrity.pdf_signature` is the slowest because pyHanko takes about a second to import) |

A typical PDF goes through 9 analyzers, so a jailed scan of a small file takes 4 to 5 s instead of 0.5 s. That's fine for queue workers. For the synchronous API, keep `FILEVET_SYNC_MAX_BYTES` low or use the `subprocess` backend inside a gVisor pod.

## Memory

Each analyzer run is capped at `memory_bytes` (1 GiB by default). Measured peaks, including the roughly 55 MB a forked worker shares with its parent:

| Analyzer | 4 MB CSV | 73 KB XLSX | Small PDF |
| --- | --- | --- | --- |
| `integrity.financial_data` | 130 MB | 78 MB | 58 MB |
| `ai.hidden_content` | 88 MB | 87 MB | 58 MB |
| `parser.csv_formula_injection` | 82 MB | 87 MB | n/a |
| `malware.yara` | 69 MB | 67 MB | 67 MB |

Expect about 2 to 3 times the input size on top of the base for text formats. Only one analyzer runs at a time per worker, so a worker needs its base plus the largest single run: about 200 MB for 5 MB inputs, and the full `memory_bytes` cap for the 50 MB default input limit at worst.

## Sizing

- Run one worker per core. Throughput per worker is roughly 1 / (average scan time), for example about 2 small PDFs a second, or one 4 MB CSV every 7 s on the machine above.
- For memory, 256 MB per worker covers inputs up to a few MB. Give workers that take 50 MB inputs at least `memory_bytes` plus 200 MB.
- Each scan writes its input and extracted children to a private temp directory, up to `max_input_bytes` plus `max_total_expanded_bytes` (550 MB by default). In Kubernetes this is the `/tmp` emptyDir, which counts against the pod's memory when it's memory-backed.
- The API runs at most one synchronous scan per CPU at a time. Everything larger than `FILEVET_SYNC_MAX_BYTES` goes to the queue.

## Regressions

The `Benchmarks` workflow runs `benchmarks/` on every push to master and stores the results as the baseline. On a pull request it runs them again and fails when any case's fastest round is more than 20% slower than the master baseline. The fastest round is used because it's the least affected by noisy CI machines.
