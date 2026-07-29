# NetTrace Benchmarks

These measurements provide a reproducible performance baseline for the twelve-sample validation corpus.

## Results

| Sample | Size (MiB) | Packets | Runtime | Peak process memory | Flows | Findings |
|---|---:|---:|---:|---:|---:|---:|
| Emotet Epoch 5 | 12.5 | 19,895 | 7.612 s | 80.2 MiB | 813 | 25 |
| Raspberry Robin | 73.7 | 91,481 | 35.514 s | 80.8 MiB | 51 | 13 |
| Redtail Linux malware | 4.8 | 43,041 | 17.513 s | 146.1 MiB | 40,687 | 6 |
| AgentTesla FTP variant | 0.1 | 182 | 0.073 s | 76.7 MiB | 10 | 6 |
| SmartApeSG to NetSupport RAT | 22.0 | 16,931 | 6.785 s | 77.6 MiB | 16 | 3 |
| Mirai IoT botnet | 9.8 | 118,105 | 39.986 s | 164.1 MiB | 50,000 | 16 |
| In-the-wild scans (Dec 1-3) | 0.0 | 42 | 0.020 s | 76.4 MiB | 5 | 0 |
| XWorm from email | 4.0 | 4,645 | 1.818 s | 77.0 MiB | 5 | 2 |
| Ten days of scans and probes | 33.6 | 374,554 | 118.640 s | 182.2 MiB | 50,000 | 134 |
| XLoader (Formbook) | 23.3 | 41,424 | 16.953 s | 90.3 MiB | 1,960 | 40 |
| Infected Android phone | 23.0 | 29,125 | 10.880 s | 79.8 MiB | 400 | 23 |
| Koi Loader / Koi Stealer | 48.7 | 43,721 | 16.862 s | 82.6 MiB | 216 | 37 |

Aggregate corpus: 255.5 MiB and 783,146 packets across 12 captures.

Flow counts of exactly 50,000 are the configured `limits.max_flows` cap engaging on
scanning traffic, not the true flow total; both such captures report the truncation
as an analysis warning.

## Environment

- Windows 11 build 26200
- Python 3.12.10
- Intel64 Family 6 Model 165 processor
- One run per sample; timings include parsing, analysis, mapping, and in-memory report construction
- Peak memory is the operating system's peak resident working set for a fresh process per sample
- JSON, HTML, PDF, and Markdown serialization time is excluded

Results vary with hardware, storage, Python version, and background load. The machine-readable record is in [`benchmarks.json`](benchmarks.json).

## Reproduce

```powershell
$pcaps = (Get-ChildItem samples\real\*.pcap | Sort-Object Name).FullName
python tools\benchmark.py @pcaps --json-output docs\benchmarks.json
```

Use `--repeat 3` for a more stable median when publishing comparative results.
