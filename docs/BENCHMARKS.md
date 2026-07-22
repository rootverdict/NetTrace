# NetTrace Benchmarks

These measurements provide a reproducible performance baseline for the five-sample validation corpus.

## Results

| Sample | Size (MiB) | Packets | Runtime | Peak process memory | Flows | Findings |
|---|---:|---:|---:|---:|---:|---:|
| Emotet Epoch 5 | 12.5 | 19,895 | 9.881 s | 79.7 MiB | 813 | 32 |
| Raspberry Robin | 73.7 | 91,481 | 44.470 s | 82.0 MiB | 51 | 42 |
| Redtail Linux malware | 4.8 | 43,041 | 22.387 s | 151.9 MiB | 40,687 | 2 |
| AgentTesla FTP variant | 0.1 | 182 | 0.081 s | 76.5 MiB | 10 | 6 |
| SmartApeSG to NetSupport RAT | 22.0 | 16,931 | 8.552 s | 77.5 MiB | 16 | 4 |

Aggregate corpus: 113.1 MiB and 171,530 packets.

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
