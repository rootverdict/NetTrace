from __future__ import annotations

import argparse
import ctypes
import json
import platform
import statistics
import subprocess
import sys
import time
from pathlib import Path

from nettrace.config import load_config
from nettrace.engine import analyze_pcap


def peak_rss_bytes() -> int:
    if sys.platform == "win32":
        class ProcessMemoryCounters(ctypes.Structure):
            _fields_ = [
                ("cb", ctypes.c_ulong),
                ("PageFaultCount", ctypes.c_ulong),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        counters = ProcessMemoryCounters()
        counters.cb = ctypes.sizeof(counters)
        get_current_process = ctypes.windll.kernel32.GetCurrentProcess
        get_current_process.restype = ctypes.c_void_p
        get_memory_info = ctypes.windll.psapi.GetProcessMemoryInfo
        get_memory_info.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong]
        get_memory_info.restype = ctypes.c_int
        process = get_current_process()
        if not get_memory_info(process, ctypes.byref(counters), counters.cb):
            raise OSError("GetProcessMemoryInfo failed")
        return int(counters.PeakWorkingSetSize)

    import resource

    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(peak if sys.platform == "darwin" else peak * 1024)


def run_worker(pcap_path: Path, config_path: Path) -> dict[str, object]:
    config = load_config(config_path)
    started = time.perf_counter()
    report = analyze_pcap(pcap_path, config)
    duration = time.perf_counter() - started
    return {
        "sample": pcap_path.name,
        "size_bytes": pcap_path.stat().st_size,
        "packets": report.packet_count,
        "seconds": round(duration, 3),
        "peak_rss_mib": round(peak_rss_bytes() / (1024 * 1024), 1),
        "flows": len(report.flows),
        "findings": len(report.findings),
    }


def benchmark_sample(pcap_path: Path, config_path: Path, repeat: int) -> dict[str, object]:
    runs: list[dict[str, object]] = []
    for _ in range(repeat):
        command = [
            sys.executable,
            str(Path(__file__).resolve()),
            "--worker",
            str(pcap_path.resolve()),
            "--config",
            str(config_path.resolve()),
        ]
        completed = subprocess.run(command, check=True, capture_output=True, text=True)
        runs.append(json.loads(completed.stdout.strip().splitlines()[-1]))
    result = dict(runs[-1])
    result["median_seconds"] = round(statistics.median(float(run["seconds"]) for run in runs), 3)
    result["peak_rss_mib"] = max(float(run["peak_rss_mib"]) for run in runs)
    result.pop("seconds", None)
    return result


def markdown(results: list[dict[str, object]]) -> str:
    rows = [
        "| Sample | Size (MiB) | Packets | Median runtime | Python peak | Flows | Findings |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for result in results:
        size_mib = int(result["size_bytes"]) / (1024 * 1024)
        rows.append(
            f"| {result['sample']} | {size_mib:.1f} | {result['packets']:,} | "
            f"{result['median_seconds']:.3f} s | {result['peak_rss_mib']:.1f} MiB | "
            f"{result['flows']:,} | {result['findings']:,} |"
        )
    return "\n".join(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark NetTrace against one or more PCAP files")
    parser.add_argument("pcaps", nargs="+", type=Path)
    parser.add_argument("-c", "--config", type=Path, default=Path("config.yaml"))
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--json-output", type=Path)
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()

    if args.repeat < 1:
        parser.error("--repeat must be at least 1")

    if args.worker:
        if len(args.pcaps) != 1:
            parser.error("worker mode requires exactly one PCAP")
        print(json.dumps(run_worker(args.pcaps[0], args.config)))
        return

    results = [benchmark_sample(path, args.config, args.repeat) for path in args.pcaps]
    payload = {
        "environment": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "processor": platform.processor() or "not reported",
        },
        "repeat": args.repeat,
        "results": results,
    }
    print(markdown(results))
    if args.json_output:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(json.dumps(payload, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
