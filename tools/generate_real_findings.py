from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from nettrace.report.markdown_report import attack_techniques, bullet_list, top_domains, top_http_urls, top_ips


DEFAULT_MANIFEST = PROJECT_ROOT / "samples" / "real" / "manifest.json"
DEFAULT_REPORT_DIR = PROJECT_ROOT / "output" / "real"
DEFAULT_OUTPUT = PROJECT_ROOT / "FINDINGS.md"


def _load_reports(manifest_path: Path, report_dir: Path) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    reports = []
    for sample in manifest["samples"]:
        filename = Path(sample["filename"])
        report_path = report_dir / f"{filename.stem}_findings.json"
        reports.append((sample, json.loads(report_path.read_text(encoding="utf-8"))))
    return reports


def _finding_counts(report: dict[str, Any]) -> Counter[str]:
    return Counter(finding.get("title", "Unknown finding") for finding in report.get("findings", []))


def _internal_host(report: dict[str, Any]) -> str:
    from nettrace.report.markdown_report import infer_victim_host

    return infer_victim_host(report)


def build_aggregate_markdown(reports: list[tuple[dict[str, Any], dict[str, Any]]]) -> str:
    totals: Counter[str] = Counter()
    all_techniques: list[str] = []
    lines = [
        "# NetTrace Findings",
        "",
        "## Dataset",
        "",
        f"NetTrace was run against {len(reports)} real public Malware-Traffic-Analysis.net PCAP "
        "samples. The workflow analyzes packet captures only and does not execute malware.",
        "",
        "## Scan Summary",
        "",
        "| Sample | Packets | DNS | HTTP | TLS | FTP | Flows | IOCs | Observed Artifacts | Findings |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for sample, report in reports:
        summary = report.get("summary", {})
        for key in (
            "packets",
            "dns_events",
            "http_events",
            "tls_events",
            "ftp_events",
            "flows",
            "iocs",
            "observed_artifacts",
            "findings",
        ):
            totals[key] += int(summary.get(key, 0))
        all_techniques.extend(attack_techniques(report))
        lines.append(
            "| {name} | {packets} | {dns} | {http} | {tls} | {ftp} | {flows} | {iocs} | {artifacts} | {findings} |".format(
                name=sample["name"],
                packets=summary.get("packets", 0),
                dns=summary.get("dns_events", 0),
                http=summary.get("http_events", 0),
                tls=summary.get("tls_events", 0),
                ftp=summary.get("ftp_events", 0),
                flows=summary.get("flows", 0),
                iocs=summary.get("iocs", 0),
                artifacts=summary.get("observed_artifacts", 0),
                findings=summary.get("findings", 0),
            )
        )
    lines.extend(
        [
            "",
            "## Aggregate Totals",
            "",
            f"- Packets: {totals['packets']}",
            f"- DNS events: {totals['dns_events']}",
            f"- HTTP events: {totals['http_events']}",
            f"- TLS events: {totals['tls_events']}",
            f"- FTP events: {totals['ftp_events']}",
            f"- Flows: {totals['flows']}",
            f"- IOCs: {totals['iocs']}",
            f"- Observed artifacts: {totals['observed_artifacts']}",
            f"- Findings: {totals['findings']}",
            "",
            "## Potential ATT&CK Technique Associations",
            "",
            bullet_list(sorted(set(all_techniques))),
            "",
        ]
    )
    for sample, report in reports:
        summary = report.get("summary", {})
        victim = _internal_host(report)
        lines.extend(
            [
                f"## {sample['name']}",
                "",
                f"- Source: {sample['source_url']}",
                f"- PCAP: `{Path(report.get('pcap_path', sample['filename']))}`",
                f"- Primary internal host heuristic: `{victim}`",
                f"- Findings: {summary.get('findings', 0)}",
                "",
                "### Finding Types",
                "",
            ]
        )
        counts = _finding_counts(report)
        if counts:
            for title, count in counts.most_common():
                lines.append(f"- {title}: {count}")
        else:
            lines.append("- None observed")
        techniques = attack_techniques(report)
        if techniques:
            lines.extend(["", "### Potential ATT&CK Technique Associations", "", bullet_list(techniques)])
        lines.extend(
            [
                "",
                "### Notable URLs",
                "",
                bullet_list(top_http_urls(report)),
                "",
                "### Notable Domains",
                "",
                bullet_list(top_domains(report)),
                "",
                "### Notable IPs And Ports",
                "",
                bullet_list(top_ips(report, victim)),
                "",
            ]
        )
    lines.extend(
        [
            "## Notes",
            "",
            "- This write-up was generated from NetTrace JSON output across every real PCAP scan in the corpus.",
            "- Treat heuristic detections as triage leads and validate them against packet context.",
            "- Output reports for each scan are available under `output/real/` after running the analysis commands.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate aggregate FINDINGS.md from real PCAP JSON reports.")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--report-dir", type=Path, default=DEFAULT_REPORT_DIR)
    parser.add_argument("-o", "--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    markdown = build_aggregate_markdown(_load_reports(args.manifest, args.report_dir))
    args.output.write_text(markdown, encoding="utf-8")
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
