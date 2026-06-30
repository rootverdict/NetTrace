from __future__ import annotations

import argparse
from pathlib import Path

from nettrace.config import load_config
from nettrace.engine import analyze_pcap
from nettrace.report.html_report import render_html_report
from nettrace.report.json_export import export_json
from nettrace.report.markdown_report import build_markdown, default_output_path
from nettrace.report.pdf_report import render_pdf_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nettrace",
        description="NetTrace malware traffic analysis platform",
    )
    parser.add_argument("pcap", help="Path to the PCAP/PCAPNG file to analyze")
    parser.add_argument(
        "-c",
        "--config",
        default="config.yaml",
        help="Path to config.yaml",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="output",
        help="Output directory for reports",
    )
    parser.add_argument("--no-html", action="store_true", help="Skip HTML report")
    parser.add_argument("--no-pdf", action="store_true", help="Skip PDF report")
    parser.add_argument("--no-json", action="store_true", help="Skip JSON export")
    parser.add_argument("--no-md", action="store_true", help="Skip Markdown analyst findings")
    parser.add_argument(
        "--md-output",
        default=None,
        help="Markdown findings path. Defaults to findings/<sample>_FINDINGS.md",
    )
    parser.add_argument("--source", default="", help="Dataset/source label for Markdown findings")
    parser.add_argument("--source-url", default="", help="Dataset/source URL for Markdown findings")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    pcap_path = Path(args.pcap)
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    config = load_config(Path(args.config))
    report = analyze_pcap(pcap_path, config)

    stem = pcap_path.stem
    if not args.no_json:
        export_json(report, output_dir / f"{stem}_findings.json")
    if not args.no_html:
        render_html_report(report, output_dir / f"{stem}_report.html")
    if not args.no_pdf:
        render_pdf_report(report, output_dir / f"{stem}_report.pdf")
    if not args.no_md:
        md_path = Path(args.md_output) if args.md_output else default_output_path(Path(f"{stem}_findings.json"))
        md_path.parent.mkdir(parents=True, exist_ok=True)
        md_path.write_text(
            build_markdown(report.to_dict(), source=args.source, source_url=args.source_url),
            encoding="utf-8",
        )

    print(f"Analysis complete: {len(report.findings)} findings")
    print(f"Output directory: {output_dir.resolve()}")
    if not args.no_md:
        print(f"Markdown findings: {md_path.resolve()}")
