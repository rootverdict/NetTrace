from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from nettrace.report.markdown_report import write_markdown_report


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate Markdown analyst findings from NetTrace JSON.")
    parser.add_argument("json_report", help="Path to NetTrace *_findings.json")
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Markdown output path. Defaults to findings/<report_stem>_FINDINGS.md",
    )
    parser.add_argument("--source", default="", help="Dataset/source label")
    parser.add_argument("--source-url", default="", help="Dataset/source URL")
    args = parser.parse_args()

    output_path = Path(args.output) if args.output else None
    destination = write_markdown_report(
        Path(args.json_report),
        output_path=output_path,
        source=args.source,
        source_url=args.source_url,
    )
    print(f"Wrote {destination}")


if __name__ == "__main__":
    main()
