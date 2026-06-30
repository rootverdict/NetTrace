from pathlib import Path

from nettrace.cli import build_parser


def test_cli_generates_markdown_by_default():
    args = build_parser().parse_args(["sample.pcap"])

    assert args.no_md is False
    assert args.md_output is None


def test_cli_accepts_markdown_controls():
    args = build_parser().parse_args(
        [
            "sample.pcap",
            "--no-md",
            "--md-output",
            "custom.md",
            "--source",
            "Unit Test",
            "--source-url",
            "https://example.test",
        ]
    )

    assert args.no_md is True
    assert Path(args.md_output) == Path("custom.md")
    assert args.source == "Unit Test"
    assert args.source_url == "https://example.test"
