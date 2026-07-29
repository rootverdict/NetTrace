from pathlib import Path

import pytest

from nettrace.cli import build_parser, main
from nettrace.config import ConfigError
from nettrace.models.report import AnalysisReport


def _empty_report():
    return AnalysisReport(
        pcap_path="sample.pcap",
        dns_events=[],
        http_events=[],
        tls_events=[],
        ftp_events=[],
        flows=[],
        iocs=[],
        findings=[],
        timeline=[],
    )


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


def test_cli_handles_missing_pcap_without_traceback_or_output_directory(tmp_path, monkeypatch, capsys):
    output = tmp_path / "should-not-exist"
    monkeypatch.setattr(
        "sys.argv",
        ["nettrace", str(tmp_path / "missing.pcap"), "--output", str(output)],
    )

    with pytest.raises(SystemExit) as exc_info:
        main()

    captured = capsys.readouterr()
    assert exc_info.value.code == 2
    assert "analysis error: PCAP not found" in captured.err
    assert "Traceback" not in captured.err
    assert not output.exists()


def test_cli_prints_analysis_warnings(tmp_path, monkeypatch, capsys):
    report = AnalysisReport(
        pcap_path="sample.pcap",
        dns_events=[],
        http_events=[],
        tls_events=[],
        ftp_events=[],
        flows=[],
        iocs=[],
        findings=[],
        timeline=[],
        warnings=["HTTP events truncated at 10 entries."],
    )
    monkeypatch.setattr("nettrace.cli.load_config", lambda _path, explicit=False: {})
    monkeypatch.setattr("nettrace.cli.analyze_pcap", lambda _path, _config: report)
    monkeypatch.setattr(
        "sys.argv",
        [
            "nettrace",
            "sample.pcap",
            "--output",
            str(tmp_path / "output"),
            "--no-json",
            "--no-html",
            "--no-pdf",
            "--no-md",
        ],
    )

    main()

    captured = capsys.readouterr()
    assert "Warning: HTTP events truncated at 10 entries." in captured.err


def test_cli_handles_report_output_errors_without_traceback(tmp_path, monkeypatch, capsys):
    output_file = tmp_path / "already-a-file"
    output_file.write_text("occupied", encoding="utf-8")
    report = AnalysisReport(
        pcap_path="sample.pcap",
        dns_events=[],
        http_events=[],
        tls_events=[],
        ftp_events=[],
        flows=[],
        iocs=[],
        findings=[],
        timeline=[],
    )
    monkeypatch.setattr("nettrace.cli.load_config", lambda _path, explicit=False: {})
    monkeypatch.setattr("nettrace.cli.analyze_pcap", lambda _path, _config: report)
    monkeypatch.setattr("sys.argv", ["nettrace", "sample.pcap", "--output", str(output_file)])

    with pytest.raises(SystemExit) as exc_info:
        main()

    captured = capsys.readouterr()
    assert exc_info.value.code == 2
    assert "report output error" in captured.err
    assert "Traceback" not in captured.err


def test_cli_reports_configuration_errors_without_traceback(tmp_path, monkeypatch, capsys):
    def _raise(_path, explicit=False):
        raise ConfigError("bad threshold")

    monkeypatch.setattr("nettrace.cli.load_config", _raise)
    monkeypatch.setattr("sys.argv", ["nettrace", "sample.pcap", "--output", str(tmp_path / "out")])

    with pytest.raises(SystemExit) as exc_info:
        main()

    captured = capsys.readouterr()
    assert exc_info.value.code == 2
    assert "configuration error: bad threshold" in captured.err
    assert "Traceback" not in captured.err


def test_cli_writes_every_report_format_by_default(tmp_path, monkeypatch, capsys):
    output = tmp_path / "output"
    md_path = tmp_path / "findings" / "sample_FINDINGS.md"
    monkeypatch.setattr("nettrace.cli.load_config", lambda _path, explicit=False: {})
    monkeypatch.setattr("nettrace.cli.analyze_pcap", lambda _path, _config: _empty_report())
    monkeypatch.setattr(
        "sys.argv",
        ["nettrace", "sample.pcap", "--output", str(output), "--md-output", str(md_path)],
    )

    main()

    # Every enabled writer must have produced its file.
    assert (output / "sample_findings.json").is_file()
    assert (output / "sample_report.html").is_file()
    assert (output / "sample_report.pdf").is_file()
    assert md_path.is_file()

    captured = capsys.readouterr()
    assert "Analysis complete: 0 findings" in captured.out
    assert "Markdown findings:" in captured.out
