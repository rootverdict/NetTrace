"""Capped report sections must disclose what they hide.

The HTML report used to slice `observed_artifacts[:500]` with no notice, so a
Redtail-scale capture rendered 500 rows and silently dropped 40,147 more. For a
forensics tool that is the dangerous kind of truncation: the analyst has no cue
that anything is missing. Findings and IOCs were not capped at all, so a capture
reaching the engine's 20,000-finding limit produced an unusable document.
"""

from pathlib import Path

from nettrace.models.events import IOC
from nettrace.models.findings import Finding
from nettrace.models.report import AnalysisReport
from nettrace.report.display_limits import (
    MAX_FINDINGS,
    MAX_IOCS,
    MAX_OBSERVED_ARTIFACTS,
    MAX_TIMELINE,
    limited,
)
from nettrace.report.html_report import render_html_report
from nettrace.report.pdf_report import render_pdf_report


def _finding(index: int) -> Finding:
    return Finding(
        title=f"Finding {index}",
        description="synthetic",
        severity="low",
        category="test",
        evidence={"index": index},
        score=index,
    )


def _report(**kwargs) -> AnalysisReport:
    fields = {
        "dns_events": [],
        "http_events": [],
        "tls_events": [],
        "ftp_events": [],
        "flows": [],
        "iocs": [],
        "findings": [],
        "timeline": [],
    }
    fields.update(kwargs)
    return AnalysisReport(pcap_path="synthetic.pcap", **fields)


def test_limited_reports_the_true_total_not_the_slice():
    section = limited(range(1000), 10)
    assert len(section.items) == 10
    assert section.total == 1000
    assert section.hidden == 990
    assert section.truncated is True
    assert "10 of 1,000" in section.notice
    assert "990 not shown" in section.notice


def test_limited_is_silent_when_nothing_is_hidden():
    section = limited(range(5), 10)
    assert section.truncated is False
    assert section.notice == ""
    assert section.hidden == 0


def test_ordering_wording_is_honest_about_which_entries_survived():
    assert "highest-scoring 2" in limited(range(9), 2, ordering="highest-scoring").notice
    assert "first 2" in limited(range(9), 2).notice


def test_html_discloses_truncated_observed_artifacts(tmp_path: Path):
    artifacts = [IOC("ip", f"10.0.0.{i % 250}", "flow") for i in range(MAX_OBSERVED_ARTIFACTS + 47)]
    path = render_html_report(_report(observed_artifacts=artifacts), tmp_path / "r.html")
    html = path.read_text(encoding="utf-8")

    assert "47 not shown" in html
    assert f"{MAX_OBSERVED_ARTIFACTS:,} of {MAX_OBSERVED_ARTIFACTS + 47:,}" in html


def test_html_discloses_truncated_iocs(tmp_path: Path):
    iocs = [IOC("domain", f"host{i}.example", "dns") for i in range(MAX_IOCS + 3)]
    html = render_html_report(_report(iocs=iocs), tmp_path / "r.html").read_text(encoding="utf-8")

    assert "3 not shown" in html


def test_html_keeps_the_highest_scoring_findings_and_says_so(tmp_path: Path):
    findings = [_finding(index) for index in range(MAX_FINDINGS + 5)]
    html = render_html_report(_report(findings=findings), tmp_path / "r.html").read_text(encoding="utf-8")

    assert "highest-scoring" in html
    assert "5 not shown" in html
    # The top scorer is kept; the lowest scorers are the ones dropped.
    assert f"Finding {MAX_FINDINGS + 4}</h3>" in html
    assert "Finding 0</h3>" not in html


def test_html_timeline_notice_still_present(tmp_path: Path):
    timeline = [{"timestamp": float(i), "type": "dns", "summary": f"e{i}"} for i in range(MAX_TIMELINE + 12)]
    html = render_html_report(_report(timeline=timeline), tmp_path / "r.html").read_text(encoding="utf-8")

    assert "12 not shown" in html


def test_html_has_no_truncation_notice_for_small_reports(tmp_path: Path):
    report = _report(
        findings=[_finding(1)],
        iocs=[IOC("domain", "a.example", "dns")],
        observed_artifacts=[IOC("ip", "10.0.0.1", "flow")],
        timeline=[{"timestamp": 1.0, "type": "dns", "summary": "e"}],
    )
    html = render_html_report(report, tmp_path / "r.html").read_text(encoding="utf-8")

    assert "not shown" not in html
    assert 'class="truncation"' not in html


def test_pdf_caps_findings_instead_of_growing_without_bound(tmp_path: Path):
    """Adding 1,500 more findings past the cap must not grow the document."""
    at_cap = render_pdf_report(
        _report(findings=[_finding(i) for i in range(MAX_FINDINGS)]), tmp_path / "at.pdf"
    ).stat().st_size
    far_over = render_pdf_report(
        _report(findings=[_finding(i) for i in range(MAX_FINDINGS + 1500)]), tmp_path / "over.pdf"
    ).stat().st_size

    # Only the one-line truncation notice separates them.
    assert abs(far_over - at_cap) < at_cap * 0.02


def test_pdf_renders_without_truncation_for_small_reports(tmp_path: Path):
    path = render_pdf_report(_report(findings=[_finding(1)]), tmp_path / "r.pdf")
    assert path.exists()
