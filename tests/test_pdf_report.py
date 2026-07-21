from pypdf import PdfReader

from nettrace.models.report import AnalysisReport
from nettrace.report.pdf_report import MAX_EVIDENCE_CHARS, format_evidence, render_pdf_report


def test_format_evidence_truncates_large_payloads():
    evidence = {"blob": "A" * (MAX_EVIDENCE_CHARS + 200)}

    text = format_evidence(evidence)

    assert len(text) < MAX_EVIDENCE_CHARS + 100
    assert "... truncated ..." in text


def test_pdf_displays_analysis_warnings(tmp_path):
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
        warnings=["Timeline truncated at 10 entries."],
    )
    output = render_pdf_report(report, tmp_path / "report.pdf")

    text = "\n".join(page.extract_text() or "" for page in PdfReader(str(output)).pages)

    assert "Analysis Warnings" in text
    assert "Timeline truncated at 10 entries." in text
