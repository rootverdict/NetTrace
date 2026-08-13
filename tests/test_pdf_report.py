from pypdf import PdfReader

from nettrace.models.findings import Finding
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


def test_pdf_escapes_capture_controlled_paragraph_text(tmp_path):
    report = AnalysisReport(
        pcap_path="captures/<unsafe>.pcap",
        dns_events=[],
        http_events=[],
        tls_events=[],
        ftp_events=[],
        flows=[],
        iocs=[],
        findings=[
            Finding(
                title="Suspicious <script> activity",
                description="Observed <bad> marker in request.",
                category="test",
                evidence={"request": "<script>alert(1)</script>"},
                severity="high",
                score=80,
            )
        ],
        timeline=[],
        warnings=["Warning includes <unsafe> text"],
    )
    output = render_pdf_report(report, tmp_path / "unsafe.pdf")

    text = "\n".join(page.extract_text() or "" for page in PdfReader(str(output)).pages)

    assert "captures/<unsafe>.pcap" in text
    assert "Suspicious <script> activity" in text
    assert "Warning includes <unsafe> text" in text


def test_pdf_is_byte_reproducible_for_identical_report(tmp_path):
    report = AnalysisReport(
        pcap_path="sample.pcap",
        dns_events=[],
        http_events=[],
        tls_events=[],
        ftp_events=[],
        flows=[],
        iocs=[],
        findings=[
            Finding(
                title="Deterministic finding",
                description="The same report must produce the same PDF bytes.",
                category="test",
                evidence={"packet_number": 7},
                severity="medium",
                score=50,
            )
        ],
        timeline=[],
    )

    first = render_pdf_report(report, tmp_path / "first.pdf")
    second = render_pdf_report(report, tmp_path / "second.pdf")

    assert first.read_bytes() == second.read_bytes()
