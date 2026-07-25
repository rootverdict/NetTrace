import json

from nettrace.models.events import IOC
from nettrace.models.findings import Finding
from nettrace.models.report import AnalysisReport
from nettrace.report.html_report import render_html_report
from nettrace.report.json_export import export_json


def sample_report() -> AnalysisReport:
    return AnalysisReport(
        pcap_path="captures/<unsafe>.pcap",
        dns_events=[],
        http_events=[],
        tls_events=[],
        ftp_events=[],
        flows=[],
        iocs=[IOC("domain", "bad.example", "dns", packet_number=7)],
        observed_artifacts=[IOC("ip", "45.33.32.156", "flow:tcp:443", packet_number=8, confidence="observed")],
        findings=[
            Finding(
                title="Suspicious <script> activity",
                description="A behavioral signal was detected.",
                category="test",
                evidence={"request": "<script>alert(1)</script>"},
                severity="high",
                score=80,
            )
        ],
        timeline=[
            {"timestamp": float(index), "type": "test", "summary": f"event {index}"}
            for index in range(201)
        ],
        packet_count=12,
        warnings=["Capture was truncated"],
    )


def test_export_json_creates_parent_and_serializes_complete_report(tmp_path):
    output = tmp_path / "nested" / "report.json"

    result = export_json(sample_report(), output)
    data = json.loads(output.read_text(encoding="utf-8"))

    assert result == output
    assert data["pcap_path"] == "captures/<unsafe>.pcap"
    assert data["summary"]["packets"] == 12
    assert data["summary"]["high"] == 1
    assert data["iocs"][0]["packet_number"] == 7
    assert data["observed_artifacts"][0]["packet_number"] == 8
    assert data["summary"]["observed_artifacts"] == 1
    assert data["warnings"] == ["Capture was truncated"]
    assert len(data["timeline"]) == 201


def test_render_html_creates_parent_escapes_content_and_limits_timeline(tmp_path):
    output = tmp_path / "nested" / "report.html"

    result = render_html_report(sample_report(), output)
    html = output.read_text(encoding="utf-8")

    assert result == output
    assert "NetTrace Analysis Report" in html
    assert "Capture was truncated" in html
    assert "Suspicious &lt;script&gt; activity" in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "Observed Artifacts" in html
    assert "45.33.32.156" in html
    assert "Timeline truncated to 200 entries" in html
    assert "event 199" in html
    assert "event 200" not in html
