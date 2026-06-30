from nettrace.analysis.port_analyzer import analyze_flows
from nettrace.models.events import Flow


def test_suspicious_port_creates_finding():
    flow = Flow("10.0.0.5", "203.0.113.66", 50000, 4444, "TCP", 1.0, 2.0, packet_count=2)
    findings = analyze_flows([flow], {"high_frequency_connections": 50})
    assert any(finding.category == "unusual_port" for finding in findings)


def test_suspicious_port_reports_each_distinct_flow():
    flows = [
        Flow("10.0.0.5", "203.0.113.66", 50000, 4444, "TCP", 1.0, 1.0, packet_count=1),
        Flow("10.0.0.5", "203.0.113.66", 50001, 4444, "TCP", 2.0, 2.0, packet_count=1),
    ]

    findings = analyze_flows(flows, {"high_frequency_connections": 50})

    assert sum(1 for finding in findings if finding.category == "unusual_port") == 2
