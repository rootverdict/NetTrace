from nettrace.analysis.port_analyzer import analyze_flows
from nettrace.models.events import Flow


def test_suspicious_port_creates_finding():
    flow = Flow("10.0.0.5", "203.0.113.66", 50000, 4444, "TCP", 1.0, 2.0, packet_count=2)
    findings = analyze_flows([flow], {"high_frequency_connections": 50})
    assert any(finding.category == "unusual_port" for finding in findings)


def test_repeat_flows_to_one_port_aggregate_into_a_single_finding():
    # Previously one finding per flow. On scanning traffic that was unusable:
    # a Mirai capture produced 27,309 identical findings, hit the 20,000 cap,
    # and evicted the unrelated real detections from the report.
    flows = [
        Flow("10.0.0.5", "203.0.113.66", 50000, 4444, "TCP", 1.0, 1.0, packet_count=1),
        Flow("10.0.0.5", "203.0.113.66", 50001, 4444, "TCP", 2.0, 2.0, packet_count=1),
    ]

    findings = [f for f in analyze_flows(flows, {"high_frequency_connections": 50})
                if f.category == "unusual_port"]

    assert len(findings) == 1
    assert findings[0].evidence["flow_count"] == 2
    assert findings[0].evidence["distinct_destinations"] == 1
    # A single-destination group still names the peer, as it did before.
    assert findings[0].evidence["dst_ip"] == "203.0.113.66"
    assert findings[0].timestamp == 1.0


def test_scan_across_many_destinations_is_one_finding_naming_the_breadth():
    flows = [
        Flow("10.0.0.5", f"203.0.113.{i}", 50000 + i, 4444, "TCP", float(i), float(i), packet_count=1)
        for i in range(40)
    ]

    findings = [f for f in analyze_flows(flows, {"high_frequency_connections": 50})
                if f.category == "unusual_port"]

    assert len(findings) == 1
    assert findings[0].evidence["distinct_destinations"] == 40
    assert "40 destinations" in findings[0].description
    # Breadth is in the counts, not in 40 separate findings.
    assert len(findings[0].evidence["top_peers"]) == 8


def test_distinct_ports_stay_distinct_findings():
    flows = [
        Flow("10.0.0.5", "203.0.113.66", 50000, 4444, "TCP", 1.0, 1.0, packet_count=1),
        Flow("10.0.0.5", "203.0.113.66", 50001, 1337, "TCP", 2.0, 2.0, packet_count=1),
    ]

    findings = [f for f in analyze_flows(flows, {"high_frequency_connections": 50})
                if f.category == "unusual_port"]

    assert sorted(f.evidence["dst_port"] for f in findings) == [1337, 4444]


def test_high_frequency_groups_by_destination_not_by_port():
    """Volume to separate peers stays separate: that is the signal."""
    flows = [
        Flow("10.0.0.5", "203.0.113.1", 50000, 8080, "TCP", 1.0, 2.0, packet_count=60),
        Flow("10.0.0.5", "203.0.113.1", 50001, 8080, "TCP", 3.0, 4.0, packet_count=70),
        Flow("10.0.0.5", "203.0.113.2", 50002, 8080, "TCP", 5.0, 6.0, packet_count=80),
    ]

    findings = [f for f in analyze_flows(flows, {"high_frequency_connections": 50})
                if f.category == "high_frequency_connections"]

    assert len(findings) == 2
    by_dst = {f.evidence["dst_ip"]: f for f in findings}
    assert by_dst["203.0.113.1"].evidence["flow_count"] == 2
    assert by_dst["203.0.113.1"].evidence["packet_count"] == 130
    assert by_dst["203.0.113.2"].evidence["flow_count"] == 1


def test_aggregated_finding_keeps_openable_packet_evidence():
    flows = [
        Flow("10.0.0.5", "203.0.113.66", 50000, 4444, "TCP", 1.0, 1.0, packet_count=1,
             packet_numbers=[11]),
        Flow("10.0.0.5", "203.0.113.66", 50001, 4444, "TCP", 2.0, 2.0, packet_count=9,
             packet_numbers=[22, 23]),
    ]

    finding = next(f for f in analyze_flows(flows, {"high_frequency_connections": 50})
                   if f.category == "unusual_port")

    # Anchored on the busiest flow so the filter opens real traffic.
    assert finding.evidence["wireshark_filter"]
    assert "22" in finding.evidence["wireshark_filter"]
