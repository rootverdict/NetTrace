from scapy.all import IP, TCP

from nettrace.analysis.port_analyzer import analyze_flows
from nettrace.parsers.flow_builder import build_flows, flow_key


def test_flow_key_orders_ip_addresses_numerically_not_lexicographically():
    key = flow_key("2.0.0.1", "10.0.0.1", 50000, 4444, "TCP")

    assert key == ("2.0.0.1", "10.0.0.1", 50000, 4444, "TCP")


def test_flow_builder_aggregates_packets_by_conversation_tuple():
    first = IP(src="10.0.0.5", dst="203.0.113.66") / TCP(sport=50000, dport=443)
    second = IP(src="10.0.0.5", dst="203.0.113.66") / TCP(sport=50000, dport=443)
    first.time = 1.0
    second.time = 3.0

    flows = build_flows([first, second])

    assert len(flows) == 1
    assert flows[0].packet_count == 2
    assert flows[0].duration == 2.0
    assert flows[0].dst_port == 443
    assert flows[0].first_packet_number == 1
    assert flows[0].packet_numbers == [1, 2]


def test_flow_builder_merges_reverse_direction_packets():
    request = IP(src="10.0.0.5", dst="203.0.113.66") / TCP(sport=50000, dport=443)
    response = IP(src="203.0.113.66", dst="10.0.0.5") / TCP(sport=443, dport=50000)
    request.time = 1.0
    response.time = 2.0

    flows = build_flows([request, response])

    assert len(flows) == 1
    assert flows[0].packet_count == 2
    assert flows[0].byte_count == len(request) + len(response)
    assert flows[0].duration == 1.0
    assert flows[0].src_ip == "10.0.0.5"
    assert flows[0].dst_ip == "203.0.113.66"
    assert flows[0].src_port == 50000
    assert flows[0].dst_port == 443
    assert flows[0].packet_numbers == [1, 2]


def test_flow_builder_preserves_first_packet_direction_for_suspicious_ports():
    packet = IP(src="172.16.0.5", dst="13.107.5.88") / TCP(sport=50000, dport=4444)
    packet.time = 1.0

    flows = build_flows([packet])
    findings = analyze_flows(flows, {"high_frequency_connections": 50})

    assert flows[0].src_ip == "172.16.0.5"
    assert flows[0].dst_ip == "13.107.5.88"
    assert flows[0].dst_port == 4444
    assert flows[0].first_packet_number == 1
    assert any(finding.category == "unusual_port" for finding in findings)
    finding = next(finding for finding in findings if finding.category == "unusual_port")
    assert finding.evidence["first_packet_number"] == 1
    assert finding.evidence["wireshark_filter"] == "frame.number in {1}"


def test_flow_builder_infers_direction_when_capture_starts_mid_session():
    server_to_client = IP(src="13.107.5.88", dst="172.16.0.5") / TCP(sport=4444, dport=50000, flags="PA")
    client_to_server = IP(src="172.16.0.5", dst="13.107.5.88") / TCP(sport=50000, dport=4444, flags="PA")
    server_to_client.time = 1.0
    client_to_server.time = 2.0

    flows = build_flows([server_to_client, client_to_server])
    findings = analyze_flows(flows, {"high_frequency_connections": 50})

    assert len(flows) == 1
    assert flows[0].src_ip == "172.16.0.5"
    assert flows[0].dst_ip == "13.107.5.88"
    assert flows[0].dst_port == 4444
    assert flows[0].packet_numbers == [1, 2]
    assert any(finding.category == "unusual_port" for finding in findings)
