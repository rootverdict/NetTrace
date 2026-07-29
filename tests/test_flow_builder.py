from scapy.all import ICMP, IP, UDP, Raw, TCP
from scapy.layers.inet6 import IPv6

from nettrace.analysis.port_analyzer import analyze_flows
from nettrace.parsers.flow_builder import build_flows, flow_key, update_flow


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


def test_flow_builder_bounds_per_packet_samples():
    packets = []
    for index in range(20):
        packet = IP(src="10.0.0.5", dst="45.33.32.156") / TCP(sport=50000, dport=443, seq=index)
        packet.time = float(index)
        packets.append(packet)

    flows = {}
    from nettrace.parsers.flow_builder import update_flow

    for number, packet in enumerate(packets, 1):
        update_flow(flows, packet, number, sample_limit=4)

    flow = next(iter(flows.values()))
    assert flow.packet_count == 20
    assert len(flow.timestamps) == 4
    assert len(flow.packet_numbers) == 8


def test_flow_builder_enforces_flow_limit():
    from nettrace.parsers.flow_builder import update_flow

    flows = {}
    first = IP(src="10.0.0.5", dst="45.33.32.156") / TCP(sport=50000, dport=443)
    second = IP(src="10.0.0.5", dst="45.33.32.156") / TCP(sport=50001, dport=443)
    first.time = 1.0
    second.time = 2.0

    assert update_flow(flows, first, 1, max_flows=1)
    assert not update_flow(flows, second, 2, max_flows=1)
    assert len(flows) == 1


def test_reused_tcp_tuple_creates_separate_connection_flows():
    packets = [
        IP(src="10.0.0.5", dst="45.33.32.156") / TCP(sport=50000, dport=443, seq=100, flags="S"),
        IP(src="10.0.0.5", dst="45.33.32.156") / TCP(sport=50000, dport=443, seq=101, flags="PA") / Raw(load=b"one"),
        IP(src="10.0.0.5", dst="45.33.32.156") / TCP(sport=50000, dport=443, seq=5000, flags="S"),
        IP(src="10.0.0.5", dst="45.33.32.156") / TCP(sport=50000, dport=443, seq=5001, flags="PA") / Raw(load=b"two"),
    ]
    for number, packet in enumerate(packets, 1):
        packet.time = float(number)

    flows = build_flows(packets)

    assert len(flows) == 2
    assert [flow.packet_count for flow in flows] == [2, 2]


def test_non_ip_packet_is_recorded_without_creating_a_flow():
    # A packet with no IPv4/IPv6 layer has no endpoints to key on; update_flow
    # reports success (nothing to bound) and adds no flow.
    flows = {}
    assert update_flow(flows, TCP(sport=1, dport=2), packet_number=1) is True
    assert flows == {}


def test_syn_ack_orients_flow_toward_the_connection_initiator():
    # The capture starts on the server's SYN/ACK, so the initiator is the peer
    # the SYN/ACK is sent to.
    syn_ack = IP(src="203.0.113.10", dst="10.0.0.5") / TCP(sport=443, dport=50000, flags="SA")
    syn_ack.time = 1.0

    flows = build_flows([syn_ack])

    assert flows[0].src_ip == "10.0.0.5"
    assert flows[0].dst_ip == "203.0.113.10"
    assert flows[0].dst_port == 443


def test_direction_uses_service_port_when_no_other_signal():
    # Both endpoints private and below the ephemeral floor: the well-known
    # service port (25) decides which side is the server.
    packet = IP(src="10.0.0.5", dst="10.0.0.9") / UDP(sport=1000, dport=25)
    packet.time = 1.0

    flows = build_flows([packet])

    assert flows[0].dst_port == 25
    assert flows[0].src_ip == "10.0.0.5"


def test_direction_uses_ephemeral_port_when_only_source_is_ephemeral():
    packet = IP(src="10.0.0.5", dst="10.0.0.9") / UDP(sport=51000, dport=1000)
    packet.time = 1.0

    flows = build_flows([packet])

    assert flows[0].src_port == 51000
    assert flows[0].dst_port == 1000


def test_non_tcp_udp_protocol_uses_ip_protocol_number():
    packet = IP(src="10.0.0.5", dst="203.0.113.10") / ICMP()
    packet.time = 1.0

    flows = build_flows([packet])

    assert len(flows) == 1
    # ICMP is IP protocol 1; the flow protocol is the numeric value as a string.
    assert flows[0].protocol == "1"


def test_ipv6_non_transport_protocol_is_keyed_by_next_header():
    packet = IPv6(src="2001:db8::1", dst="2001:db8::2", nh=59)  # 59 = no next header
    packet.time = 1.0

    flows = build_flows([packet])

    assert len(flows) == 1
    assert flows[0].protocol == "59"


def test_later_stronger_direction_signal_reorients_the_flow():
    # First packet is a mid-session data segment (weak direction signal); the
    # following SYN then authoritatively sets the initiator direction.
    data = IP(src="203.0.113.10", dst="10.0.0.5") / TCP(sport=443, dport=50000, flags="PA") / Raw(load=b"x")
    syn = IP(src="10.0.0.5", dst="203.0.113.10") / TCP(sport=50000, dport=443, flags="S")
    data.time = 1.0
    syn.time = 2.0

    flows = build_flows([data, syn])

    assert flows[0].src_ip == "10.0.0.5"
    assert flows[0].dst_ip == "203.0.113.10"
    assert flows[0].dst_port == 443


def test_out_of_order_earlier_packet_updates_first_packet_number():
    later = IP(src="10.0.0.5", dst="203.0.113.10") / TCP(sport=50000, dport=443)
    earlier = IP(src="10.0.0.5", dst="203.0.113.10") / TCP(sport=50000, dport=443)
    later.time = 5.0
    earlier.time = 1.0

    flows = {}
    update_flow(flows, later, packet_number=1)
    update_flow(flows, earlier, packet_number=2)

    flow = next(iter(flows.values()))
    assert flow.first_seen == 1.0
    assert flow.first_packet_number == 2
