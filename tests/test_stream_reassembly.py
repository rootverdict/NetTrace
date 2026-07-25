from pathlib import Path

from scapy.all import DNS, DNSQR, IP, IPv6, Raw, TCP, UDP, fragment, raw, wrpcap

from nettrace.config import load_config
from nettrace.engine import analyze_pcap
from nettrace.parsers.dns_extractor import extract_dns_event
from nettrace.parsers.flow_builder import build_flows
from nettrace.parsers.ftp_extractor import FTPStreamExtractor
from nettrace.parsers.http_extractor import HTTPStreamExtractor, extract_http_event
from nettrace.parsers.tls_extractor import TLSStreamExtractor
from nettrace.parsers.tcp_stream import TCPStreamBuffers


def tls_client_hello(hostname: str) -> bytes:
    name = hostname.encode()
    name_entry = b"\x00" + len(name).to_bytes(2, "big") + name
    server_name_data = len(name_entry).to_bytes(2, "big") + name_entry
    extension = b"\x00\x00" + len(server_name_data).to_bytes(2, "big") + server_name_data
    body = (
        b"\x03\x03"
        + (b"R" * 32)
        + b"\x00"
        + b"\x00\x02\x13\x01"
        + b"\x01\x00"
        + len(extension).to_bytes(2, "big")
        + extension
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


def test_http_stream_reassembles_split_request():
    extractor = HTTPStreamExtractor()
    first = IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(sport=50000, dport=80, seq=100) / Raw(load=b"GE")
    second_payload = b"T /x.exe HTTP/1.1\r\nHost: evil.example\r\n\r\n"
    second = IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(sport=50000, dport=80, seq=102) / Raw(
        load=second_payload
    )
    first.time = 1.0
    second.time = 2.0

    assert extractor.feed(first, 1) == []
    events = extractor.feed(second, 2)

    assert len(events) == 1
    assert events[0].host == "evil.example"
    assert events[0].packet_number == 1


def test_http_stream_reassembles_out_of_order_request():
    extractor = HTTPStreamExtractor()
    head = b"GE"
    tail = b"T /x.exe HTTP/1.1\r\nHost: evil.example\r\n\r\n"
    later = IP(src="10.0.0.5", dst="45.33.32.156") / TCP(sport=50000, dport=80, seq=102) / Raw(load=tail)
    earlier = IP(src="10.0.0.5", dst="45.33.32.156") / TCP(sport=50000, dport=80, seq=100) / Raw(load=head)
    later.time = 2.0
    earlier.time = 1.0

    assert extractor.feed(later, 2) == []
    events = extractor.feed(earlier, 1)

    assert len(events) == 1
    assert events[0].uri == "/x.exe"
    assert events[0].packet_number == 1


def test_tls_stream_reassembles_split_client_hello():
    payload = tls_client_hello("split.example")
    split = 20
    extractor = TLSStreamExtractor()
    first = IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(sport=50000, dport=443, seq=100) / Raw(
        load=payload[:split]
    )
    second = IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(
        sport=50000, dport=443, seq=100 + split
    ) / Raw(load=payload[split:])
    first.time = 1.0
    second.time = 2.0

    assert extractor.feed(first, 1) == []
    events = extractor.feed(second, 2)

    assert len(events) == 1
    assert events[0].sni == "split.example"
    assert events[0].src_port == 50000


def test_tls_stream_reassembles_out_of_order_client_hello():
    payload = tls_client_hello("ordered.example")
    split = 20
    extractor = TLSStreamExtractor()
    later = IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(
        sport=50000, dport=443, seq=100 + split
    ) / Raw(load=payload[split:])
    earlier = IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(
        sport=50000, dport=443, seq=100
    ) / Raw(load=payload[:split])
    later.time = 2.0
    earlier.time = 1.0

    assert extractor.feed(later, 2) == []
    events = extractor.feed(earlier, 1)

    assert len(events) == 1
    assert events[0].sni == "ordered.example"
    assert events[0].packet_number == 1


def test_tls_stream_reassembles_client_hello_across_tls_records():
    record = tls_client_hello("records.example")
    handshake = record[5:]
    split = 30
    payloads = [
        b"\x16\x03\x01" + split.to_bytes(2, "big") + handshake[:split],
        b"\x16\x03\x01" + (len(handshake) - split).to_bytes(2, "big") + handshake[split:],
    ]
    extractor = TLSStreamExtractor()
    events = []
    sequence = 100
    for number, payload in enumerate(payloads, 1):
        packet = IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(
            sport=50000, dport=443, seq=sequence, flags="PA"
        ) / Raw(load=payload)
        packet.time = float(number)
        sequence += len(payload)
        events.extend(extractor.feed(packet, number))

    assert len(events) == 1
    assert events[0].sni == "records.example"


def test_ftp_stream_reassembles_out_of_order_command():
    extractor = FTPStreamExtractor()
    later = IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(sport=50000, dport=21, seq=102) / Raw(
        load=b"ER analyst\r\n"
    )
    earlier = IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(sport=50000, dport=21, seq=100) / Raw(load=b"US")
    later.time = 2.0
    earlier.time = 1.0

    assert extractor.feed(later, 2) == []
    events = extractor.feed(earlier, 1)

    assert len(events) == 1
    assert events[0].command == "USER"
    assert events[0].argument == "analyst"


def test_ipv6_dns_http_and_flow_parsing():
    dns = IPv6(src="2001:db8::1", dst="2001:4860:4860::8888") / UDP(sport=53000, dport=53) / DNS(
        qd=DNSQR(qname="example.com")
    )
    http = IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(sport=50000, dport=80) / Raw(
        load=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    )
    dns.time = 1.0
    http.time = 2.0

    assert extract_dns_event(dns) is not None
    assert extract_http_event(http) is not None
    assert len(build_flows([dns, http])) == 2


def test_engine_uses_stream_reassembly(tmp_path):
    first = IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(sport=50000, dport=80, seq=100) / Raw(load=b"GE")
    second = IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(sport=50000, dport=80, seq=102) / Raw(
        load=b"T /payload.exe HTTP/1.1\r\nHost: evil.example\r\n\r\n"
    )
    first.time = 1.0
    second.time = 2.0
    capture = tmp_path / "split.pcap"
    wrpcap(str(capture), [first, second])

    report = analyze_pcap(capture, load_config(Path("does-not-exist.yaml")))

    assert len(report.http_events) == 1
    assert any(finding.title == "Possible executable/script download request" for finding in report.findings)


def test_http_stream_resets_when_tcp_tuple_is_reused():
    extractor = HTTPStreamExtractor()
    packets = [
        IP(src="10.0.0.5", dst="45.33.32.156") / TCP(sport=50000, dport=80, seq=100, flags="S"),
        IP(src="10.0.0.5", dst="45.33.32.156") / TCP(sport=50000, dport=80, seq=101, flags="PA")
        / Raw(load=b"GET /one HTTP/1.1\r\nHost: one.example\r\n\r\n"),
        IP(src="10.0.0.5", dst="45.33.32.156") / TCP(sport=50000, dport=80, seq=5000, flags="S"),
        IP(src="10.0.0.5", dst="45.33.32.156") / TCP(sport=50000, dport=80, seq=5001, flags="PA")
        / Raw(load=b"GET /two HTTP/1.1\r\nHost: two.example\r\n\r\n"),
    ]
    events = []
    for number, packet in enumerate(packets, 1):
        packet.time = float(number)
        events.extend(extractor.feed(packet, number))

    assert [event.host for event in events] == ["one.example", "two.example"]


def test_engine_reassembles_segmented_dns_over_tcp(tmp_path):
    dns_message = raw(DNS(id=7, qd=DNSQR(qname="tcp.example")))
    framed = len(dns_message).to_bytes(2, "big") + dns_message
    packets = [
        IP(src="10.0.0.5", dst="8.8.8.8") / TCP(sport=53000, dport=53, seq=100, flags="PA")
        / Raw(load=framed[:8]),
        IP(src="10.0.0.5", dst="8.8.8.8") / TCP(sport=53000, dport=53, seq=108, flags="PA")
        / Raw(load=framed[8:]),
    ]
    for number, packet in enumerate(packets, 1):
        packet.time = float(number)
    capture = tmp_path / "dns-tcp.pcap"
    wrpcap(str(capture), packets)

    report = analyze_pcap(capture, load_config(Path("does-not-exist.yaml")))

    assert len(report.dns_events) == 1
    assert report.dns_events[0].query == "tcp.example"


def test_engine_warns_when_tcp_reassembly_discards_stream(tmp_path):
    packet = IP(src="10.0.0.5", dst="45.33.32.156") / TCP(sport=50000, dport=80, seq=100, flags="PA") / Raw(
        load=b"GET /incomplete"
    )
    packet.time = 1.0
    capture = tmp_path / "tcp-limit.pcap"
    wrpcap(str(capture), [packet])
    config = load_config(Path("does-not-exist.yaml"))
    config["limits"]["max_tcp_stream_buffer_bytes"] = 8

    report = analyze_pcap(capture, config)

    assert "TCP reassembly discarded 1 incomplete or resource-limited streams." in report.warnings


def test_tcp_reassembly_enforces_aggregate_buffer_limit():
    buffers = TCPStreamBuffers(max_buffer_bytes=100, max_total_buffer_bytes=10)
    packets = [
        IP(src="10.0.0.5", dst="45.33.32.156") / TCP(sport=50000, dport=80, seq=1, flags="PA") / Raw(load=b"A" * 6),
        IP(src="10.0.0.5", dst="45.33.32.156") / TCP(sport=50001, dport=80, seq=1, flags="PA") / Raw(load=b"B" * 6),
    ]
    for number, packet in enumerate(packets, 1):
        packet.time = float(number)
        buffers.feed(packet, number)

    assert buffers.total_buffered_bytes <= 10
    assert buffers.discarded_streams == 1


def test_tcp_reassembly_handles_sequence_number_wraparound():
    extractor = HTTPStreamExtractor()
    first_payload = b"GET /wrap HTTP/1.1\r\nHo"
    second_payload = b"st: wrap.example\r\n\r\n"
    first_sequence = 0xFFFFFFF0
    packets = [
        IP(src="10.0.0.5", dst="45.33.32.156") / TCP(
            sport=50000, dport=80, seq=first_sequence, flags="PA"
        ) / Raw(load=first_payload),
        IP(src="10.0.0.5", dst="45.33.32.156") / TCP(
            sport=50000,
            dport=80,
            seq=(first_sequence + len(first_payload)) & 0xFFFFFFFF,
            flags="PA",
        ) / Raw(load=second_payload),
    ]
    events = []
    for number, packet in enumerate(packets, 1):
        packet.time = float(number)
        events.extend(extractor.feed(packet, number))

    assert len(events) == 1
    assert events[0].host == "wrap.example"


def test_engine_warns_when_configured_intel_file_is_missing(tmp_path):
    packet = IP(src="10.0.0.5", dst="8.8.8.8") / UDP(sport=53000, dport=53)
    packet.time = 1.0
    capture = tmp_path / "missing-intel.pcap"
    wrpcap(str(capture), [packet])
    config = load_config(Path("does-not-exist.yaml"))
    missing = tmp_path / "missing-domains.txt"
    config["intel"]["known_bad_domains"] = str(missing)

    report = analyze_pcap(capture, config)

    assert f"Local intelligence file not found for known_bad_domains: {missing}" in report.warnings


def test_engine_reassembles_ipv4_fragments(tmp_path):
    packet = IP(src="10.0.0.5", dst="45.33.32.156", id=1234) / TCP(sport=50000, dport=80, seq=100) / Raw(
        load=b"GET /payload.exe HTTP/1.1\r\nHost: evil.example\r\n\r\n"
    )
    packet.time = 1.0
    fragments = fragment(packet, fragsize=24)
    for item in fragments:
        item.time = 1.0
    capture = tmp_path / "fragmented.pcap"
    wrpcap(str(capture), fragments)

    report = analyze_pcap(capture, load_config(Path("does-not-exist.yaml")))

    assert len(report.http_events) == 1
    assert report.http_events[0].host == "evil.example"
    assert any(finding.title == "Possible executable/script download request" for finding in report.findings)


def test_engine_reports_resource_truncation(tmp_path):
    first = IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(sport=50000, dport=80)
    second = IPv6(src="2001:db8::1", dst="2001:db8::3") / TCP(sport=50001, dport=80)
    first.time = 1.0
    second.time = 2.0
    capture = tmp_path / "limited.pcap"
    wrpcap(str(capture), [first, second])
    config = load_config(Path("does-not-exist.yaml"))
    config["limits"]["max_flows"] = 1

    report = analyze_pcap(capture, config)

    assert len(report.flows) == 1
    assert "Flow records truncated at 1 entries." in report.warnings


def test_engine_uses_configured_http_ports(tmp_path):
    packet = IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(sport=50000, dport=8001, seq=100) / Raw(
        load=b"GET /payload.exe HTTP/1.1\r\nHost: evil.example\r\n\r\n"
    )
    packet.time = 1.0
    capture = tmp_path / "custom-port.pcap"
    wrpcap(str(capture), [packet])
    config = load_config(Path("does-not-exist.yaml"))
    config["protocols"]["http_ports"].append(8001)

    report = analyze_pcap(capture, config)

    assert len(report.http_events) == 1
    assert any(finding.title == "Possible executable/script download request" for finding in report.findings)


def test_engine_caps_findings_at_configured_max(tmp_path):
    # Bug #10: there was previously no cap -- a hostile/noisy capture could
    # produce an unbounded number of findings.
    packets = []
    for index in range(5):
        packet = (
            IP(src="10.0.0.5", dst=f"203.0.113.{index}")
            / TCP(sport=40000 + index, dport=4444, seq=100, flags="PA")
            / Raw(load=b"x" * 10)
        )
        packet.time = float(index)
        packets.append(packet)
    capture = tmp_path / "many-findings.pcap"
    wrpcap(str(capture), packets)
    config = load_config(Path("does-not-exist.yaml"))
    config["limits"]["max_findings"] = 2

    report = analyze_pcap(capture, config)

    assert len(report.findings) == 2
    assert any("Findings truncated at 2 entries" in warning for warning in report.warnings)


def test_engine_surfaces_conflicting_overlap_warning(tmp_path):
    # Bug #3: conflicting overlapping retransmissions must be visible to the
    # analyst, not silently resolved. Uses an incomplete request (no blank
    # line) so the bytes stay unconsumed in the buffer -- a complete request
    # would be consumed immediately and hit the bug #8 path instead.
    packets = [
        IP(src="10.0.0.5", dst="45.33.32.156") / TCP(sport=50000, dport=80, seq=100, flags="PA")
        / Raw(load=b"GET /aaaaaaaaaaaa"),
        IP(src="10.0.0.5", dst="45.33.32.156") / TCP(sport=50000, dport=80, seq=100, flags="PA")
        / Raw(load=b"GET /bbbbbbbbbbbb"),
    ]
    for number, packet in enumerate(packets, 1):
        packet.time = float(number)
    capture = tmp_path / "overlap-conflict.pcap"
    wrpcap(str(capture), packets)

    report = analyze_pcap(capture, load_config(Path("does-not-exist.yaml")))

    assert any("overlapping retransmission" in warning for warning in report.warnings)


def test_engine_surfaces_incomplete_stream_warning(tmp_path):
    # Bug #4: a stream still open (no FIN/RST, never hit a resource limit)
    # when the capture ends was previously invisible in the report.
    packet = IP(src="10.0.0.5", dst="45.33.32.156") / TCP(sport=50000, dport=80, seq=100, flags="PA") / Raw(
        load=b"GET /never-finishes"
    )
    packet.time = 1.0
    capture = tmp_path / "truncated.pcap"
    wrpcap(str(capture), [packet])

    report = analyze_pcap(capture, load_config(Path("does-not-exist.yaml")))

    assert any("incomplete stream" in warning for warning in report.warnings)
