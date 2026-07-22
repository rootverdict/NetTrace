from scapy.all import IP, Raw, TCP, UDP

from nettrace.parsers.tls_extractor import (
    TLSStreamExtractor,
    extract_sni,
    extract_tls_event,
    extract_tls_events,
)


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


def tls_packet(payload: bytes, *, dport: int = 443, seq: int = 100):
    packet = IP(src="10.0.0.5", dst="203.0.113.8") / TCP(
        sport=50000, dport=dport, seq=seq, flags="PA"
    ) / Raw(load=payload)
    packet.time = 12.5
    return packet


def test_extract_sni_rejects_non_tls_and_malformed_client_hello():
    assert extract_sni(b"") == ""
    assert extract_sni(b"GET / HTTP/1.1\r\n") == ""
    assert extract_sni(b"\x16\x03\x01\x00\x2a" + b"\x01" + (b"\x00" * 41)) == ""


def test_extract_tls_event_preserves_packet_metadata():
    event = extract_tls_event(tls_packet(tls_client_hello("edge.example")), packet_number=9)

    assert event is not None
    assert event.sni == "edge.example"
    assert event.timestamp == 12.5
    assert event.src_ip == "10.0.0.5"
    assert event.dst_port == 443
    assert event.src_port == 50000
    assert event.packet_number == 9


def test_extract_tls_event_rejects_unsupported_packets():
    udp = IP(src="10.0.0.5", dst="203.0.113.8") / UDP(sport=50000, dport=443) / Raw(load=b"x")
    no_payload = IP(src="10.0.0.5", dst="203.0.113.8") / TCP(sport=50000, dport=443)

    assert extract_tls_event(udp) is None
    assert extract_tls_event(no_payload) is None
    assert extract_tls_event(tls_packet(tls_client_hello("ignored.example"), dport=80)) is None
    assert extract_tls_event(tls_packet(b"not tls")) is None


def test_extract_tls_events_filters_invalid_packets_and_numbers_matches():
    invalid = tls_packet(b"not tls")
    valid = tls_packet(tls_client_hello("batch.example"))

    events = extract_tls_events([invalid, valid])

    assert [event.sni for event in events] == ["batch.example"]
    assert events[0].packet_number == 2


def test_tls_stream_skips_complete_non_handshake_record_before_client_hello():
    application_data = b"\x17\x03\x03\x00\x03abc"
    extractor = TLSStreamExtractor()

    events = extractor.feed(tls_packet(application_data + tls_client_hello("stream.example")), 4)

    assert [event.sni for event in events] == ["stream.example"]
    assert events[0].packet_number == 4


def test_tls_stream_retains_incomplete_or_unrecognized_data():
    extractor = TLSStreamExtractor()

    assert extractor.feed(tls_packet(b"\x16\x03\x01\x00\x20short"), 1) == []
    assert TLSStreamExtractor().feed(tls_packet(b"xxxxx"), 2) == []
    assert TLSStreamExtractor().feed(tls_packet(tls_client_hello("ignored.example"), dport=80), 3) == []
