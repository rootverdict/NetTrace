"""Regression tests for bug #1: a message whose final bytes ride in a
FIN/RST-bearing TCP segment must still be parsed, not silently dropped.

Before the fix, feed() buffered the FIN/RST payload and then removed the
stream and returned None, so the extractor never saw the completed message.
"""

from scapy.all import IP, Raw, TCP
from scapy.layers.dns import DNS, DNSQR

from nettrace.parsers.dns_extractor import DNSStreamExtractor
from nettrace.parsers.ftp_extractor import FTPStreamExtractor
from nettrace.parsers.http_extractor import HTTPStreamExtractor
from nettrace.parsers.tls_extractor import TLSStreamExtractor


def _seg(sport, dport, seq, payload, flags="A", t=1.0):
    packet = IP(src="10.0.0.5", dst="203.0.113.10") / TCP(sport=sport, dport=dport, seq=seq, flags=flags) / Raw(load=payload)
    packet.time = t
    return packet


def test_ftp_command_in_fin_segment_is_parsed():
    extractor = FTPStreamExtractor()
    events = extractor.feed(_seg(50000, 21, 1000, b"RETR secret_payload.bin\r\n", flags="FA"), 1)
    assert [(e.command, e.argument) for e in events] == [("RETR", "secret_payload.bin")]
    assert extractor.streams.incomplete_streams == 0


def test_multi_segment_http_request_completed_by_fin_is_parsed():
    extractor = HTTPStreamExtractor()
    part1 = b"GET /malware.exe HTTP/1.1\r\nHost: ev"
    assert extractor.feed(_seg(50000, 80, 2000, part1, flags="A", t=1.0), 1) == []
    events = extractor.feed(
        _seg(50000, 80, 2000 + len(part1), b"il.com\r\nUser-Agent: badbot\r\n\r\n", flags="FA", t=1.1),
        2,
    )
    assert len(events) == 1
    assert (events[0].method, events[0].host, events[0].uri) == ("GET", "evil.com", "/malware.exe")
    assert extractor.streams.incomplete_streams == 0


def test_dns_over_tcp_message_in_fin_segment_is_parsed():
    extractor = DNSStreamExtractor()
    message = bytes(DNS(rd=1, qd=DNSQR(qname="c2.evil.example")))
    frame = len(message).to_bytes(2, "big") + message
    events = extractor.feed(_seg(50000, 53, 3000, frame, flags="FA"), 1)
    assert [e.query for e in events] == ["c2.evil.example"]
    assert extractor.streams.incomplete_streams == 0


def _tls_client_hello(hostname: str) -> bytes:
    name = hostname.encode()
    name_entry = b"\x00" + len(name).to_bytes(2, "big") + name
    server_name_data = len(name_entry).to_bytes(2, "big") + name_entry
    extension = b"\x00\x00" + len(server_name_data).to_bytes(2, "big") + server_name_data
    body = b"\x03\x03" + (b"R" * 32) + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00" + len(extension).to_bytes(2, "big") + extension
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    record = b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake
    return record


def test_tls_client_hello_in_fin_segment_is_parsed():
    extractor = TLSStreamExtractor()
    payload = _tls_client_hello("c2.evil.example")
    events = extractor.feed(_seg(50000, 443, 4000, payload, flags="FA"), 1)
    assert [e.sni for e in events] == ["c2.evil.example"]
    assert extractor.streams.incomplete_streams == 0
