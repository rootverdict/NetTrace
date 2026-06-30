from scapy.all import IP, TCP, Raw

from nettrace.parsers.http_extractor import extract_http_event, extract_http_events


def test_extract_plaintext_http_request():
    payload = (
        b"GET /payload.exe HTTP/1.1\r\n"
        b"Host: malware-test.example\r\n"
        b"User-Agent: python-requests/2.28\r\n"
        b"\r\n"
    )
    packet = IP(src="10.0.0.5", dst="198.51.100.23") / TCP(sport=51515, dport=80) / Raw(load=payload)
    packet.time = 2.0

    events = extract_http_events([packet])

    assert len(events) == 1
    assert events[0].method == "GET"
    assert events[0].host == "malware-test.example"
    assert events[0].uri == "/payload.exe"
    assert events[0].user_agent == "python-requests/2.28"
    assert events[0].packet_number == 1


def test_http_response_packet_is_not_parsed_as_request():
    payload = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    packet = IP(src="198.51.100.23", dst="10.0.0.5") / TCP(sport=80, dport=51515) / Raw(load=payload)
    packet.time = 3.0

    assert extract_http_event(packet) is None
