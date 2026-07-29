"""A request split across segments must not be emitted twice.

`engine.analyze_pcap` falls back to the single-packet extractor whenever the
stream extractor produced nothing for a packet. `_parse_headers` used to accept
a header block with no terminating blank line, so the first half of a split
request was emitted as a *finished* event -- and because `Host:` had not
arrived yet, `HTTPEvent.url` fell back to the destination IP and published a URL
IOC for a request that never appeared on the wire. The reassembled real event
was then emitted too, so counts, findings and timeline entries all doubled.

The engine dedup key could not catch it: `host` and `user_agent` differ between
the phantom and the real event. Long headers and cookies make this common in
real captures.
"""

from pathlib import Path

from scapy.all import IP, Raw, TCP, wrpcap

from nettrace.config import load_config
from nettrace.engine import analyze_pcap
from nettrace.parsers.http_extractor import _parse_headers

REQUEST = (
    b"GET /update.exe HTTP/1.1\r\n"
    b"User-Agent: curl/7.68.0\r\n"
    b"Accept: */*\r\n"
    b"Host: evil.example\r\n"
    b"Connection: close\r\n"
    b"\r\n"
)


def _segment(seq: int, payload: bytes, timestamp: float):
    packet = IP(src="10.0.0.5", dst="198.51.100.20") / TCP(
        sport=50000, dport=80, seq=seq, flags="PA"
    ) / Raw(load=payload)
    packet.time = timestamp
    return packet


def _split_capture(tmp_path: Path) -> Path:
    cut = REQUEST.index(b"Host:")  # Host lands in the second segment
    packets = [_segment(1, REQUEST[:cut], 1.0), _segment(1 + cut, REQUEST[cut:], 2.0)]
    path = tmp_path / "split.pcap"
    wrpcap(str(path), packets)
    return path


def test_parse_headers_rejects_an_unterminated_header_block():
    assert _parse_headers(REQUEST[: REQUEST.index(b"Host:")]) is None
    assert _parse_headers(REQUEST) is not None


def test_split_request_yields_exactly_one_event(tmp_path: Path):
    report = analyze_pcap(_split_capture(tmp_path), load_config(Path("config.yaml")))

    assert len(report.http_events) == 1
    event = report.http_events[0]
    assert event.host == "evil.example"
    assert event.url == "http://evil.example/update.exe"


def test_split_request_does_not_fabricate_an_ip_based_url_ioc(tmp_path: Path):
    report = analyze_pcap(_split_capture(tmp_path), load_config(Path("config.yaml")))

    urls = [ioc.value for ioc in report.iocs if ioc.kind == "url"]
    assert urls == ["http://evil.example/update.exe"]
    assert not any("198.51.100.20" in url for url in urls)


def test_complete_single_packet_request_still_rescued_by_fallback(tmp_path: Path):
    """The fallback must keep working for requests that arrive intact."""
    packet = _segment(1, REQUEST, 1.0)
    packet[TCP].dport = 8080  # not an http_port, so only the fallback can see it
    path = tmp_path / "single.pcap"
    wrpcap(str(path), [packet])

    report = analyze_pcap(path, load_config(Path("config.yaml")))

    assert [event.host for event in report.http_events] == ["evil.example"]


# NetSupport RAT's C2 POSTs are complete, self-contained requests that use bare
# LF line endings. Splitting on CRLF alone collapsed each one into a single
# "line", so every header was dropped: Host and User-Agent came back empty even
# though both sat in the packet. The malware's own User-Agent is a strong IOC,
# so losing it mattered.
LF_REQUEST = (
    b"POST http://194.180.191.64/fakeurl.htm HTTP/1.1\n"
    b"User-Agent: NetSupport Manager/1.3\n"
    b"Content-Type: application/x-www-form-urlencoded\n"
    b"Content-Length:    22\n"
    b"Host: 194.180.191.64\n"
    b"Connection: Keep-Alive\n"
    b"\n"
    b"CMD=POLL\nINFO=1\nACK=1\n"
)


def test_bare_lf_request_headers_are_parsed():
    parsed = _parse_headers(LF_REQUEST)

    assert parsed is not None
    method, uri, host, user_agent = parsed
    assert method == "POST"
    assert uri == "http://194.180.191.64/fakeurl.htm"
    assert host == "194.180.191.64"
    assert user_agent == "NetSupport Manager/1.3"


def test_bare_lf_request_still_needs_its_terminator():
    head_only = LF_REQUEST.split(b"\n\n", 1)[0]
    assert _parse_headers(head_only) is None


def test_body_lines_cannot_masquerade_as_headers():
    """The LF body below contains colon-free lines, but a crafted one must not
    reach the header map -- only the head is parsed."""
    request = (
        b"POST /x HTTP/1.1\nHost: real.example\n\nHost: spoofed.example\nUser-Agent: fake\n"
    )
    method, uri, host, user_agent = _parse_headers(request)

    assert host == "real.example"
    assert user_agent == ""
