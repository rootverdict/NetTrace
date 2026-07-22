from pathlib import Path

from scapy.all import IP, Raw, TCP, wrpcap

from nettrace.config import load_config
from nettrace.engine import analyze_pcap


def test_engine_falls_back_to_packet_http_when_stream_has_leading_gap(tmp_path: Path):
    pcap = tmp_path / "midstream-http.pcap"
    packets = [
        IP(src="10.0.0.5", dst="203.0.113.20")
        / TCP(sport=51515, dport=80, seq=200, flags="PA")
        / Raw(load=b"unrelated midstream bytes"),
        IP(src="10.0.0.5", dst="203.0.113.20")
        / TCP(sport=51515, dport=80, seq=100, flags="PA")
        / Raw(load=b"GET /payload.exe HTTP/1.1\r\nHost: malware-test.example\r\n\r\n"),
    ]
    for index, packet in enumerate(packets, start=1):
        packet.time = float(index)
    wrpcap(str(pcap), packets)

    report = analyze_pcap(pcap, load_config(Path("config.yaml")))

    assert [(event.method, event.url) for event in report.http_events] == [
        ("GET", "http://malware-test.example/payload.exe")
    ]
