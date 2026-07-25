import random

from scapy.all import IP, Raw, TCP, fragment

from nettrace.parsers.http_extractor import HTTPStreamExtractor
from nettrace.parsers.ip_reassembly import IPFragmentReassembler


def test_random_tcp_segmentation_reassembles_single_http_request():
    payload = b"GET /fuzz.exe HTTP/1.1\r\nHost: fuzz.example\r\nUser-Agent: curl/8.0\r\n\r\n"
    rng = random.Random(1337)

    for _ in range(40):
        cut_points = sorted(rng.sample(range(1, len(payload)), rng.randint(1, 8)))
        starts = [0, *cut_points]
        ends = [*cut_points, len(payload)]
        segments = []
        for index, (start, end) in enumerate(zip(starts, ends), start=1):
            packet = (
                IP(src="10.0.0.5", dst="45.33.32.156")
                / TCP(sport=50000, dport=80, seq=1000 + start, flags="PA")
                / Raw(load=payload[start:end])
            )
            packet.time = float(index)
            segments.append(packet)
        rng.shuffle(segments)

        extractor = HTTPStreamExtractor()
        events = []
        for number, packet in enumerate(segments, start=1):
            events.extend(extractor.feed(packet, number))

        assert [(event.method, event.host, event.uri) for event in events] == [("GET", "fuzz.example", "/fuzz.exe")]


def test_random_ipv4_fragment_order_reassembles_payload():
    packet = IP(src="10.0.0.1", dst="10.0.0.2", id=4242) / TCP(sport=1234, dport=80) / Raw(b"A" * 96)
    packet.time = 1.0
    fragments = fragment(packet, fragsize=24)
    rng = random.Random(4242)

    for _ in range(20):
        shuffled = list(fragments)
        rng.shuffle(shuffled)
        reassembler = IPFragmentReassembler()
        rebuilt = None
        for number, item in enumerate(shuffled, start=1):
            item.time = float(number)
            result = reassembler.feed(item, number)
            if result is not None:
                rebuilt = result[0]

        assert rebuilt is not None
        assert bytes(rebuilt[Raw].load).endswith(b"A" * 96)
