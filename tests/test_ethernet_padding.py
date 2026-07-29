"""Ethernet padding must never be treated as TCP stream payload.

A frame below the 60-byte Ethernet minimum is zero-padded on the wire. Scapy
dissects that padding as a `Padding` layer beneath TCP, so `bytes(tcp.payload)`
on a bare ACK returns six zero bytes. Feeding those into reassembly opened a
phantom stream at the sequence number the *next* real segment would use; the
real segment then looked like a conflicting retransmission, the overlap policy
rejected it, and the stream was left holding padding it could never parse.

Every other reassembly test builds bare `IP()/TCP()/Raw()` packets, which never
carry padding -- these tests deliberately round-trip through `Ether()` and real
serialization so the padding is actually present.
"""

from scapy.all import Ether, IP, Raw, TCP
from scapy.packet import Padding

from nettrace.parsers.flow_builder import update_flow
from nettrace.parsers.tcp_stream import TCPStreamBuffers, tcp_payload
from nettrace.parsers.tls_extractor import TLSStreamExtractor

CLIENT = "10.0.0.101"
SERVER = "203.0.113.10"
ETHERNET_MIN_FRAME = 60


def _ethernet(payload):
    return Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / payload


def _wire(packet, timestamp: float = 1.0):
    """Serialize, pad to the Ethernet minimum, and re-dissect.

    The padding is applied by the sending NIC rather than by scapy, so it has
    to be added explicitly here to reproduce what a real capture contains.
    """
    raw = bytes(packet)
    if len(raw) < ETHERNET_MIN_FRAME:
        raw += b"\x00" * (ETHERNET_MIN_FRAME - len(raw))
    rebuilt = Ether(raw)
    rebuilt.time = timestamp
    return rebuilt


def _ack(seq: int, timestamp: float = 1.0, dport: int = 443):
    return _wire(
        _ethernet(IP(src=CLIENT, dst=SERVER) / TCP(sport=50000, dport=dport, seq=seq, flags="A")),
        timestamp,
    )


def _data(seq: int, payload: bytes, timestamp: float = 1.0, dport: int = 443):
    return _wire(
        _ethernet(
            IP(src=CLIENT, dst=SERVER) / TCP(sport=50000, dport=dport, seq=seq, flags="PA") / Raw(load=payload)
        ),
        timestamp,
    )


def _client_hello(host: str) -> bytes:
    name = host.encode()
    server_name_list = b"\x00" + len(name).to_bytes(2, "big") + name
    sni_extension_body = len(server_name_list).to_bytes(2, "big") + server_name_list
    extension = b"\x00\x00" + len(sni_extension_body).to_bytes(2, "big") + sni_extension_body
    body = (
        b"\x03\x03"
        + b"\x00" * 32  # random
        + b"\x00"  # session id length
        + b"\x00\x02\x00\x2f"  # cipher suites
        + b"\x01\x00"  # compression methods
        + len(extension).to_bytes(2, "big")
        + extension
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake


def test_bare_ack_frame_really_carries_ethernet_padding():
    """Guard the premise: without padding these tests would prove nothing."""
    packet = _ack(1000)
    assert packet.haslayer(Padding)
    assert len(bytes(packet[TCP].payload)) == 6
    assert tcp_payload(packet) == b""


def test_padding_is_not_buffered_as_stream_data():
    buffers = TCPStreamBuffers()
    assert buffers.feed(_ack(1000), 1) is None
    assert buffers.total_buffered_bytes == 0
    assert buffers.incomplete_streams == 0


def test_padded_ack_does_not_reject_the_following_real_segment():
    """The padded ACK and the real data share a stream *and* a sequence number."""
    buffers = TCPStreamBuffers()
    buffers.feed(_ack(1000, dport=80), 1)
    state = buffers.feed(_data(1000, b"GET / HTTP/1.1\r\n\r\n", dport=80), 2)
    assert state is not None
    assert bytes(state.buffer) == b"GET / HTTP/1.1\r\n\r\n"
    assert buffers.conflicting_overlaps == 0
    assert buffers.discarded_streams == 0


def test_tls_sni_survives_a_padded_ack_at_the_same_sequence():
    extractor = TLSStreamExtractor()
    extractor.feed(_ack(1000), 1)
    events = extractor.feed(_data(1000, _client_hello("evil.example")), 2)
    assert [event.sni for event in events] == ["evil.example"]
    assert extractor.streams.conflicting_overlaps == 0


def test_padded_ack_does_not_count_as_a_beacon_event():
    """`Padding` subclasses `Raw`, so haslayer(Raw) is true for a bare ACK."""
    flows: dict[tuple, object] = {}
    update_flow(flows, _ack(1000, timestamp=1.0, dport=80), packet_number=1)
    flow = next(iter(flows.values()))
    assert flow.beacon_timestamps == []

    update_flow(flows, _data(1000, b"hello", timestamp=2.0, dport=80), packet_number=2)
    assert flow.beacon_timestamps == [2.0]


def test_padding_does_not_inflate_tracked_sequence_numbers():
    flows: dict[tuple, object] = {}
    update_flow(flows, _ack(1000, dport=80), packet_number=1)
    flow = next(iter(flows.values()))
    assert flow.tcp_seq_floor == 1000
    assert flow.tcp_seq_next == 1000


def test_payload_longer_than_the_minimum_frame_is_untouched():
    payload = b"A" * 200
    packet = _data(1000, payload, dport=80)
    assert not packet.haslayer(Padding)
    assert tcp_payload(packet) == payload


def test_short_payload_keeps_its_data_and_drops_only_the_padding():
    packet = _data(1000, b"hi", dport=80)
    assert packet.haslayer(Padding)
    assert tcp_payload(packet) == b"hi"


def test_hand_built_packets_without_ethernet_are_unaffected():
    """Hand-built packets have no Padding layer; existing tests must still pass."""
    packet = IP(src=CLIENT, dst=SERVER) / TCP(sport=50000, dport=80, seq=1) / Raw(load=b"x")
    assert tcp_payload(packet) == b"x"
