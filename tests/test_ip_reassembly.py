from scapy.all import IP, IPv6, IPv6ExtHdrFragment, Raw

from nettrace.parsers.ip_reassembly import IPFragmentReassembler


def ipv4_fragment(ident: int, offset: int, payload: bytes, *, more: bool = True):
    packet = IP(
        src="10.0.0.1",
        dst="10.0.0.2",
        id=ident,
        proto=253,
        frag=offset,
        flags="MF" if more else 0,
    ) / Raw(payload)
    packet.time = float(ident)
    return packet


def test_non_fragment_packet_passes_through_unchanged():
    packet = IP(src="10.0.0.1", dst="10.0.0.2") / Raw(b"payload")
    result = IPFragmentReassembler().feed(packet, 7)

    assert result == (packet, 7)


def test_ipv4_fragments_reassemble_and_keep_first_packet_metadata():
    reassembler = IPFragmentReassembler()
    first = ipv4_fragment(10, 0, b"ABCDEFGH")
    second = ipv4_fragment(10, 1, b"IJKL", more=False)
    second.time = 99.0

    assert reassembler.feed(first, 3) is None
    rebuilt, packet_number = reassembler.feed(second, 4)

    assert packet_number == 3
    assert rebuilt.time == 10.0
    assert bytes(rebuilt[IP].payload) == b"ABCDEFGHIJKL"
    assert int(rebuilt[IP].frag) == 0
    assert not rebuilt[IP].flags.MF
    assert reassembler.incomplete_datagrams == 0


def test_ipv6_fragments_reassemble_without_fragment_header():
    reassembler = IPFragmentReassembler()
    first = IPv6(src="2001:db8::1", dst="2001:db8::2") / IPv6ExtHdrFragment(
        nh=253, id=22, offset=0, m=1
    ) / Raw(b"ABCDEFGH")
    second = IPv6(src="2001:db8::1", dst="2001:db8::2") / IPv6ExtHdrFragment(
        nh=253, id=22, offset=1, m=0
    ) / Raw(b"IJKL")
    first.time = 2.0
    second.time = 3.0

    assert reassembler.feed(first, 8) is None
    rebuilt, packet_number = reassembler.feed(second, 9)

    assert packet_number == 8
    assert rebuilt.time == 2.0
    assert not rebuilt.haslayer(IPv6ExtHdrFragment)
    assert bytes(rebuilt[IPv6].payload) == b"ABCDEFGHIJKL"


def test_overlapping_or_conflicting_fragments_discard_datagram():
    overlap = IPFragmentReassembler()
    assert overlap.feed(ipv4_fragment(30, 0, b"A" * 16), 1) is None
    assert overlap.feed(ipv4_fragment(30, 1, b"B" * 8, more=False), 2) is None
    assert overlap.discarded_datagrams == 1
    assert overlap.incomplete_datagrams == 0

    duplicate = IPFragmentReassembler()
    assert duplicate.feed(ipv4_fragment(31, 0, b"A" * 8), 1) is None
    assert duplicate.feed(ipv4_fragment(31, 0, b"B" * 8), 2) is None
    assert duplicate.discarded_datagrams == 1


def test_fragment_and_datagram_resource_limits_evict_state():
    fragments = IPFragmentReassembler(max_fragments_per_datagram=1)
    assert fragments.feed(ipv4_fragment(40, 0, b"A" * 8), 1) is None
    assert fragments.feed(ipv4_fragment(40, 1, b"B" * 8), 2) is None
    assert fragments.discarded_datagrams == 1

    datagrams = IPFragmentReassembler(max_datagrams=1)
    assert datagrams.feed(ipv4_fragment(41, 0, b"A" * 8), 1) is None
    assert datagrams.feed(ipv4_fragment(42, 0, b"B" * 8), 2) is None
    assert datagrams.incomplete_datagrams == 1
    assert datagrams.discarded_datagrams == 1


def test_conflicting_final_lengths_discard_datagram():
    reassembler = IPFragmentReassembler()
    assert reassembler.feed(ipv4_fragment(50, 1, b"A" * 8, more=False), 1) is None
    assert reassembler.feed(ipv4_fragment(50, 2, b"B" * 8, more=False), 2) is None

    assert reassembler.discarded_datagrams == 1
    assert reassembler.incomplete_datagrams == 0
