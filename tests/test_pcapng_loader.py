from pathlib import Path
import struct

import pytest
from scapy.all import DNS, DNSQR, Ether, IP, UDP
from scapy.error import Scapy_Exception
from scapy.utils import PcapNgWriter, RawPcapNgWriter

from nettrace.parsers.pcap_loader import iter_packets


def _pcapng_block(block_type: int, body: bytes) -> bytes:
    total_length = 12 + len(body)
    return struct.pack("<II", block_type, total_length) + body + struct.pack("<I", total_length)


def _dns_packet(query: str, timestamp: float = 1.0):
    packet = IP(src="10.0.0.5", dst="8.8.8.8") / UDP(sport=53000, dport=53) / DNS(qd=DNSQR(qname=query))
    packet.time = timestamp
    return packet


def test_iter_packets_reads_standard_pcapng(tmp_path):
    capture = tmp_path / "standard.pcapng"
    packet = _dns_packet("pcapng.example", timestamp=1.25)
    with PcapNgWriter(str(capture)) as writer:
        writer.write(packet)

    packets = list(iter_packets(capture))

    assert len(packets) == 1
    assert packets[0][DNSQR].qname == b"pcapng.example."


def test_iter_packets_reads_pcapng_with_multiple_packets_and_timestamps(tmp_path):
    capture = tmp_path / "timestamps.pcapng"
    packets = [_dns_packet("one.example", 1.125), _dns_packet("two.example", 2.123456)]
    with PcapNgWriter(str(capture)) as writer:
        for packet in packets:
            writer.write(packet)

    loaded = list(iter_packets(capture))

    assert [packet[DNSQR].qname for packet in loaded] == [b"one.example.", b"two.example."]
    assert [round(float(packet.time), 6) for packet in loaded] == [1.125, 2.123456]


def test_iter_packets_reads_pcapng_multiple_interfaces_and_link_layers(tmp_path):
    capture = tmp_path / "interfaces.pcapng"
    ethernet_packet = Ether() / _dns_packet("ethernet.example", timestamp=3.0)
    ethernet_packet.sniffed_on = "eth0"
    raw_ip_packet = _dns_packet("raw-ip.example", timestamp=4.0)
    raw_ip_packet.sniffed_on = "tun0"

    with RawPcapNgWriter(str(capture)) as writer:
        writer.write(ethernet_packet)
        writer.write(raw_ip_packet)

    loaded = list(iter_packets(capture))

    assert loaded[0].haslayer(Ether)
    assert loaded[0][DNSQR].qname == b"ethernet.example."
    assert loaded[1].haslayer(IP)
    assert loaded[1][DNSQR].qname == b"raw-ip.example."


def test_iter_packets_reads_pcapng_nanosecond_timestamps(tmp_path):
    capture = tmp_path / "nanosecond.pcapng"
    packet = bytes(Ether() / _dns_packet("nano.example", timestamp=1.0))
    shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    # IDB: Ethernet linktype, snaplen, if_tsresol option set to 10^-9 seconds.
    idb_body = struct.pack("<HHI", 1, 0, 262144)
    idb_body += struct.pack("<HH", 9, 1) + b"\x09\x00\x00\x00"
    idb_body += struct.pack("<HH", 0, 0)
    timestamp_ns = 1_500_000_123
    epb_body = struct.pack(
        "<IIIII",
        0,
        timestamp_ns >> 32,
        timestamp_ns & 0xFFFFFFFF,
        len(packet),
        len(packet),
    )
    epb_body += packet + (b"\x00" * ((4 - len(packet) % 4) % 4))
    capture.write_bytes(_pcapng_block(0x0A0D0D0A, shb_body) + _pcapng_block(1, idb_body) + _pcapng_block(6, epb_body))

    loaded = list(iter_packets(capture))

    assert len(loaded) == 1
    assert loaded[0][DNSQR].qname == b"nano.example."
    assert round(float(loaded[0].time), 9) == 1.500000123


def test_iter_packets_reports_malformed_pcapng(tmp_path):
    capture = tmp_path / "malformed.pcapng"
    capture.write_bytes(b"\x0a\x0d\x0d\x0a\x1c\x00\x00\x00broken")

    with pytest.raises((Scapy_Exception, EOFError, ValueError)):
        list(iter_packets(capture))
