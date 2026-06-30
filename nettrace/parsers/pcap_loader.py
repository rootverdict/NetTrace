from __future__ import annotations

from pathlib import Path

from scapy.all import PcapReader


def iter_packets(path: Path):
    if not path.exists():
        raise FileNotFoundError(f"PCAP not found: {path}")
    with PcapReader(str(path)) as reader:
        for packet in reader:
            yield packet
