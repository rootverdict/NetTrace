from __future__ import annotations

from pathlib import Path

from scapy.all import PcapReader


def iter_packets(path: Path):
    """Yield packets from a PCAP/PCAPNG file one at a time.

    Streaming via ``PcapReader`` keeps memory bounded on large captures -- the
    whole file is never loaded at once. Raises ``FileNotFoundError`` if the path
    does not exist so the CLI can report it as an analysis error.
    """
    if not path.exists():
        raise FileNotFoundError(f"PCAP not found: {path}")
    with PcapReader(str(path)) as reader:
        for packet in reader:
            yield packet
