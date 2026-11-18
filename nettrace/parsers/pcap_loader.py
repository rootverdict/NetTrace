from __future__ import annotations

from pathlib import Path
from typing import Iterable, Set

from scapy.all import PcapReader, PcapWriter


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


def export_evidence_pcap(
    input_pcap: Path,
    output_pcap: Path,
    packet_numbers: Iterable[int],
) -> int:
    """Extract and write only specified 1-based packet numbers to a new PCAP file.

    Returns the count of packets successfully written.
    """
    targets: Set[int] = {n for n in packet_numbers if n > 0}
    if not targets:
        return 0

    output_pcap.parent.mkdir(parents=True, exist_ok=True)
    written = 0

    with PcapReader(str(input_pcap)) as reader:
        with PcapWriter(str(output_pcap), sync=True) as writer:
            for index, packet in enumerate(reader, start=1):
                if index in targets:
                    writer.write(packet)
                    written += 1
                    if written >= len(targets):
                        break

    return written

