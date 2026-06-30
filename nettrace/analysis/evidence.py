from __future__ import annotations

from nettrace.models.events import Flow


def packet_evidence(packet_number: int = 0) -> dict:
    """Return Wireshark evidence only for real PCAP frame numbers.

    A non-positive packet number means "unknown" inside NetTrace, while Wireshark
    frames are 1-based. Omitting the field avoids creating a misleading
    frame.number <= 0 filter.
    """
    if packet_number <= 0:
        return {}
    return {
        "packet_number": packet_number,
        "wireshark_filter": f"frame.number == {packet_number}",
    }


def flow_packet_evidence(flow: Flow, limit: int = 8) -> dict:
    packet_numbers = [number for number in flow.packet_numbers if number]
    if not packet_numbers:
        return {}
    sample = packet_numbers[:limit]
    return {
        "first_packet_number": flow.first_packet_number or sample[0],
        "packet_numbers_sample": sample,
        "wireshark_filter": "frame.number in {" + " ".join(str(number) for number in sample) + "}",
    }
