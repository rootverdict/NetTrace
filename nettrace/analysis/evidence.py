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


def collect_evidence_packet_numbers(findings: list) -> set[int]:
    """Collect all unique positive packet numbers referenced across finding evidence."""
    packet_numbers: set[int] = set()
    for finding in findings:
        evidence = getattr(finding, "evidence", {}) or {}
        if not isinstance(evidence, dict):
            continue

        if "packet_number" in evidence and isinstance(evidence["packet_number"], int) and evidence["packet_number"] > 0:
            packet_numbers.add(evidence["packet_number"])

        if "first_packet_number" in evidence and isinstance(evidence["first_packet_number"], int) and evidence["first_packet_number"] > 0:
            packet_numbers.add(evidence["first_packet_number"])

        if "packet_numbers_sample" in evidence and isinstance(evidence["packet_numbers_sample"], (list, tuple, set)):
            for num in evidence["packet_numbers_sample"]:
                if isinstance(num, int) and num > 0:
                    packet_numbers.add(num)

    return packet_numbers

