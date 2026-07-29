from __future__ import annotations

from collections import defaultdict
from pathlib import Path

import yaml

from nettrace.analysis.evidence import flow_packet_evidence
from nettrace.models.events import Flow
from nettrace.models.findings import Finding


DEFAULT_SUSPICIOUS_PORTS = {4444, 6667, 9001, 1337, 31337}
DEFAULT_RULES_PATH = Path(__file__).parent.parent / "rules" / "suspicious_ports.yaml"

# How many destinations to name inside an aggregated finding. Enough to act on,
# short enough to keep the evidence readable.
MAX_LISTED_PEERS = 8


def load_suspicious_ports(path: Path = DEFAULT_RULES_PATH) -> set[int]:
    file_path = Path(path)
    if not file_path.exists():
        return DEFAULT_SUSPICIOUS_PORTS
    data = yaml.safe_load(file_path.read_text(encoding="utf-8")) or {}
    return {int(port) for port in data.get("ports", [])}


def _peer_summary(flows: list[Flow]) -> list[dict[str, object]]:
    ranked = sorted(flows, key=lambda flow: flow.packet_count, reverse=True)
    return [
        {
            "src_ip": flow.src_ip,
            "dst_ip": flow.dst_ip,
            "packet_count": flow.packet_count,
            "byte_count": flow.byte_count,
        }
        for flow in ranked[:MAX_LISTED_PEERS]
    ]


def _group_evidence(flows: list[Flow]) -> dict[str, object]:
    """Evidence for a group of flows, anchored on the busiest one.

    `flow_packet_evidence` of the busiest flow keeps the Wireshark filter and
    packet numbers pointing at traffic an analyst can actually open, while the
    counts describe the whole group.
    """
    busiest = max(flows, key=lambda flow: flow.packet_count)
    return {
        "flow_count": len(flows),
        "distinct_destinations": len({flow.dst_ip for flow in flows}),
        "distinct_sources": len({flow.src_ip for flow in flows}),
        "total_packets": sum(flow.packet_count for flow in flows),
        "total_bytes": sum(flow.byte_count for flow in flows),
        "top_peers": _peer_summary(flows),
        **flow_packet_evidence(busiest),
    }


def analyze_flows(flows: list[Flow], thresholds: dict) -> list[Finding]:
    """Aggregate port findings so one behaviour produces one finding.

    Emitting a finding per flow made these checks unusable on scanning traffic:
    a Mirai capture with 27,309 telnet flows produced 27,309 identical
    "suspicious port" findings, hit the 20,000-findings cap, and *evicted the
    unrelated real detections* from the report. Grouping keeps the same evidence
    while bounding the output by distinct behaviour rather than by flow count.
    """
    findings: list[Finding] = []
    suspicious_ports = load_suspicious_ports()
    high_frequency = int(thresholds.get("high_frequency_connections", 50))

    # Suspicious ports group by port: one scan of 27,309 hosts on telnet is one
    # behaviour, not 27,309. The destination count carries the breadth.
    by_port: dict[tuple[int, str], list[Flow]] = defaultdict(list)
    # High-frequency groups by destination endpoint instead: volume to a single
    # peer is the signal, so separate peers stay separate findings.
    by_peer: dict[tuple[str, int, str], list[Flow]] = defaultdict(list)

    for flow in flows:
        if flow.dst_port in suspicious_ports:
            by_port[(flow.dst_port, flow.protocol)].append(flow)
        if flow.packet_count >= high_frequency:
            by_peer[(flow.dst_ip, flow.dst_port, flow.protocol)].append(flow)

    for (dst_port, protocol), group in sorted(by_port.items()):
        evidence = _group_evidence(group)
        destinations = evidence["distinct_destinations"]
        if destinations > 1:
            description = (
                f"{evidence['flow_count']} flows reached {destinations} destinations on port "
                f"{dst_port}, a port commonly seen in malware labs, backdoors, or tunneling. "
                "Traffic spread across many destinations on one port also resembles scanning."
            )
        else:
            description = (
                "Traffic used a port commonly seen in malware labs, backdoors, or tunneling."
            )
        findings.append(
            Finding(
                title="Connection to suspicious non-standard port",
                description=description,
                category="unusual_port",
                timestamp=min(flow.first_seen for flow in group),
                confidence="low",
                evidence={
                    "dst_port": dst_port,
                    "protocol": protocol,
                    # Kept for single-destination groups so the common case reads
                    # exactly as it did before aggregation.
                    **({"dst_ip": group[0].dst_ip, "src_ip": group[0].src_ip} if destinations == 1 else {}),
                    **evidence,
                },
                tags=["non-standard-port"],
            )
        )

    for (dst_ip, dst_port, protocol), group in sorted(by_peer.items()):
        evidence = _group_evidence(group)
        findings.append(
            Finding(
                title="High-frequency connection",
                description=(
                    "Flow generated a high volume of packets and may require exfiltration or C2 review."
                    if len(group) == 1
                    else f"{len(group)} separate flows to this destination each exceeded the "
                    f"{high_frequency}-packet threshold and may require exfiltration or C2 review."
                ),
                category="high_frequency_connections",
                timestamp=min(flow.first_seen for flow in group),
                confidence="low",
                evidence={
                    "src_ip": group[0].src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "protocol": protocol,
                    "packet_count": evidence["total_packets"],
                    "byte_count": evidence["total_bytes"],
                    **evidence,
                },
                tags=["high-frequency"],
            )
        )

    return findings
