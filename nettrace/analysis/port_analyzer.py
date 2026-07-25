from __future__ import annotations

from pathlib import Path

import yaml

from nettrace.analysis.evidence import flow_packet_evidence
from nettrace.models.events import Flow
from nettrace.models.findings import Finding


DEFAULT_SUSPICIOUS_PORTS = {4444, 6667, 9001, 1337, 31337}
DEFAULT_RULES_PATH = Path(__file__).parent.parent / "rules" / "suspicious_ports.yaml"


def load_suspicious_ports(path: Path = DEFAULT_RULES_PATH) -> set[int]:
    file_path = Path(path)
    if not file_path.exists():
        return DEFAULT_SUSPICIOUS_PORTS
    data = yaml.safe_load(file_path.read_text(encoding="utf-8")) or {}
    return {int(port) for port in data.get("ports", [])}


def analyze_flows(flows: list[Flow], thresholds: dict) -> list[Finding]:
    findings: list[Finding] = []
    suspicious_ports = load_suspicious_ports()
    high_frequency = int(thresholds.get("high_frequency_connections", 50))

    for flow in flows:
        if flow.dst_port in suspicious_ports:
            findings.append(
                Finding(
                    title="Connection to suspicious non-standard port",
                    description="Traffic used a port commonly seen in malware labs, backdoors, or tunneling.",
                    category="unusual_port",
                    timestamp=flow.first_seen,
                    confidence="low",
                    evidence={
                        "src_ip": flow.src_ip,
                        "dst_ip": flow.dst_ip,
                        "dst_port": flow.dst_port,
                        "protocol": flow.protocol,
                        **flow_packet_evidence(flow),
                    },
                    tags=["non-standard-port"],
                )
            )
        if flow.packet_count >= high_frequency:
            findings.append(
                Finding(
                    title="High-frequency connection",
                    description="Flow generated a high volume of packets and may require exfiltration or C2 review.",
                    category="high_frequency_connections",
                    timestamp=flow.first_seen,
                    confidence="low",
                    evidence={
                        "src_ip": flow.src_ip,
                        "dst_ip": flow.dst_ip,
                        "dst_port": flow.dst_port,
                        "packet_count": flow.packet_count,
                        "byte_count": flow.byte_count,
                        **flow_packet_evidence(flow),
                    },
                    tags=["high-frequency"],
                )
            )
    return findings
