from __future__ import annotations

from nettrace.analysis.evidence import flow_packet_evidence, packet_evidence
from nettrace.models.events import Flow, TLSEvent
from nettrace.models.findings import Finding
from nettrace.parsers.tls_extractor import TLS_PORTS


def analyze_tls_events(tls_events: list[TLSEvent], flows: list[Flow], thresholds: dict) -> list[Finding]:
    findings: list[Finding] = []
    long_session = float(thresholds.get("long_tls_session_seconds", 900))
    sni_length_threshold = int(thresholds.get("tls_sni_length_threshold", 24))
    tls_connections = {
        (event.src_ip, event.dst_ip, event.src_port, event.dst_port)
        for event in tls_events
        if event.src_port
    }
    tls_endpoints = {(event.src_ip, event.dst_ip, event.dst_port) for event in tls_events}
    for flow in flows:
        confirmed_tls = (
            (flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port) in tls_connections
            or (flow.src_ip, flow.dst_ip, flow.dst_port) in tls_endpoints
        )
        if flow.protocol == "TCP" and flow.dst_port in TLS_PORTS and confirmed_tls and flow.duration >= long_session:
            findings.append(
                Finding(
                    title="Long TLS session",
                    description="Extended confirmed TLS session may indicate encrypted command-and-control activity.",
                    category="long_tls_session",
                    timestamp=flow.first_seen,
                    evidence={
                        "src_ip": flow.src_ip,
                        "dst_ip": flow.dst_ip,
                        "duration_seconds": round(flow.duration, 3),
                        "packet_count": flow.packet_count,
                        **flow_packet_evidence(flow),
                    },
                    tags=["tls", "encrypted-channel"],
                )
            )
    for event in tls_events:
        if event.sni and len(event.sni.split(".")[0]) > sni_length_threshold:
            findings.append(
                Finding(
                    title="Unusually long TLS SNI",
                    description="The TLS SNI hostname is unusually long and may be algorithmically generated.",
                    category="tls_c2",
                    timestamp=event.timestamp,
                    evidence={"sni": event.sni, "dst_ip": event.dst_ip, **packet_evidence(event.packet_number)},
                    tags=["tls", "sni"],
                )
            )
    return findings
