from __future__ import annotations

from typing import Any

from nettrace.models.events import DNSEvent, Flow, HTTPEvent, TLSEvent
from nettrace.models.findings import Finding


def build_timeline(
    dns_events: list[DNSEvent],
    http_events: list[HTTPEvent],
    tls_events: list[TLSEvent],
    flows: list[Flow],
    findings: list[Finding],
) -> list[dict[str, Any]]:
    timeline: list[dict[str, Any]] = []
    for event in dns_events:
        timeline.append({"timestamp": event.timestamp, "type": "dns", "summary": event.query})
    for event in http_events:
        timeline.append({"timestamp": event.timestamp, "type": "http", "summary": event.url})
    for event in tls_events:
        timeline.append({"timestamp": event.timestamp, "type": "tls", "summary": event.sni or event.dst_ip})
    for flow in flows:
        timeline.append(
            {
                "timestamp": flow.first_seen,
                "type": "flow",
                "summary": f"{flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port} {flow.protocol}",
            }
        )
    for finding in findings:
        if finding.timestamp is not None:
            timeline.append({"timestamp": finding.timestamp, "type": "finding", "summary": finding.title})
    return sorted(timeline, key=lambda item: item["timestamp"])
