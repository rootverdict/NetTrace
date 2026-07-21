from __future__ import annotations

import heapq
from typing import Any

from nettrace.models.events import DNSEvent, FTPEvent, Flow, HTTPEvent, TLSEvent
from nettrace.models.findings import Finding


def build_timeline(
    dns_events: list[DNSEvent],
    http_events: list[HTTPEvent],
    tls_events: list[TLSEvent],
    flows: list[Flow],
    findings: list[Finding],
    ftp_events: list[FTPEvent] | None = None,
    max_entries: int | None = None,
) -> list[dict[str, Any]]:
    heap: list[tuple[float, int, dict[str, Any]]] = []
    counter = 0

    def add(item: dict[str, Any]) -> None:
        nonlocal counter
        counter += 1
        if max_entries is None:
            heapq.heappush(heap, (item["timestamp"], counter, item))
            return
        entry = (-item["timestamp"], counter, item)
        if len(heap) < max_entries:
            heapq.heappush(heap, entry)
        elif item["timestamp"] < -heap[0][0]:
            heapq.heapreplace(heap, entry)

    for event in dns_events:
        add({"timestamp": event.timestamp, "type": "dns", "summary": event.query})
    for event in http_events:
        add({"timestamp": event.timestamp, "type": "http", "summary": event.url})
    for event in tls_events:
        add({"timestamp": event.timestamp, "type": "tls", "summary": event.sni or event.dst_ip})
    for event in ftp_events or []:
        add({"timestamp": event.timestamp, "type": "ftp", "summary": f"{event.command} {event.argument}".rstrip()})
    for flow in flows:
        add(
            {
                "timestamp": flow.first_seen,
                "type": "flow",
                "summary": f"{flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port} {flow.protocol}",
            }
        )
    for finding in findings:
        if finding.timestamp is not None:
            add({"timestamp": finding.timestamp, "type": "finding", "summary": finding.title})
    return sorted((entry[2] for entry in heap), key=lambda item: item["timestamp"])
