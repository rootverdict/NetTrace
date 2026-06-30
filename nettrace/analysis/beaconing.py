from __future__ import annotations

import statistics

from nettrace.analysis.evidence import flow_packet_evidence
from nettrace.models.events import Flow
from nettrace.models.findings import Finding


def detect_beaconing(flows: list[Flow], thresholds: dict) -> list[Finding]:
    findings: list[Finding] = []
    min_events = int(thresholds.get("beacon_min_events", 5))
    max_cv = float(thresholds.get("beacon_max_cv", 0.25))
    min_interval = float(thresholds.get("beacon_min_interval_seconds", 2))

    for flow in flows:
        timestamps = sorted(flow.timestamps)
        if len(timestamps) < min_events:
            continue
        intervals = [b - a for a, b in zip(timestamps, timestamps[1:]) if b - a > 0]
        if len(intervals) < min_events - 1:
            continue
        mean_interval = statistics.mean(intervals)
        if mean_interval < min_interval:
            continue
        stdev = statistics.stdev(intervals) if len(intervals) > 1 else 0.0
        cv = stdev / mean_interval if mean_interval else 999.0
        if cv <= max_cv:
            findings.append(
                Finding(
                    title="Possible beaconing behavior",
                    description="Regular connection timing suggests command-and-control beaconing.",
                    category="dns_beaconing" if flow.dst_port == 53 else "network_beaconing",
                    timestamp=flow.first_seen,
                    evidence={
                        "src_ip": flow.src_ip,
                        "dst_ip": flow.dst_ip,
                        "dst_port": flow.dst_port,
                        "protocol": flow.protocol,
                        "events": len(timestamps),
                        "mean_interval_seconds": round(mean_interval, 3),
                        "coefficient_of_variation": round(cv, 3),
                        **flow_packet_evidence(flow),
                    },
                    tags=["beaconing"],
                )
            )
    return findings
