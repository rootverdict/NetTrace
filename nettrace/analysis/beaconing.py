from __future__ import annotations

import heapq
import math
from collections import defaultdict

from nettrace.analysis.evidence import flow_packet_evidence
from nettrace.models.events import Flow
from nettrace.models.findings import Finding


def detect_beaconing(flows: list[Flow], thresholds: dict) -> list[Finding]:
    findings: list[Finding] = []
    min_events = int(thresholds.get("beacon_min_events", 5))
    max_cv = float(thresholds.get("beacon_max_cv", 0.25))
    min_interval = float(thresholds.get("beacon_min_interval_seconds", 2))
    max_group_events = int(thresholds.get("beacon_max_group_events", 10_000))

    grouped: dict[tuple[str, str, int, str], list[Flow]] = defaultdict(list)
    for flow in flows:
        activity = flow.beacon_timestamps or flow.timestamps
        if activity:
            grouped[(flow.src_ip, flow.dst_ip, flow.dst_port, flow.protocol)].append(flow)

    for group_flows in grouped.values():
        activities: list[tuple[Flow, list[float]]] = []
        heap: list[tuple[float, int, int]] = []
        for flow in group_flows:
            timestamps = flow.beacon_timestamps or flow.timestamps
            ordered = timestamps if all(a <= b for a, b in zip(timestamps, timestamps[1:])) else sorted(timestamps)
            activity_index = len(activities)
            activities.append((flow, ordered))
            heapq.heappush(heap, (ordered[0], activity_index, 0))

        processed_events = 0
        interval_count = 0
        mean_interval = 0.0
        interval_m2 = 0.0
        previous_timestamp: float | None = None
        while heap and processed_events < max_group_events:
            timestamp, activity_index, timestamp_index = heapq.heappop(heap)
            processed_events += 1
            if previous_timestamp is not None:
                interval = timestamp - previous_timestamp
                if interval > 0:
                    interval_count += 1
                    delta = interval - mean_interval
                    mean_interval += delta / interval_count
                    interval_m2 += delta * (interval - mean_interval)
            previous_timestamp = timestamp
            next_index = timestamp_index + 1
            timestamps = activities[activity_index][1]
            if next_index < len(timestamps):
                heapq.heappush(heap, (timestamps[next_index], activity_index, next_index))

        if processed_events < min_events or interval_count < min_events - 1:
            continue
        if mean_interval < min_interval:
            continue
        stdev = math.sqrt(interval_m2 / (interval_count - 1)) if interval_count > 1 else 0.0
        cv = stdev / mean_interval if mean_interval else 999.0
        if cv <= max_cv:
            flow = activities[0][0]
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
                        "events": processed_events,
                        "timing_events_truncated": bool(heap),
                        "mean_interval_seconds": round(mean_interval, 3),
                        "coefficient_of_variation": round(cv, 3),
                        **flow_packet_evidence(flow),
                    },
                    tags=["beaconing"],
                )
            )
    return findings
