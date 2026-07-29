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
    max_interval = float(thresholds.get("beacon_max_interval_seconds", 3600))
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
        contributing_indices: set[int] = set()
        while heap and processed_events < max_group_events:
            timestamp, activity_index, timestamp_index = heapq.heappop(heap)
            processed_events += 1
            contributing_indices.add(activity_index)
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
        # An upper bound as well as a lower one. Interval regularity alone does
        # not separate C2 from a scanner or scheduled job that happens to be
        # punctual: a ten-day capture of internet background noise produced 127
        # "beacons" with mean intervals of 2 to 48 hours. Real C2 in this corpus
        # beacons at 10s and 900s, and the slowest observed false positive is
        # 7,109s, so the default sits in that gap.
        if mean_interval > max_interval:
            continue
        if mean_interval < min_interval:
            continue
        stdev = math.sqrt(interval_m2 / (interval_count - 1)) if interval_count > 1 else 0.0
        cv = stdev / mean_interval if mean_interval else 999.0
        if cv <= max_cv:
            flow = activities[0][0]
            # Bug #7: aggregate evidence across every flow that fed the beacon
            # calculation, not just the first one -- a rotating-source-port
            # beacon spans multiple flows, and the old code silently attributed
            # all 30+ events to a single connection's packet numbers.
            contributing_flows = [activities[index][0] for index in sorted(contributing_indices)]
            first_packet_number = 0
            wireshark_numbers: list[int] = []
            for contributing_flow in contributing_flows:
                flow_evidence = flow_packet_evidence(contributing_flow, limit=4)
                wireshark_numbers.extend(flow_evidence.get("packet_numbers_sample", []))
                if not first_packet_number and flow_evidence.get("first_packet_number"):
                    first_packet_number = flow_evidence["first_packet_number"]
            observation_window = max((f.last_seen for f in contributing_flows), default=flow.last_seen) - min(
                (f.first_seen for f in contributing_flows), default=flow.first_seen
            )
            # Bug #6: confidence reflects how strong the signal actually is --
            # more events and a tighter coefficient of variation is stronger
            # evidence than a borderline 5-event, cv=0.24 group.
            if processed_events >= 50 and cv <= 0.05:
                confidence = "high"
            elif processed_events >= 10 and cv <= 0.15:
                confidence = "medium"
            else:
                confidence = "low"
            findings.append(
                Finding(
                    title="Possible beaconing behavior",
                    description="Regular connection timing suggests command-and-control beaconing.",
                    category="dns_beaconing" if flow.dst_port == 53 else "network_beaconing",
                    timestamp=flow.first_seen,
                    confidence=confidence,
                    evidence={
                        "src_ip": flow.src_ip,
                        "dst_ip": flow.dst_ip,
                        "dst_port": flow.dst_port,
                        "protocol": flow.protocol,
                        "events": processed_events,
                        "timing_events_truncated": bool(heap),
                        "mean_interval_seconds": round(mean_interval, 3),
                        "coefficient_of_variation": round(cv, 3),
                        "connection_count": len(contributing_flows),
                        "observation_window_seconds": round(observation_window, 3),
                        "first_packet_number": first_packet_number or flow.first_packet_number,
                        "packet_numbers_sample": wireshark_numbers[:8],
                        "wireshark_filter": (
                            "frame.number in {" + " ".join(str(n) for n in wireshark_numbers[:8]) + "}"
                            if wireshark_numbers
                            else ""
                        ),
                    },
                    tags=["beaconing"],
                )
            )
    return findings
