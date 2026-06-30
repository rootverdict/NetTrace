from nettrace.analysis.beaconing import detect_beaconing
from nettrace.models.events import Flow


def test_regular_intervals_create_beacon_finding():
    flow = Flow(
        src_ip="10.0.0.5",
        dst_ip="203.0.113.66",
        src_port=51515,
        dst_port=443,
        protocol="TCP",
        first_seen=0.0,
        last_seen=40.0,
        packet_count=5,
        byte_count=500,
        timestamps=[0.0, 10.0, 20.0, 30.0, 40.0],
    )
    findings = detect_beaconing(
        [flow],
        {
            "beacon_min_events": 5,
            "beacon_max_cv": 0.25,
            "beacon_min_interval_seconds": 5,
        },
    )
    assert len(findings) == 1
