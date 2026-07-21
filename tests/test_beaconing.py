from nettrace.analysis.beaconing import detect_beaconing
from nettrace.models.events import Flow
from nettrace.parsers.flow_builder import build_flows
from scapy.all import IP, TCP


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


def test_beaconing_groups_connections_with_rotating_ephemeral_ports():
    packets = []
    for index in range(5):
        packet = IP(src="10.0.0.5", dst="45.33.32.156") / TCP(
            sport=50000 + index,
            dport=443,
            flags="S",
            seq=index + 1,
        )
        packet.time = float(index * 10)
        packets.append(packet)

    findings = detect_beaconing(
        build_flows(packets),
        {"beacon_min_events": 5, "beacon_max_cv": 0.25, "beacon_min_interval_seconds": 2},
    )

    assert len(findings) == 1
    assert findings[0].evidence["events"] == 5


def test_beaconing_caps_group_timing_work():
    flow = Flow(
        "10.0.0.5",
        "45.33.32.156",
        50000,
        443,
        "TCP",
        0.0,
        190.0,
        beacon_timestamps=[float(index * 10) for index in range(20)],
    )

    findings = detect_beaconing(
        [flow],
        {
            "beacon_min_events": 5,
            "beacon_max_cv": 0.25,
            "beacon_min_interval_seconds": 2,
            "beacon_max_group_events": 10,
        },
    )

    assert findings[0].evidence["events"] == 10
    assert findings[0].evidence["timing_events_truncated"] is True
