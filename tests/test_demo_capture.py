"""The beaconing demo capture must actually demonstrate beaconing.

`samples/suspicious/demo_beacon_http.pcap` is the capture the README points at
and the source of the committed `docs/demo/` reports. Its six beacons were built
without setting `seq`, so scapy defaulted every one to 0 and the retransmission
guard in `flow_builder` treated beacons 2-6 as duplicates: the flow recorded a
single timestamp and the headline finding never fired.
"""

from pathlib import Path

from scapy.all import TCP, rdpcap

from nettrace.config import load_config
from nettrace.engine import analyze_pcap
from nettrace.parsers.flow_builder import update_flow

CAPTURE = Path("samples/suspicious/demo_beacon_http.pcap")


def test_demo_beacons_carry_distinct_sequence_numbers():
    beacons = [
        packet
        for packet in rdpcap(str(CAPTURE))
        if packet.haslayer(TCP) and int(packet[TCP].dport) == 4444 and bytes(packet[TCP].payload)
    ]
    sequences = [int(packet[TCP].seq) for packet in beacons]

    assert len(beacons) == 6
    assert len(set(sequences)) == len(sequences), "duplicate seq makes beacons look like retransmissions"


def test_demo_flow_records_every_beacon_not_just_the_first():
    flows: dict[tuple, object] = {}
    for number, packet in enumerate(rdpcap(str(CAPTURE)), start=1):
        update_flow(flows, packet, packet_number=number)

    beacon_flow = next(flow for flow in flows.values() if flow.dst_port == 4444)
    intervals = [
        round(b - a, 3)
        for a, b in zip(beacon_flow.beacon_timestamps, beacon_flow.beacon_timestamps[1:])
    ]

    assert len(beacon_flow.beacon_timestamps) == 7  # SYN plus six beacons
    assert intervals == [10.0] * 6


def test_demo_capture_produces_a_beaconing_finding():
    report = analyze_pcap(CAPTURE, load_config(Path("config.yaml")))

    beaconing = [f for f in report.findings if f.title == "Possible beaconing behavior"]
    assert len(beaconing) == 1
    assert beaconing[0].evidence["mean_interval_seconds"] == 10.0
    assert beaconing[0].evidence["coefficient_of_variation"] == 0.0
