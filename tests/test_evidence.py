from nettrace.analysis.evidence import collect_evidence_packet_numbers, packet_evidence
from nettrace.models.findings import Finding


def test_packet_evidence_omits_unknown_packet_number():
    assert packet_evidence(0) == {}
    assert packet_evidence(-1) == {}


def test_packet_evidence_adds_wireshark_frame_filter():
    assert packet_evidence(42) == {
        "packet_number": 42,
        "wireshark_filter": "frame.number == 42",
    }


def test_collect_evidence_packet_numbers():
    f1 = Finding(
        title="F1",
        description="desc",
        category="cat",
        evidence={"packet_number": 10, "packet_numbers_sample": [10, 20, 30]},
    )
    f2 = Finding(
        title="F2",
        description="desc",
        category="cat",
        evidence={"first_packet_number": 15, "packet_numbers_sample": [15, 25]},
    )
    f3 = Finding(
        title="F3",
        description="desc",
        category="cat",
        evidence={},
    )
    numbers = collect_evidence_packet_numbers([f1, f2, f3, None])
    assert numbers == {10, 15, 20, 25, 30}

