from nettrace.analysis.evidence import packet_evidence


def test_packet_evidence_omits_unknown_packet_number():
    assert packet_evidence(0) == {}
    assert packet_evidence(-1) == {}


def test_packet_evidence_adds_wireshark_frame_filter():
    assert packet_evidence(42) == {
        "packet_number": 42,
        "wireshark_filter": "frame.number == 42",
    }
