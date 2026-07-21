from scapy.all import IP, Raw, TCP

from nettrace.analysis.ftp_analyzer import analyze_ftp_events
from nettrace.parsers.ftp_extractor import FTPStreamExtractor


def test_ftp_password_is_redacted_and_upload_is_flagged():
    extractor = FTPStreamExtractor()
    packet = IP(src="10.0.0.5", dst="45.33.32.156") / TCP(sport=50000, dport=21, seq=100) / Raw(
        load=b"PASS super-secret\r\nSTOR stolen.txt\r\n"
    )
    packet.time = 1.0

    events = extractor.feed(packet, 7)
    findings = analyze_ftp_events(events)

    assert [event.command for event in events] == ["PASS", "STOR"]
    assert events[0].argument == "<redacted>"
    assert all("super-secret" not in str(finding.evidence) for finding in findings)
    assert {finding.title for finding in findings} == {"Cleartext FTP credentials", "File upload over FTP"}
