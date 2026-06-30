from scapy.all import DNS, DNSQR, DNSRR, IP, UDP

from nettrace.parsers.dns_extractor import extract_dns_events


def test_extract_dns_query_and_answer():
    packet = (
        IP(src="8.8.8.8", dst="10.0.0.5")
        / UDP(sport=53, dport=53000)
        / DNS(
            qr=1,
            qd=DNSQR(qname="example.com"),
            an=DNSRR(rrname="example.com", ttl=60, rdata="203.0.113.66"),
        )
    )
    packet.time = 1.0

    events = extract_dns_events([packet])

    assert len(events) == 1
    assert events[0].query == "example.com"
    assert events[0].answers == ["203.0.113.66"]
    assert events[0].ttl == 60
    assert events[0].packet_number == 1
