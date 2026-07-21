from scapy.all import DNS, DNSQR, DNSRR, IP, UDP
from scapy.layers.dns import DNSRRMX, DNSRRSOA, DNSRRSRV

from nettrace.parsers.dns_extractor import extract_dns_events
from nettrace.analysis.ioc_extractor import extract_iocs


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


def test_cname_answer_is_extracted_as_domain_ioc():
    packet = (
        IP(src="8.8.8.8", dst="10.0.0.5")
        / UDP(sport=53, dport=53000)
        / DNS(
            qr=1,
            qd=DNSQR(qname="alias.example"),
            an=DNSRR(rrname="alias.example", type="CNAME", rdata="target.evil"),
        )
    )
    packet.time = 1.0

    event = extract_dns_events([packet])[0]
    iocs = extract_iocs([event], [], [], [])

    assert event.answer_domains == ["target.evil"]
    assert any(ioc.kind == "domain" and ioc.value == "target.evil" for ioc in iocs)


def test_multiple_dns_answers_preserve_each_ttl():
    answers = DNSRR(rrname="example.com", ttl=120, rdata="45.33.32.156") / DNSRR(
        rrname="example.com", ttl=60, rdata="45.33.32.157"
    )
    packet = (
        IP(src="8.8.8.8", dst="10.0.0.5")
        / UDP(sport=53, dport=53000)
        / DNS(qr=1, qd=DNSQR(qname="example.com"), ancount=2, an=answers)
    )
    packet.time = 1.0

    event = extract_dns_events([packet])[0]

    assert event.answers == ["45.33.32.156", "45.33.32.157"]
    assert event.answer_ttls == [120, 60]
    assert event.ttl == 60


def test_specialized_dns_records_extract_embedded_domains():
    answers = (
        DNSRRMX(rrname="example.com", ttl=120, exchange="mail.evil.example")
        / DNSRRSRV(rrname="_service._tcp.example.com", ttl=60, target="srv.evil.example", port=443)
        / DNSRRSOA(
            rrname="example.com",
            ttl=30,
            mname="ns.evil.example",
            rname="admin.evil.example",
        )
    )
    packet = IP(src="8.8.8.8", dst="10.0.0.5") / UDP(sport=53, dport=53000) / DNS(
        qr=1,
        qd=DNSQR(qname="example.com"),
        ancount=3,
        an=answers,
    )
    packet.time = 1.0

    event = extract_dns_events([IP(bytes(packet))])[0]

    assert event.answer_domains == [
        "mail.evil.example",
        "srv.evil.example",
        "ns.evil.example",
        "admin.evil.example",
    ]
    assert event.answer_ttls == [120, 60, 30, 30]


def test_dns_packet_with_multiple_questions_creates_an_event_per_question():
    questions = DNSQR(qname="one.example") / DNSQR(qname="two.example")
    packet = IP(src="10.0.0.5", dst="8.8.8.8") / UDP(sport=53000, dport=53) / DNS(
        qdcount=2,
        qd=questions,
    )
    packet.time = 1.0

    events = extract_dns_events([IP(bytes(packet))])

    assert [event.query for event in events] == ["one.example", "two.example"]
