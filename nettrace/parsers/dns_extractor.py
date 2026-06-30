from __future__ import annotations

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP

from nettrace.models.events import DNSEvent


def _decode(value: bytes | str) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore").rstrip(".")
    return str(value).rstrip(".")


def extract_dns_event(packet, packet_number: int = 0) -> DNSEvent | None:
    if not packet.haslayer(IP) or not packet.haslayer(DNS) or not packet.haslayer(DNSQR):
        return None
    dns = packet[DNS]
    query = _decode(dns[DNSQR].qname)
    answers = []
    ttl = None
    answer_count = int(dns.ancount or 0)
    rr = dns.an
    records = []
    if isinstance(rr, DNSRR):
        while isinstance(rr, DNSRR):
            records.append(rr)
            rr = rr.payload
    else:
        try:
            records = [record for record in rr if isinstance(record, DNSRR)]
        except TypeError:
            records = []
    if answer_count:
        records = records[:answer_count]
    for record in records:
        answers.append(_decode(record.rdata))
        ttl = int(record.ttl)
    return DNSEvent(
        timestamp=float(packet.time),
        src_ip=packet[IP].src,
        dst_ip=packet[IP].dst,
        query=query,
        answers=answers,
        ttl=ttl,
        packet_number=packet_number,
    )


def extract_dns_events(packets: list) -> list[DNSEvent]:
    events: list[DNSEvent] = []
    for index, packet in enumerate(packets, start=1):
        event = extract_dns_event(packet, packet_number=index)
        if event:
            events.append(event)
    return events
