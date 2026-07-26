from __future__ import annotations

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import TCP

from nettrace.models.events import DNSEvent
from nettrace.parsers.tcp_stream import TCPStreamBuffers, ip_endpoints


def _decode(value: bytes | str) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore").rstrip(".")
    return str(value).rstrip(".")


def _flatten_dns_field(value, field_name: str, count: int) -> list:
    try:
        roots = list(value)
    except TypeError:
        roots = [value] if value is not None else []
    records = []
    seen: set[int] = set()
    for root in roots:
        record = root
        while hasattr(record, field_name) and id(record) not in seen:
            seen.add(id(record))
            records.append(record)
            record = getattr(record, "payload", None)
    return records[:count] if count else records


def _answer_values(record) -> tuple[list[str], list[str]]:
    record_type = int(record.type)
    if record_type == 15 and hasattr(record, "exchange"):
        value = _decode(record.exchange)
        return [value], [value]
    if record_type == 33 and hasattr(record, "target"):
        value = _decode(record.target)
        return [value], [value]
    if record_type == 6 and hasattr(record, "mname"):
        values = [_decode(record.mname), _decode(record.rname)]
        return values, values
    if not hasattr(record, "rdata"):
        return [], []
    rdata = record.rdata
    if isinstance(rdata, list):
        value = "".join(_decode(part) for part in rdata)
    else:
        value = _decode(rdata)
    return [value], [value] if record_type in {2, 5, 12} else []


def _events_from_dns(
    dns: DNS,
    endpoints: tuple[str, str],
    timestamp: float,
    packet_number: int,
) -> list[DNSEvent]:
    if not dns.haslayer(DNSQR):
        return []
    question_count = int(dns.qdcount or 0)
    questions = _flatten_dns_field(dns.qd, "qname", question_count)
    answers = []
    answer_domains = []
    answer_ttls = []
    answer_count = int(dns.ancount or 0)
    records = _flatten_dns_field(dns.an, "rrname", answer_count)
    for record in records:
        values, domains = _answer_values(record)
        answers.extend(values)
        answer_domains.extend(domains)
        answer_ttls.extend([int(record.ttl)] * len(values))
    # Keep the scalar field for compatibility; the minimum is the effective
    # cache lifetime for the complete answer set.
    ttl = min(answer_ttls) if answer_ttls else None
    return [
        DNSEvent(
            timestamp=timestamp,
            src_ip=endpoints[0],
            dst_ip=endpoints[1],
            query=_decode(question.qname),
            answers=list(answers),
            ttl=ttl,
            packet_number=packet_number,
            answer_domains=list(answer_domains),
            answer_ttls=list(answer_ttls),
        )
        for question in questions
    ]


def extract_dns_event(packet, packet_number: int = 0) -> DNSEvent | None:
    events = extract_dns_events_from_packet(packet, packet_number)
    return events[0] if events else None


def extract_dns_events_from_packet(packet, packet_number: int = 0) -> list[DNSEvent]:
    endpoints = ip_endpoints(packet)
    if endpoints is None or not packet.haslayer(DNS):
        return []
    try:
        return _events_from_dns(packet[DNS], endpoints, float(packet.time), packet_number)
    except (ValueError, IndexError, TypeError, AttributeError):
        return []


class DNSStreamExtractor:
    """Extract length-prefixed DNS messages carried over TCP streams."""

    def __init__(self, stream_options: dict | None = None) -> None:
        self.streams = TCPStreamBuffers(**(stream_options or {}))

    def feed(self, packet, packet_number: int = 0) -> list[DNSEvent]:
        if not packet.haslayer(TCP):
            return []
        tcp = packet[TCP]
        if int(tcp.sport) != 53 and int(tcp.dport) != 53:
            return []
        state = self.streams.feed(packet, packet_number)
        if state is None:
            return []
        events: list[DNSEvent] = []
        while len(state.buffer) >= 2:
            message_length = int.from_bytes(state.buffer[:2], "big")
            if message_length == 0:
                self.streams.consume(state, 2, packet_number, float(packet.time))
                continue
            frame_length = 2 + message_length
            if len(state.buffer) < frame_length:
                break
            event_packet_number = state.first_packet_number
            event_timestamp = state.first_timestamp
            try:
                dns = DNS(bytes(state.buffer[2:frame_length]))
                parsed_events = _events_from_dns(
                    dns,
                    (state.src_ip, state.dst_ip),
                    event_timestamp,
                    event_packet_number,
                )
            except (ValueError, IndexError, TypeError, AttributeError):
                parsed_events = []
            self.streams.consume(state, frame_length, packet_number, float(packet.time))
            events.extend(parsed_events)
        if state.closing:
            self.streams.close(state)
        return events


def extract_dns_events(packets: list) -> list[DNSEvent]:
    events: list[DNSEvent] = []
    for index, packet in enumerate(packets, start=1):
        events.extend(extract_dns_events_from_packet(packet, packet_number=index))
    return events
