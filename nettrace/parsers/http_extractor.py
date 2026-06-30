from __future__ import annotations

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from nettrace.models.events import HTTPEvent

HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"}
HTTP_PORTS = {80, 8080, 8000, 8888}


def _parse_headers(payload: bytes) -> tuple[str, str, str, str] | None:
    try:
        text = payload.decode("iso-8859-1", errors="ignore")
    except Exception:
        return None
    lines = text.split("\r\n")
    if not lines:
        return None
    parts = lines[0].split()
    if len(parts) < 2 or parts[0] not in HTTP_METHODS:
        return None
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
    return parts[0], parts[1], headers.get("host", ""), headers.get("user-agent", "")


def extract_http_event(packet, packet_number: int = 0) -> HTTPEvent | None:
    if not packet.haslayer(IP) or not packet.haslayer(TCP) or not packet.haslayer(Raw):
        return None
    tcp = packet[TCP]
    if tcp.dport not in HTTP_PORTS:
        return None
    parsed = _parse_headers(bytes(packet[Raw].load))
    if not parsed:
        return None
    method, uri, host, user_agent = parsed
    return HTTPEvent(
        timestamp=float(packet.time),
        src_ip=packet[IP].src,
        dst_ip=packet[IP].dst,
        method=method,
        host=host,
        uri=uri,
        user_agent=user_agent,
        packet_number=packet_number,
    )


def extract_http_events(packets: list) -> list[HTTPEvent]:
    events: list[HTTPEvent] = []
    for index, packet in enumerate(packets, start=1):
        event = extract_http_event(packet, packet_number=index)
        if event:
            events.append(event)
    return events
