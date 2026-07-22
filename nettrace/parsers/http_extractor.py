from __future__ import annotations

from scapy.layers.inet import TCP
from scapy.packet import Raw

from nettrace.models.events import HTTPEvent
from nettrace.parsers.tcp_stream import TCPStreamBuffers, ip_endpoints

HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"}
HTTP_PORTS = {80, 8080, 8000, 8888}


def _chunked_message_length(buffer: bytearray, body_start: int) -> int | None:
    cursor = body_start
    while True:
        line_end = buffer.find(b"\r\n", cursor)
        if line_end < 0:
            return None
        size_text = bytes(buffer[cursor:line_end]).split(b";", 1)[0].strip()
        try:
            chunk_size = int(size_text, 16)
        except ValueError:
            return None
        cursor = line_end + 2
        if chunk_size == 0:
            while True:
                trailer_start = cursor
                trailer_end = buffer.find(b"\r\n", cursor)
                if trailer_end < 0:
                    return None
                cursor = trailer_end + 2
                if trailer_end == trailer_start:
                    return cursor
        chunk_end = cursor + chunk_size
        if len(buffer) < chunk_end + 2:
            return None
        if buffer[chunk_end : chunk_end + 2] != b"\r\n":
            return None
        cursor = chunk_end + 2


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


def extract_http_event(
    packet,
    packet_number: int = 0,
    http_ports: set[int] | None = None,
    allow_any_port: bool = False,
) -> HTTPEvent | None:
    endpoints = ip_endpoints(packet)
    if endpoints is None or not packet.haslayer(TCP) or not packet.haslayer(Raw):
        return None
    tcp = packet[TCP]
    ports = HTTP_PORTS if http_ports is None else http_ports
    if tcp.dport not in ports and not allow_any_port:
        return None
    parsed = _parse_headers(bytes(packet[Raw].load))
    if not parsed:
        return None
    method, uri, host, user_agent = parsed
    return HTTPEvent(
        timestamp=float(packet.time),
        src_ip=endpoints[0],
        dst_ip=endpoints[1],
        method=method,
        host=host,
        uri=uri,
        user_agent=user_agent,
        packet_number=packet_number,
    )


class HTTPStreamExtractor:
    def __init__(self, http_ports: set[int] | None = None, stream_options: dict | None = None) -> None:
        self.streams = TCPStreamBuffers(**(stream_options or {}))
        self.http_ports = HTTP_PORTS if http_ports is None else http_ports

    def feed(self, packet, packet_number: int = 0) -> list[HTTPEvent]:
        if not packet.haslayer(TCP) or int(packet[TCP].dport) not in self.http_ports:
            return []
        state = self.streams.feed(packet, packet_number)
        if state is None:
            return []
        events: list[HTTPEvent] = []
        while True:
            header_end = state.buffer.find(b"\r\n\r\n")
            if header_end < 0:
                break
            header_length = header_end + 4
            header = bytes(state.buffer[:header_length])
            content_length = 0
            chunked = False
            invalid_content_length = False
            for line in header.split(b"\r\n")[1:]:
                if line.lower().startswith(b"content-length:"):
                    try:
                        content_length = max(0, int(line.split(b":", 1)[1].strip()))
                    except ValueError:
                        invalid_content_length = True
                elif line.lower().startswith(b"transfer-encoding:"):
                    encodings = [value.strip().lower() for value in line.split(b":", 1)[1].split(b",")]
                    chunked = b"chunked" in encodings
            if invalid_content_length and not chunked:
                break
            if chunked:
                chunked_length = _chunked_message_length(state.buffer, header_length)
                if chunked_length is None:
                    break
                total_length = chunked_length
            else:
                total_length = header_length + content_length
            if len(state.buffer) < total_length:
                break
            parsed = _parse_headers(header)
            if parsed:
                method, uri, host, user_agent = parsed
                events.append(
                    HTTPEvent(
                        timestamp=state.first_timestamp,
                        src_ip=state.src_ip,
                        dst_ip=state.dst_ip,
                        method=method,
                        host=host,
                        uri=uri,
                        user_agent=user_agent,
                        packet_number=state.first_packet_number,
                    )
                )
                self.streams.consume(state, total_length, packet_number, float(packet.time))
                continue
            possible_starts = [
                state.buffer.find(method.encode() + b" ", 1) for method in HTTP_METHODS
            ]
            next_start = min((position for position in possible_starts if position >= 0), default=-1)
            if next_start < 0:
                break
            self.streams.consume(state, next_start, packet_number, float(packet.time))
        return events


def extract_http_events(packets: list) -> list[HTTPEvent]:
    events: list[HTTPEvent] = []
    for index, packet in enumerate(packets, start=1):
        event = extract_http_event(packet, packet_number=index)
        if event:
            events.append(event)
    return events
