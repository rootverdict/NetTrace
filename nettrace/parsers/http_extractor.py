from __future__ import annotations

from scapy.layers.inet import TCP

from nettrace.models.events import HTTPEvent, redact_sensitive_query_params
from nettrace.parsers.tcp_stream import TCPStreamBuffers, ip_endpoints, tcp_payload

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
    # Bare-LF line endings are accepted alongside CRLF. NetSupport RAT's C2
    # POSTs terminate lines with LF only, and splitting on CRLF alone collapsed
    # the whole request into a single "line": every header was lost, so Host and
    # User-Agent came back empty even though both were present in the packet.
    normalized = payload.replace(b"\r\n", b"\n")

    # A request head is only complete once its blank-line terminator arrives.
    # Without this the single-packet fallback in engine.py emitted the first
    # half of a split request as a *finished* event: `Host:` had not been
    # received yet, so HTTPEvent.url fell back to the destination IP and
    # published a URL IOC for a request that never appeared on the wire, on top
    # of duplicating the real event once reassembly completed.
    if b"\n\n" not in normalized:
        return None

    # Parse only the head, so a body line containing a colon cannot masquerade
    # as a header.
    try:
        text = normalized.split(b"\n\n", 1)[0].decode("iso-8859-1", errors="ignore")
    except Exception:
        return None
    lines = text.split("\n")
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
    if endpoints is None or not packet.haslayer(TCP):
        return None
    tcp = packet[TCP]
    ports = HTTP_PORTS if http_ports is None else http_ports
    if tcp.dport not in ports and not allow_any_port:
        return None
    payload = tcp_payload(packet, tcp)
    if not payload:
        return None
    parsed = _parse_headers(payload)
    if not parsed:
        return None
    method, uri, host, user_agent = parsed
    return HTTPEvent(
        timestamp=float(packet.time),
        src_ip=endpoints[0],
        dst_ip=endpoints[1],
        method=method,
        host=host,
        uri=redact_sensitive_query_params(uri),
        user_agent=user_agent,
        packet_number=packet_number,
        src_port=int(tcp.sport),
        dst_port=int(tcp.dport),
        stream_offset=int(tcp.seq),
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
            # Frame on either CRLF or bare-LF terminators, whichever completes
            # first. `_parse_headers` already accepts LF-only requests (NetSupport
            # RAT's C2 POSTs use them), but the stream framer only recognized
            # \r\n\r\n, so a split LF request stayed buffered forever and no event
            # was ever emitted.
            terminators = [
                (position, length)
                for position, length in ((state.buffer.find(b"\r\n\r\n"), 4), (state.buffer.find(b"\n\n"), 2))
                if position >= 0
            ]
            if not terminators:
                break
            header_end, terminator_length = min(terminators)
            header_length = header_end + terminator_length
            header = bytes(state.buffer[:header_length])
            content_length = 0
            chunked = False
            invalid_content_length = False
            for line in header.replace(b"\r\n", b"\n").split(b"\n")[1:]:
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
                        uri=redact_sensitive_query_params(uri),
                        user_agent=user_agent,
                        packet_number=state.first_packet_number,
                        src_port=state.src_port,
                        dst_port=state.dst_port,
                        stream_offset=state.base_seq or 0,
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
        if state.closing:
            self.streams.close(state)
        return events


def extract_http_events(packets: list) -> list[HTTPEvent]:
    events: list[HTTPEvent] = []
    for index, packet in enumerate(packets, start=1):
        event = extract_http_event(packet, packet_number=index)
        if event:
            events.append(event)
    return events
