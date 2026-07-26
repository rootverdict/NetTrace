from __future__ import annotations

from scapy.layers.inet import TCP
from scapy.packet import Raw

from nettrace.models.events import TLSEvent
from nettrace.parsers.tcp_stream import TCPStreamBuffers, ip_endpoints

TLS_PORTS = {443, 8443, 4443, 9443}


def _read_u16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 2], "big")


def _extract_sni_from_handshake(handshake: bytes) -> str:
    try:
        if len(handshake) < 42 or handshake[0] != 0x01:
            return ""
        offset = 4 + 2 + 32
        session_id_len = handshake[offset]
        offset += 1 + session_id_len
        cipher_len = _read_u16(handshake, offset)
        offset += 2 + cipher_len
        compression_len = handshake[offset]
        offset += 1 + compression_len
        extensions_len = _read_u16(handshake, offset)
        offset += 2
        end = offset + extensions_len
        while offset + 4 <= end:
            ext_type = _read_u16(handshake, offset)
            ext_len = _read_u16(handshake, offset + 2)
            offset += 4
            ext_data = handshake[offset : offset + ext_len]
            if ext_type == 0 and len(ext_data) >= 5:
                name_len = _read_u16(ext_data, 3)
                return ext_data[5 : 5 + name_len].decode("utf-8", errors="ignore")
            offset += ext_len
    except Exception:
        return ""
    return ""


def extract_sni(payload: bytes) -> str:
    if len(payload) < 5 or payload[0] != 0x16:
        return ""
    record_length = _read_u16(payload, 3)
    return _extract_sni_from_handshake(payload[5 : 5 + record_length])


def _client_hello_from_records(buffer: bytearray) -> tuple[str, int]:
    handshake = bytearray()
    offset = 0
    while True:
        if len(buffer) < offset + 5:
            return "", 0
        if buffer[offset] != 0x16:
            return "", offset
        record_length = _read_u16(buffer, offset + 3)
        record_end = offset + 5 + record_length
        if len(buffer) < record_end:
            return "", 0
        handshake.extend(buffer[offset + 5 : record_end])
        offset = record_end
        if len(handshake) < 4:
            continue
        handshake_length = int.from_bytes(handshake[1:4], "big")
        if len(handshake) >= 4 + handshake_length:
            return _extract_sni_from_handshake(bytes(handshake[: 4 + handshake_length])), offset


def extract_tls_event(packet, packet_number: int = 0) -> TLSEvent | None:
    endpoints = ip_endpoints(packet)
    if endpoints is None or not packet.haslayer(TCP) or not packet.haslayer(Raw):
        return None
    tcp = packet[TCP]
    if tcp.dport not in TLS_PORTS and tcp.sport not in TLS_PORTS:
        return None
    sni = extract_sni(bytes(packet[Raw].load))
    if not sni:
        return None
    return TLSEvent(
        timestamp=float(packet.time),
        src_ip=endpoints[0],
        dst_ip=endpoints[1],
        dst_port=int(tcp.dport),
        sni=sni,
        packet_number=packet_number,
        src_port=int(tcp.sport),
    )


class TLSStreamExtractor:
    def __init__(self, stream_options: dict | None = None) -> None:
        self.streams = TCPStreamBuffers(**(stream_options or {}))

    def feed(self, packet, packet_number: int = 0) -> list[TLSEvent]:
        if not packet.haslayer(TCP) or int(packet[TCP].dport) not in TLS_PORTS:
            return []
        state = self.streams.feed(packet, packet_number)
        if state is None:
            return []
        events: list[TLSEvent] = []
        while len(state.buffer) >= 5:
            if state.buffer[0] not in {0x14, 0x15, 0x16, 0x17}:
                # The first observed segment can be the tail of an out-of-order
                # record. Retain it so an earlier segment can be prepended.
                break
            record_length = _read_u16(state.buffer, 3)
            total_length = 5 + record_length
            if len(state.buffer) < total_length:
                break
            if state.buffer[0] == 0x16:
                sni, consumed_length = _client_hello_from_records(state.buffer)
                if consumed_length == 0:
                    break
                total_length = consumed_length
            else:
                sni = ""
            if sni:
                events.append(
                    TLSEvent(
                        timestamp=state.first_timestamp,
                        src_ip=state.src_ip,
                        dst_ip=state.dst_ip,
                        dst_port=state.dst_port,
                        sni=sni,
                        packet_number=state.first_packet_number,
                        src_port=state.src_port,
                    )
                )
            self.streams.consume(state, total_length, packet_number, float(packet.time))
        if state.closing:
            self.streams.close(state)
        return events


def extract_tls_events(packets: list) -> list[TLSEvent]:
    events: list[TLSEvent] = []
    for index, packet in enumerate(packets, start=1):
        event = extract_tls_event(packet, packet_number=index)
        if event:
            events.append(event)
    return events
