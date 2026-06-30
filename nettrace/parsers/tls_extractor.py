from __future__ import annotations

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from nettrace.models.events import TLSEvent

TLS_PORTS = {443, 8443, 4443, 9443}


def _read_u16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 2], "big")


def extract_sni(payload: bytes) -> str:
    try:
        if len(payload) < 5 or payload[0] != 0x16:
            return ""
        record_length = _read_u16(payload, 3)
        handshake = payload[5 : 5 + record_length]
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


def extract_tls_event(packet, packet_number: int = 0) -> TLSEvent | None:
    if not packet.haslayer(IP) or not packet.haslayer(TCP) or not packet.haslayer(Raw):
        return None
    tcp = packet[TCP]
    if tcp.dport not in TLS_PORTS and tcp.sport not in TLS_PORTS:
        return None
    sni = extract_sni(bytes(packet[Raw].load))
    if not sni:
        return None
    return TLSEvent(
        timestamp=float(packet.time),
        src_ip=packet[IP].src,
        dst_ip=packet[IP].dst,
        dst_port=int(tcp.dport),
        sni=sni,
        packet_number=packet_number,
    )


def extract_tls_events(packets: list) -> list[TLSEvent]:
    events: list[TLSEvent] = []
    for index, packet in enumerate(packets, start=1):
        event = extract_tls_event(packet, packet_number=index)
        if event:
            events.append(event)
    return events
