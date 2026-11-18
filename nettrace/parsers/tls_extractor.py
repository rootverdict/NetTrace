from __future__ import annotations

import hashlib
from scapy.layers.inet import TCP

from nettrace.models.events import TLSEvent
from nettrace.parsers.tcp_stream import TCPStreamBuffers, ip_endpoints, tcp_payload

TLS_PORTS = {443, 8443, 4443, 9443}
GREASE_VALUES = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
}


def _read_u16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 2], "big")


def parse_client_hello(handshake: bytes) -> tuple[str, str, str]:
    """Parse a TLS ClientHello handshake payload.

    Returns a tuple of (sni, ja3_hash, ja3_string).
    If parsing fails or message is not a valid ClientHello, returns ("", "", "").
    """
    try:
        if len(handshake) < 42 or handshake[0] != 0x01:
            return "", "", ""

        # ClientHello TLS version (2 bytes at offset 4)
        client_version = _read_u16(handshake, 4)

        # Skip handshake type (1) + length (3) + version (2) + random (32) = 38
        offset = 38
        session_id_len = handshake[offset]
        offset += 1 + session_id_len

        # Cipher Suites
        cipher_len = _read_u16(handshake, offset)
        offset += 2
        cipher_end = offset + cipher_len
        ciphers: list[int] = []
        while offset + 2 <= cipher_end:
            cipher = _read_u16(handshake, offset)
            if cipher not in GREASE_VALUES:
                ciphers.append(cipher)
            offset += 2
        offset = cipher_end

        # Compression Methods
        compression_len = handshake[offset]
        offset += 1
        comp_end = offset + compression_len
        compressions: list[int] = []
        while offset < comp_end:
            comp = handshake[offset]
            compressions.append(comp)
            offset += 1

        # Extensions
        sni = ""
        extensions: list[int] = []
        elliptic_curves: list[int] = []
        ec_point_formats: list[int] = []

        if offset + 2 <= len(handshake):
            extensions_len = _read_u16(handshake, offset)
            offset += 2
            end = offset + extensions_len
            while offset + 4 <= end:
                ext_type = _read_u16(handshake, offset)
                ext_len = _read_u16(handshake, offset + 2)
                offset += 4
                ext_data = handshake[offset : offset + ext_len]

                if ext_type not in GREASE_VALUES:
                    extensions.append(ext_type)

                # SNI (extension 0)
                if ext_type == 0 and len(ext_data) >= 5:
                    name_len = _read_u16(ext_data, 3)
                    sni = ext_data[5 : 5 + name_len].decode("utf-8", errors="ignore")

                # Supported Elliptic Curves / Groups (extension 10 / 0x000a)
                elif ext_type == 10 and len(ext_data) >= 2:
                    curve_list_len = _read_u16(ext_data, 0)
                    c_offset = 2
                    c_end = 2 + curve_list_len
                    while c_offset + 2 <= min(len(ext_data), c_end):
                        curve = _read_u16(ext_data, c_offset)
                        if curve not in GREASE_VALUES:
                            elliptic_curves.append(curve)
                        c_offset += 2

                # EC Point Formats (extension 11 / 0x000b)
                elif ext_type == 11 and len(ext_data) >= 1:
                    ec_len = ext_data[0]
                    for p in ext_data[1 : 1 + ec_len]:
                        ec_point_formats.append(p)

                offset += ext_len

        ja3_string = (
            f"{client_version},"
            + "-".join(str(c) for c in ciphers)
            + ","
            + "-".join(str(e) for e in extensions)
            + ","
            + "-".join(str(c) for c in elliptic_curves)
            + ","
            + "-".join(str(p) for p in ec_point_formats)
        )
        ja3_hash = hashlib.md5(ja3_string.encode("ascii")).hexdigest()
        return sni, ja3_hash, ja3_string
    except Exception:
        return "", "", ""


def _extract_sni_from_handshake(handshake: bytes) -> str:
    sni, _, _ = parse_client_hello(handshake)
    return sni


def extract_sni(payload: bytes) -> str:
    if len(payload) < 5 or payload[0] != 0x16:
        return ""
    record_length = _read_u16(payload, 3)
    return _extract_sni_from_handshake(payload[5 : 5 + record_length])


def _client_hello_from_records(buffer: bytearray) -> tuple[str, str, str, int]:
    handshake = bytearray()
    offset = 0
    while True:
        if len(buffer) < offset + 5:
            return "", "", "", 0
        if buffer[offset] != 0x16:
            return "", "", "", offset
        record_length = _read_u16(buffer, offset + 3)
        record_end = offset + 5 + record_length
        if len(buffer) < record_end:
            return "", "", "", 0
        handshake.extend(buffer[offset + 5 : record_end])
        offset = record_end
        if len(handshake) < 4:
            continue
        handshake_length = int.from_bytes(handshake[1:4], "big")
        if len(handshake) >= 4 + handshake_length:
            sni, ja3, ja3_str = parse_client_hello(bytes(handshake[: 4 + handshake_length]))
            return sni, ja3, ja3_str, offset


def extract_tls_event(packet, packet_number: int = 0) -> TLSEvent | None:
    endpoints = ip_endpoints(packet)
    if endpoints is None or not packet.haslayer(TCP):
        return None
    tcp = packet[TCP]
    if tcp.dport not in TLS_PORTS and tcp.sport not in TLS_PORTS:
        return None
    payload = tcp_payload(packet, tcp)
    if len(payload) < 5 or payload[0] != 0x16:
        return None
    record_length = _read_u16(payload, 3)
    sni, ja3, ja3_str = parse_client_hello(payload[5 : 5 + record_length])
    if not sni and not ja3:
        return None
    return TLSEvent(
        timestamp=float(packet.time),
        src_ip=endpoints[0],
        dst_ip=endpoints[1],
        dst_port=int(tcp.dport),
        sni=sni,
        ja3=ja3,
        ja3_string=ja3_str,
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
                sni, ja3, ja3_str, consumed_length = _client_hello_from_records(state.buffer)
                if consumed_length == 0:
                    break
                total_length = consumed_length
            else:
                sni, ja3, ja3_str = "", "", ""
            if sni or ja3:
                events.append(
                    TLSEvent(
                        timestamp=state.first_timestamp,
                        src_ip=state.src_ip,
                        dst_ip=state.dst_ip,
                        dst_port=state.dst_port,
                        sni=sni,
                        ja3=ja3,
                        ja3_string=ja3_str,
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
