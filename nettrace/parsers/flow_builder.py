from __future__ import annotations

import ipaddress

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.packet import Raw

from nettrace.models.events import Flow
from nettrace.parsers.tcp_stream import TCP_SEQUENCE_MODULUS, unwrap_tcp_sequence

EPHEMERAL_PORT_MIN = 49152
SERVER_LIKE_PORTS = {
    20,
    21,
    22,
    25,
    53,
    80,
    110,
    143,
    443,
    445,
    465,
    587,
    993,
    995,
    1337,
    1433,
    3306,
    3389,
    4443,
    4444,
    5432,
    5900,
    6667,
    8000,
    8080,
    8443,
    9001,
    9443,
    31337,
}
DEFAULT_FLOW_SAMPLE_LIMIT = 256
PACKET_NUMBER_SAMPLE_LIMIT = 8


def _ip_endpoints(packet) -> tuple[str, str] | None:
    if packet.haslayer(IP):
        return packet[IP].src, packet[IP].dst
    if packet.haslayer(IPv6):
        return packet[IPv6].src, packet[IPv6].dst
    return None


def _endpoint_sort_key(ip: str, port: int) -> tuple[int, int, int, int, str]:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return (1, 0, 0, port, ip)
    return (0, address.version, int(address), port, "")


def flow_key(src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str) -> tuple[str, str, int, int, str]:
    left = _endpoint_sort_key(src_ip, src_port)
    right = _endpoint_sort_key(dst_ip, dst_port)
    if left <= right:
        return (src_ip, dst_ip, src_port, dst_port, protocol)
    return (dst_ip, src_ip, dst_port, src_port, protocol)


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _is_global(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _direction_from_packet(packet, src_port: int, dst_port: int, protocol: str) -> tuple[str, str, int, int, int]:
    endpoints = _ip_endpoints(packet)
    if endpoints is None:
        return "", "", src_port, dst_port, 0
    src_ip, dst_ip = endpoints

    if protocol == "TCP" and packet.haslayer(TCP):
        flags = int(packet[TCP].flags)
        syn = bool(flags & 0x02)
        ack = bool(flags & 0x10)
        if syn and not ack:
            return src_ip, dst_ip, src_port, dst_port, 100
        if syn and ack:
            return dst_ip, src_ip, dst_port, src_port, 100

    src_private = _is_private(src_ip)
    dst_private = _is_private(dst_ip)
    src_global = _is_global(src_ip)
    dst_global = _is_global(dst_ip)
    if src_private and dst_global:
        return src_ip, dst_ip, src_port, dst_port, 70
    if dst_private and src_global:
        return dst_ip, src_ip, dst_port, src_port, 70

    src_ephemeral = src_port >= EPHEMERAL_PORT_MIN
    dst_ephemeral = dst_port >= EPHEMERAL_PORT_MIN
    if src_ephemeral and not dst_ephemeral:
        return src_ip, dst_ip, src_port, dst_port, 60
    if dst_ephemeral and not src_ephemeral:
        return dst_ip, src_ip, dst_port, src_port, 60

    src_service = src_port in SERVER_LIKE_PORTS
    dst_service = dst_port in SERVER_LIKE_PORTS
    if dst_service and not src_service:
        return src_ip, dst_ip, src_port, dst_port, 50
    if src_service and not dst_service:
        return dst_ip, src_ip, dst_port, src_port, 50

    return src_ip, dst_ip, src_port, dst_port, 10


def update_flow(
    flows: dict[tuple, Flow],
    packet,
    packet_number: int = 0,
    *,
    max_flows: int | None = None,
    sample_limit: int = DEFAULT_FLOW_SAMPLE_LIMIT,
) -> bool:
    endpoints = _ip_endpoints(packet)
    if endpoints is None:
        return True
    packet_src_ip, packet_dst_ip = endpoints
    protocol = ""
    src_port = 0
    dst_port = 0
    if packet.haslayer(TCP):
        protocol = "TCP"
        src_port = int(packet[TCP].sport)
        dst_port = int(packet[TCP].dport)
    elif packet.haslayer(UDP):
        protocol = "UDP"
        src_port = int(packet[UDP].sport)
        dst_port = int(packet[UDP].dport)
    else:
        protocol = str(packet[IP].proto if packet.haslayer(IP) else packet[IPv6].nh)
    key = flow_key(packet_src_ip, packet_dst_ip, src_port, dst_port, protocol)
    initial_tcp_seq = None
    if protocol == "TCP":
        flags = int(packet[TCP].flags)
        syn_start = bool(flags & 0x02) and not bool(flags & 0x10)
        if syn_start:
            initial_tcp_seq = int(packet[TCP].seq)
            existing = flows.get(key)
            raw_segment_start = (initial_tcp_seq + 1) % TCP_SEQUENCE_MODULUS
            segment_start = (
                unwrap_tcp_sequence(raw_segment_start, existing.tcp_seq_next)
                if existing is not None and existing.tcp_seq_next is not None
                else raw_segment_start
            )
            segment_end = segment_start + (len(bytes(packet[TCP].payload)) if packet[TCP].payload else 0)
            belongs_to_existing = (
                existing is not None
                and existing.tcp_seq_floor is not None
                and existing.tcp_seq_next is not None
                and segment_start <= existing.tcp_seq_next + 1
                and segment_end >= existing.tcp_seq_floor - 1
            )
            if existing is not None and existing.initial_tcp_seq != initial_tcp_seq and not belongs_to_existing:
                archive_key = (*key, "connection", existing.first_packet_number)
                suffix = 1
                while archive_key in flows:
                    archive_key = (*key, "connection", existing.first_packet_number, suffix)
                    suffix += 1
                flows[archive_key] = flows.pop(key)
    if key not in flows and max_flows is not None and len(flows) >= max_flows:
        return False
    direction = _direction_from_packet(packet, src_port, dst_port, protocol)
    timestamp = float(packet.time)
    if key not in flows:
        flows[key] = Flow(
            src_ip=direction[0],
            dst_ip=direction[1],
            src_port=direction[2],
            dst_port=direction[3],
            protocol=protocol,
            first_seen=timestamp,
            last_seen=timestamp,
            first_packet_number=packet_number,
            direction_score=direction[4],
            initial_tcp_seq=initial_tcp_seq,
        )
    flow = flows[key]
    if protocol == "TCP":
        flags = int(packet[TCP].flags)
        raw_sequence_start = (int(packet[TCP].seq) + (1 if flags & 0x02 else 0)) % TCP_SEQUENCE_MODULUS
        sequence_start = (
            unwrap_tcp_sequence(raw_sequence_start, flow.tcp_seq_next)
            if flow.tcp_seq_next is not None
            else raw_sequence_start
        )
        sequence_end = sequence_start + len(bytes(packet[TCP].payload))
        flow.tcp_seq_floor = sequence_start if flow.tcp_seq_floor is None else min(flow.tcp_seq_floor, sequence_start)
        flow.tcp_seq_next = sequence_end if flow.tcp_seq_next is None else max(flow.tcp_seq_next, sequence_end)
    if direction[4] > flow.direction_score:
        flow.src_ip = direction[0]
        flow.dst_ip = direction[1]
        flow.src_port = direction[2]
        flow.dst_port = direction[3]
        flow.direction_score = direction[4]
    flow.packet_count += 1
    flow.byte_count += len(packet)
    if timestamp < flow.first_seen:
        flow.first_packet_number = packet_number
    flow.first_seen = min(flow.first_seen, timestamp)
    flow.last_seen = max(flow.last_seen, timestamp)
    if len(flow.timestamps) < sample_limit:
        flow.timestamps.append(timestamp)
    if packet_number and len(flow.packet_numbers) < PACKET_NUMBER_SAMPLE_LIMIT:
        flow.packet_numbers.append(packet_number)
    from_initiator = (
        packet_src_ip == flow.src_ip
        and packet_dst_ip == flow.dst_ip
        and src_port == flow.src_port
        and dst_port == flow.dst_port
    )
    if from_initiator and len(flow.beacon_timestamps) < sample_limit:
        if protocol == "TCP":
            flags = int(packet[TCP].flags)
            syn_start = bool(flags & 0x02) and not bool(flags & 0x10)
            has_payload = packet.haslayer(Raw) and bool(bytes(packet[Raw].load))
            sequence = int(packet[TCP].seq)
            if (syn_start or has_payload) and sequence != flow.last_beacon_tcp_seq:
                flow.beacon_timestamps.append(timestamp)
                flow.last_beacon_tcp_seq = sequence
        elif protocol == "UDP":
            flow.beacon_timestamps.append(timestamp)
    return True


def build_flows(packets: list) -> list[Flow]:
    flows: dict[tuple, Flow] = {}
    for index, packet in enumerate(packets, start=1):
        update_flow(flows, packet, packet_number=index)
    return list(flows.values())
