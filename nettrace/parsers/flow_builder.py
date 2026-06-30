from __future__ import annotations

import ipaddress

from scapy.layers.inet import IP, TCP, UDP

from nettrace.models.events import Flow

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
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

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


def update_flow(flows: dict[tuple[str, str, int, int, str], Flow], packet, packet_number: int = 0) -> None:
    if not packet.haslayer(IP):
        return
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
        protocol = str(packet[IP].proto)
    key = flow_key(packet[IP].src, packet[IP].dst, src_port, dst_port, protocol)
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
        )
    flow = flows[key]
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
    flow.timestamps.append(timestamp)
    if packet_number:
        flow.packet_numbers.append(packet_number)


def build_flows(packets: list) -> list[Flow]:
    flows: dict[tuple[str, str, int, int, str], Flow] = {}
    for index, packet in enumerate(packets, start=1):
        update_flow(flows, packet, packet_number=index)
    return list(flows.values())
