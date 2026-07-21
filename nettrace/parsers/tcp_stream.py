from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field

from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6

TCP_SEQUENCE_MODULUS = 1 << 32


def unwrap_tcp_sequence(sequence: int, reference: int) -> int:
    """Map a 32-bit TCP sequence number nearest to an unbounded reference."""
    base = reference - (reference % TCP_SEQUENCE_MODULUS)
    candidates = (
        base + sequence,
        base + sequence - TCP_SEQUENCE_MODULUS,
        base + sequence + TCP_SEQUENCE_MODULUS,
    )
    return min(candidates, key=lambda candidate: abs(candidate - reference))


@dataclass
class _TCPSegment:
    payload: bytes
    packet_number: int
    timestamp: float


@dataclass
class TCPStreamState:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    buffer: bytearray = field(default_factory=bytearray)
    base_seq: int | None = None
    next_seq: int | None = None
    pending: dict[int, _TCPSegment] = field(default_factory=dict)
    first_packet_number: int = 0
    first_timestamp: float = 0.0


def ip_endpoints(packet) -> tuple[str, str] | None:
    if packet.haslayer(IP):
        return packet[IP].src, packet[IP].dst
    if packet.haslayer(IPv6):
        return packet[IPv6].src, packet[IPv6].dst
    return None


class TCPStreamBuffers:
    def __init__(
        self,
        max_streams: int = 10_000,
        max_buffer_bytes: int = 1_048_576,
        max_pending_segments: int = 256,
        max_total_buffer_bytes: int = 67_108_864,
    ) -> None:
        self.max_streams = max_streams
        self.max_buffer_bytes = max_buffer_bytes
        self.max_pending_segments = max_pending_segments
        self.max_total_buffer_bytes = max_total_buffer_bytes
        self._streams: OrderedDict[tuple[str, str, int, int], TCPStreamState] = OrderedDict()
        self._total_buffered_bytes = 0
        self.discarded_streams = 0

    @property
    def total_buffered_bytes(self) -> int:
        return self._total_buffered_bytes

    @staticmethod
    def _state_size(state: TCPStreamState) -> int:
        return len(state.buffer) + sum(len(item.payload) for item in state.pending.values())

    def _remove_stream(self, key: tuple[str, str, int, int], *, discarded: bool) -> None:
        state = self._streams.pop(key, None)
        if state is None:
            return
        size = self._state_size(state)
        self._total_buffered_bytes -= size
        if discarded and size:
            self.discarded_streams += 1

    @staticmethod
    def _merge_pending(state: TCPStreamState) -> None:
        if state.base_seq is None or state.next_seq is None:
            return
        changed = True
        while changed:
            changed = False
            for sequence, segment in sorted(state.pending.items()):
                end = sequence + len(segment.payload)
                if end < state.base_seq or sequence > state.next_seq:
                    continue
                if end <= state.next_seq and sequence >= state.base_seq:
                    del state.pending[sequence]
                    changed = True
                    break
                if sequence < state.base_seq and end >= state.base_seq:
                    prefix_length = state.base_seq - sequence
                    state.buffer[:0] = segment.payload[:prefix_length]
                    state.base_seq = sequence
                    state.first_packet_number = segment.packet_number
                    state.first_timestamp = segment.timestamp
                if sequence <= state.next_seq and end > state.next_seq:
                    overlap = state.next_seq - sequence
                    state.buffer.extend(segment.payload[overlap:])
                    state.next_seq = end
                del state.pending[sequence]
                changed = True
                break

    def feed(self, packet, packet_number: int) -> TCPStreamState | None:
        endpoints = ip_endpoints(packet)
        if endpoints is None or not packet.haslayer(TCP):
            return None
        src_ip, dst_ip = endpoints
        tcp = packet[TCP]
        key = (src_ip, dst_ip, int(tcp.sport), int(tcp.dport))
        flags = int(tcp.flags)
        syn_start = bool(flags & 0x02) and not bool(flags & 0x10)
        payload = bytes(tcp.payload)
        raw_sequence = (int(tcp.seq) + (1 if flags & 0x02 else 0)) % TCP_SEQUENCE_MODULUS
        existing_state = self._streams.get(key)
        sequence = (
            unwrap_tcp_sequence(raw_sequence, existing_state.next_seq)
            if existing_state is not None and existing_state.next_seq is not None
            else raw_sequence
        )
        if syn_start and existing_state is not None:
            belongs_to_current_range = bool(payload) and existing_state.base_seq is not None and existing_state.next_seq is not None and (
                sequence <= existing_state.next_seq and sequence + len(payload) >= existing_state.base_seq
            )
            if not belongs_to_current_range:
                self._remove_stream(key, discarded=True)
        if not payload:
            if flags & 0x05:  # FIN or RST
                self._remove_stream(key, discarded=True)
            return None

        state = self._streams.get(key)
        if state is None:
            if len(self._streams) >= self.max_streams:
                self._remove_stream(next(iter(self._streams)), discarded=True)
            state = TCPStreamState(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=int(tcp.sport),
                dst_port=int(tcp.dport),
                first_packet_number=packet_number,
                first_timestamp=float(packet.time),
            )
            self._streams[key] = state
        else:
            self._streams.move_to_end(key)

        previous_size = self._state_size(state)

        if not state.buffer and not state.pending:
            state.first_packet_number = packet_number
            state.first_timestamp = float(packet.time)

        segment = _TCPSegment(payload, packet_number, float(packet.time))
        if state.next_seq is None or state.base_seq is None:
            state.buffer.extend(payload)
            state.base_seq = sequence
            state.next_seq = sequence + len(payload)
        else:
            existing = state.pending.get(sequence)
            if existing is None or len(payload) > len(existing.payload):
                state.pending[sequence] = segment
            self._merge_pending(state)

        buffered_bytes = self._state_size(state)
        self._total_buffered_bytes += buffered_bytes - previous_size
        if buffered_bytes > self.max_buffer_bytes or len(state.pending) > self.max_pending_segments:
            self._remove_stream(key, discarded=True)
            return None
        while self._total_buffered_bytes > self.max_total_buffer_bytes and self._streams:
            self._remove_stream(next(iter(self._streams)), discarded=True)
        if key not in self._streams:
            return None
        return state

    def consume(self, state: TCPStreamState, length: int, next_packet_number: int, next_timestamp: float) -> None:
        previous_size = self._state_size(state)
        del state.buffer[:length]
        if state.base_seq is not None:
            state.base_seq += length
        state.first_packet_number = next_packet_number
        state.first_timestamp = next_timestamp
        self._total_buffered_bytes += self._state_size(state) - previous_size
