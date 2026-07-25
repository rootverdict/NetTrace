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
    last_timestamp: float = 0.0
    # True once consume() has run at least once. Before that, base_seq is just
    # the earliest segment received so far (out-of-order arrivals below it are
    # still legitimate and must be prefixed in). After that, base_seq is a
    # genuine "already parsed and removed" low-water mark -- see bug #8.
    has_consumed: bool = False


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
        overlap_policy: str = "reject-conflicting-overlap",
        max_idle_seconds: float = 300.0,
    ) -> None:
        if overlap_policy not in {"first-seen-wins", "last-seen-wins", "reject-conflicting-overlap"}:
            raise ValueError("Unsupported TCP overlap policy.")
        self.max_streams = max_streams
        self.max_buffer_bytes = max_buffer_bytes
        self.max_pending_segments = max_pending_segments
        self.max_total_buffer_bytes = max_total_buffer_bytes
        self.overlap_policy = overlap_policy
        self.max_idle_seconds = max(0.0, float(max_idle_seconds))
        self._streams: OrderedDict[tuple[str, str, int, int], TCPStreamState] = OrderedDict()
        self._total_buffered_bytes = 0
        self.discarded_streams = 0
        self.conflicting_overlaps = 0

    @property
    def total_buffered_bytes(self) -> int:
        return self._total_buffered_bytes

    @property
    def incomplete_streams(self) -> int:
        """Streams still open (never hit FIN/RST/eviction) when iteration ends.

        Bug #4: the engine only ever reported streams it actively discarded
        for resource limits -- a stream that simply never got a chance to
        finish (truncated capture, missing final segment) looked identical to
        a clean report with nothing outstanding.
        """
        return sum(1 for state in self._streams.values() if self._state_size(state) > 0)

    @property
    def incomplete_buffered_bytes(self) -> int:
        return sum(self._state_size(state) for state in self._streams.values())

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

    def _expire_idle(self, current_timestamp: float) -> None:
        if self.max_idle_seconds <= 0:
            return
        for key, state in list(self._streams.items()):
            last_seen = state.last_timestamp or state.first_timestamp
            if current_timestamp - last_seen > self.max_idle_seconds:
                self._remove_stream(key, discarded=True)

    def _merge_segment(self, state: TCPStreamState, sequence: int, segment: _TCPSegment) -> tuple[bool, bool]:
        if state.base_seq is None or state.next_seq is None:
            return False, False
        payload = segment.payload
        end = sequence + len(payload)
        if end < state.base_seq or sequence > state.next_seq:
            return False, False

        conflict = False
        overlap_start = max(sequence, state.base_seq)
        overlap_end = min(end, state.next_seq)
        if overlap_start < overlap_end:
            payload_offset = overlap_start - sequence
            buffer_offset = overlap_start - state.base_seq
            overlap_length = overlap_end - overlap_start
            accepted = bytes(state.buffer[buffer_offset : buffer_offset + overlap_length])
            retransmitted = payload[payload_offset : payload_offset + overlap_length]
            conflict = accepted != retransmitted

        if conflict and self.overlap_policy == "reject-conflicting-overlap":
            return True, True

        if sequence < state.base_seq:
            prefix_length = state.base_seq - sequence
            state.buffer[:0] = payload[:prefix_length]
            state.base_seq = sequence
            state.first_packet_number = segment.packet_number
            state.first_timestamp = segment.timestamp

        if overlap_start < overlap_end and self.overlap_policy == "last-seen-wins":
            buffer_offset = overlap_start - state.base_seq
            payload_offset = overlap_start - sequence
            overlap_length = overlap_end - overlap_start
            state.buffer[buffer_offset : buffer_offset + overlap_length] = payload[
                payload_offset : payload_offset + overlap_length
            ]

        if end > state.next_seq:
            suffix_offset = max(0, state.next_seq - sequence)
            state.buffer.extend(payload[suffix_offset:])
            state.next_seq = end
        return True, conflict

    def _merge_pending(self, state: TCPStreamState) -> bool:
        """Merge ready pending segments into the buffer.

        Returns True if a byte-level conflict was found between overlapping
        retransmitted data and data already accepted (bug #3): the old code
        accepted/trimmed overlapping segments without ever comparing bytes, so
        a retransmission with *different* content than what was already
        buffered was silently and arbitrarily resolved.
        """
        if state.base_seq is None or state.next_seq is None:
            return False
        conflict = False
        changed = True
        while changed:
            changed = False
            for sequence, segment in sorted(state.pending.items()):
                end = sequence + len(segment.payload)
                # Bug #8: a segment entirely covering already-consumed bytes
                # must be discarded outright, not left in `pending` forever --
                # but only once consume() has actually run. Before that,
                # base_seq is merely the earliest segment received so far, and
                # an out-of-order arrival ending exactly at base_seq is a
                # legitimate missing prefix, not a stale retransmission.
                if state.has_consumed and end <= state.base_seq:
                    del state.pending[sequence]
                    changed = True
                    break
                if end < state.base_seq or sequence > state.next_seq:
                    continue
                merged, segment_conflict = self._merge_segment(state, sequence, segment)
                conflict = conflict or segment_conflict
                del state.pending[sequence]
                changed = merged
                break
        return conflict

    def feed(self, packet, packet_number: int) -> TCPStreamState | None:
        endpoints = ip_endpoints(packet)
        if endpoints is None or not packet.haslayer(TCP):
            return None
        timestamp = float(getattr(packet, "time", 0.0))
        self._expire_idle(timestamp)
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
                first_timestamp=timestamp,
                last_timestamp=timestamp,
            )
            self._streams[key] = state
        else:
            self._streams.move_to_end(key)
            state.last_timestamp = timestamp

        previous_size = self._state_size(state)

        if not state.buffer and not state.pending:
            state.first_packet_number = packet_number
            state.first_timestamp = timestamp

        segment = _TCPSegment(payload, packet_number, timestamp)
        if state.next_seq is None or state.base_seq is None:
            state.buffer.extend(payload)
            state.base_seq = sequence
            state.next_seq = sequence + len(payload)
        else:
            existing = state.pending.get(sequence)
            if existing is None or len(payload) > len(existing.payload):
                state.pending[sequence] = segment
            if self._merge_pending(state):
                self.conflicting_overlaps += 1

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
        state.has_consumed = True
        state.first_packet_number = next_packet_number
        state.first_timestamp = next_timestamp
        self._total_buffered_bytes += self._state_size(state) - previous_size
