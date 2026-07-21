from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field

from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment
from scapy.packet import Raw


@dataclass
class _FragmentState:
    fragments: dict[int, bytes] = field(default_factory=dict)
    total_length: int | None = None
    first_fragment: object | None = None
    first_packet_number: int = 0
    first_timestamp: float = 0.0


class IPFragmentReassembler:
    """Bounded, streaming IPv4 and IPv6 fragment reassembly."""

    def __init__(
        self,
        max_datagrams: int = 1_024,
        max_total_bytes: int = 8_388_608,
        max_fragments_per_datagram: int = 256,
    ) -> None:
        self.max_datagrams = max_datagrams
        self.max_total_bytes = max_total_bytes
        self.max_fragments_per_datagram = max_fragments_per_datagram
        self._datagrams: OrderedDict[tuple, _FragmentState] = OrderedDict()
        self._stored_bytes = 0
        self.discarded_datagrams = 0

    @property
    def incomplete_datagrams(self) -> int:
        return len(self._datagrams)

    def _discard(self, key: tuple) -> None:
        state = self._datagrams.pop(key, None)
        if state is not None:
            self._stored_bytes -= sum(len(value) for value in state.fragments.values())
            self.discarded_datagrams += 1

    def _make_room(self) -> None:
        while self._datagrams and (
            len(self._datagrams) > self.max_datagrams or self._stored_bytes > self.max_total_bytes
        ):
            self._discard(next(iter(self._datagrams)))

    @staticmethod
    def _assemble(state: _FragmentState) -> bytes | None:
        if state.total_length is None or state.first_fragment is None or 0 not in state.fragments:
            return None
        cursor = 0
        parts: list[bytes] = []
        for offset, payload in sorted(state.fragments.items()):
            if offset != cursor:
                return None
            parts.append(payload)
            cursor += len(payload)
        if cursor != state.total_length:
            return None
        return b"".join(parts)

    @staticmethod
    def _rebuild_ipv4(packet, payload: bytes):
        rebuilt = packet.copy()
        ip = rebuilt[IP]
        ip.flags.MF = False
        ip.frag = 0
        ip.len = None
        ip.chksum = None
        ip.remove_payload()
        ip.add_payload(Raw(payload))
        parsed = rebuilt.__class__(bytes(rebuilt))
        parsed.time = packet.time
        return parsed

    @staticmethod
    def _rebuild_ipv6(packet, payload: bytes):
        rebuilt = packet.copy()
        fragment = rebuilt[IPv6ExtHdrFragment]
        underlayer = fragment.underlayer
        underlayer.nh = int(fragment.nh)
        underlayer.remove_payload()
        underlayer.add_payload(Raw(payload))
        rebuilt[IPv6].plen = None
        parsed = rebuilt.__class__(bytes(rebuilt))
        parsed.time = packet.time
        return parsed

    def feed(self, packet, packet_number: int) -> tuple[object, int] | None:
        if packet.haslayer(IP):
            ip = packet[IP]
            if int(ip.frag) == 0 and not bool(ip.flags.MF):
                return packet, packet_number
            key = (4, int(ip.id), str(ip.src), str(ip.dst), int(ip.proto))
            offset = int(ip.frag) * 8
            header_length = int(ip.ihl or 5) * 4
            payload_length = max(0, int(ip.len or len(ip)) - header_length)
            payload = bytes(ip.payload)[:payload_length]
            more_fragments = bool(ip.flags.MF)
            rebuild = self._rebuild_ipv4
        elif packet.haslayer(IPv6ExtHdrFragment):
            ip = packet[IPv6]
            fragment = packet[IPv6ExtHdrFragment]
            key = (6, int(fragment.id), str(ip.src), str(ip.dst), int(fragment.nh))
            offset = int(fragment.offset) * 8
            payload = bytes(fragment.payload)
            more_fragments = bool(fragment.m)
            rebuild = self._rebuild_ipv6
        else:
            return packet, packet_number

        state = self._datagrams.get(key)
        if state is None:
            state = _FragmentState()
            self._datagrams[key] = state
        else:
            self._datagrams.move_to_end(key)

        existing = state.fragments.get(offset)
        if existing is not None and existing != payload:
            self._discard(key)
            return None
        if existing is None:
            end = offset + len(payload)
            if any(
                offset < known_offset + len(known_payload) and known_offset < end
                for known_offset, known_payload in state.fragments.items()
            ):
                self._discard(key)
                return None
            state.fragments[offset] = payload
            self._stored_bytes += len(payload)
        if len(state.fragments) > self.max_fragments_per_datagram:
            self._discard(key)
            return None
        if offset == 0:
            state.first_fragment = packet
            state.first_packet_number = packet_number
            state.first_timestamp = float(packet.time)
        if not more_fragments:
            total_length = offset + len(payload)
            if state.total_length is not None and state.total_length != total_length:
                self._discard(key)
                return None
            state.total_length = total_length

        self._make_room()
        if key not in self._datagrams:
            return None
        assembled = self._assemble(state)
        if assembled is None:
            return None

        first_fragment = state.first_fragment
        first_packet_number = state.first_packet_number
        first_timestamp = state.first_timestamp
        self._stored_bytes -= sum(len(value) for value in state.fragments.values())
        del self._datagrams[key]
        result = rebuild(first_fragment, assembled)
        result.time = first_timestamp
        return result, first_packet_number
