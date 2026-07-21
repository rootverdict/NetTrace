from __future__ import annotations

from dataclasses import asdict, dataclass, field
import ipaddress
from typing import Any
from urllib.parse import urlsplit


@dataclass
class DNSEvent:
    timestamp: float
    src_ip: str
    dst_ip: str
    query: str
    answers: list[str] = field(default_factory=list)
    ttl: int | None = None
    packet_number: int = 0
    answer_domains: list[str] = field(default_factory=list)
    answer_ttls: list[int] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class HTTPEvent:
    timestamp: float
    src_ip: str
    dst_ip: str
    method: str
    host: str
    uri: str
    user_agent: str = ""
    packet_number: int = 0

    @property
    def url(self) -> str:
        parsed = urlsplit(self.uri)
        if parsed.scheme in {"http", "https"} and parsed.netloc:
            return self.uri
        if self.method == "CONNECT":
            return f"https://{self.uri}"
        host = self.host or self.dst_ip
        if not host.startswith("["):
            try:
                if ipaddress.ip_address(host).version == 6:
                    host = f"[{host}]"
            except ValueError:
                pass
        return f"http://{host}{self.uri}"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["url"] = self.url
        return data


@dataclass
class TLSEvent:
    timestamp: float
    src_ip: str
    dst_ip: str
    dst_port: int
    sni: str = ""
    packet_number: int = 0
    src_port: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Flow:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    first_seen: float
    last_seen: float
    packet_count: int = 0
    byte_count: int = 0
    timestamps: list[float] = field(default_factory=list)
    packet_numbers: list[int] = field(default_factory=list)
    beacon_timestamps: list[float] = field(default_factory=list)
    first_packet_number: int = 0
    direction_score: int = 0
    last_beacon_tcp_seq: int | None = None
    initial_tcp_seq: int | None = None
    tcp_seq_floor: int | None = None
    tcp_seq_next: int | None = None

    @property
    def duration(self) -> float:
        return max(0.0, self.last_seen - self.first_seen)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("direction_score", None)
        data.pop("last_beacon_tcp_seq", None)
        data.pop("initial_tcp_seq", None)
        data.pop("tcp_seq_floor", None)
        data.pop("tcp_seq_next", None)
        data.pop("beacon_timestamps", None)
        packet_numbers = data.pop("packet_numbers", [])
        if packet_numbers:
            data["packet_numbers_sample"] = packet_numbers[:8]
        data["duration"] = self.duration
        return data


@dataclass(frozen=True)
class IOC:
    kind: str
    value: str
    source: str
    packet_number: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FTPEvent:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    command: str
    argument: str = ""
    packet_number: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
