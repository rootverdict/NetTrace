from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

from nettrace.models.events import DNSEvent, Flow, HTTPEvent, IOC, TLSEvent

KNOWN_GOOD_RESOLVERS = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"}
TEST_NETS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)
SOURCE_PRIORITY = {
    "http_request": 0,
    "http_host": 1,
    "http_url_host": 1,
    "http_connect_target": 1,
    "http_flow": 2,
    "tls_sni": 3,
    "tls_flow": 4,
    "dns": 5,
    "dns_answer": 6,
    "dns_answer_domain": 6,
}

# Sources backed by a parsed protocol artifact (a DNS answer, an HTTP host header,
# a TLS SNI, a request URL). Everything else -- principally raw flow endpoint IPs
# with a "flow:<proto>:<port>" source -- is an *observed* network artifact, not a
# confirmed indicator, and should not be counted or ranked the same way. See bug #11.
CONFIRMED_SOURCES = {
    "dns",
    "dns_answer",
    "dns_answer_domain",
    "http_host",
    "http_url_host",
    "http_connect_target",
    "http_request",
    "http_flow",
    "tls_sni",
    "tls_flow",
}


def _confidence_for_source(source: str) -> str:
    return "confirmed" if source in CONFIRMED_SOURCES else "observed"


def _add(iocs: set[IOC], kind: str, value: str, source: str, packet_number: int = 0) -> None:
    if not value:
        return
    if kind == "ip":
        try:
            normalized = str(ipaddress.ip_address(value))
        except ValueError:
            return
    else:
        normalized = value.lower() if kind == "domain" else value
    iocs.add(
        IOC(
            kind=kind,
            value=normalized,
            source=source,
            packet_number=packet_number,
            confidence=_confidence_for_source(source),
        )
    )


def _is_public_ioc_ip(ip: str) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if any(address in network for network in TEST_NETS):
        return False
    return (
        address.is_global
        and not address.is_private
        and not address.is_loopback
        and not address.is_link_local
        and not address.is_multicast
        and not address.is_reserved
        and not address.is_unspecified
    )


def _is_known_good_ip(ip: str) -> bool:
    return ip in KNOWN_GOOD_RESOLVERS


def _add_ip(iocs: set[IOC], value: str, source: str, packet_number: int = 0) -> None:
    if value and _is_public_ioc_ip(value) and not _is_known_good_ip(value):
        _add(iocs, "ip", value, source, packet_number=packet_number)


def _host_without_port(host: str) -> str:
    value = host.strip()
    if value.startswith("[") and "]" in value:
        return value[1 : value.index("]")]
    if value.count(":") == 1:
        name, port = value.rsplit(":", 1)
        if port.isdigit():
            return name
    return value


def _add_http_host(iocs: set[IOC], host: str, packet_number: int = 0, source: str = "http_host") -> None:
    if not host:
        return
    normalized = _host_without_port(host).rstrip(".")
    try:
        ipaddress.ip_address(normalized)
    except ValueError:
        _add(iocs, "domain", normalized, source, packet_number=packet_number)
        return
    _add_ip(iocs, normalized, source, packet_number=packet_number)


def _dedupe_iocs(iocs: set[IOC]) -> list[IOC]:
    seen: set[tuple[str, str]] = set()
    deduped: list[IOC] = []
    for ioc in sorted(
        iocs,
        key=lambda item: (
            item.kind,
            item.value,
            SOURCE_PRIORITY.get(item.source, 50),
            item.source,
            item.packet_number or 10**12,
        ),
    ):
        key = (ioc.kind, ioc.value)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(ioc)
    return deduped


def extract_iocs(
    dns_events: list[DNSEvent],
    http_events: list[HTTPEvent],
    tls_events: list[TLSEvent],
    flows: list[Flow],
) -> list[IOC]:
    iocs: set[IOC] = set()
    for event in dns_events:
        _add(iocs, "domain", event.query, "dns", packet_number=event.packet_number)
        for answer_domain in event.answer_domains:
            _add(iocs, "domain", answer_domain, "dns_answer_domain", packet_number=event.packet_number)
        for answer in event.answers:
            _add_ip(iocs, answer, "dns_answer", packet_number=event.packet_number)
    for event in http_events:
        _add_http_host(iocs, event.host, packet_number=event.packet_number)
        parsed_uri = urlsplit(event.uri)
        if parsed_uri.scheme in {"http", "https"} and parsed_uri.hostname:
            _add_http_host(
                iocs,
                parsed_uri.hostname,
                packet_number=event.packet_number,
                source="http_url_host",
            )
        elif event.method == "CONNECT":
            connect_target = urlsplit(f"//{event.uri}").hostname
            if connect_target:
                _add_http_host(
                    iocs,
                    connect_target,
                    packet_number=event.packet_number,
                    source="http_connect_target",
                )
        _add(iocs, "url", event.url, "http_request", packet_number=event.packet_number)
        _add_ip(iocs, event.dst_ip, "http_flow", packet_number=event.packet_number)
    for event in tls_events:
        _add(iocs, "domain", event.sni, "tls_sni", packet_number=event.packet_number)
        _add_ip(iocs, event.dst_ip, "tls_flow", packet_number=event.packet_number)
    for flow in flows:
        _add_ip(iocs, flow.src_ip, f"flow:{flow.protocol.lower()}:{flow.src_port}", packet_number=flow.first_packet_number)
        _add_ip(iocs, flow.dst_ip, f"flow:{flow.protocol.lower()}:{flow.dst_port}", packet_number=flow.first_packet_number)
    return _dedupe_iocs(iocs)
