"""Serialization and derived-field coverage for the event/flow dataclasses.

These `to_dict` methods and the `HTTPEvent.url` property sit on the JSON export
path, so a regression here silently corrupts every report format. The dataclass
tests keep them exercised directly instead of only through a full pipeline run.
"""

from nettrace.models.events import (
    DNSEvent,
    Flow,
    FTPEvent,
    HTTPEvent,
    TLSEvent,
    redact_sensitive_query_params,
)


def test_dns_event_to_dict_round_trips_fields():
    event = DNSEvent(
        timestamp=1.0,
        src_ip="10.0.0.5",
        dst_ip="8.8.8.8",
        query="example.com",
        answers=["203.0.113.10"],
        ttl=300,
        packet_number=7,
        answer_domains=["cdn.example.com"],
        answer_ttls=[300],
    )

    data = event.to_dict()

    assert data["query"] == "example.com"
    assert data["answers"] == ["203.0.113.10"]
    assert data["ttl"] == 300
    assert data["answer_ttls"] == [300]


def test_tls_event_to_dict_round_trips_fields():
    event = TLSEvent(
        timestamp=2.0,
        src_ip="10.0.0.5",
        dst_ip="203.0.113.10",
        dst_port=443,
        sni="evil.example",
        packet_number=9,
        src_port=50000,
    )

    data = event.to_dict()

    assert data["sni"] == "evil.example"
    assert data["dst_port"] == 443
    assert data["src_port"] == 50000


def test_ftp_event_to_dict_round_trips_fields():
    event = FTPEvent(
        timestamp=3.0,
        src_ip="10.0.0.5",
        dst_ip="203.0.113.10",
        src_port=50000,
        dst_port=21,
        command="STOR",
        argument="payload.exe",
        packet_number=11,
    )

    data = event.to_dict()

    assert data["command"] == "STOR"
    assert data["argument"] == "payload.exe"


def test_flow_to_dict_drops_internal_fields_and_samples_packets():
    flow = Flow(
        src_ip="10.0.0.5",
        dst_ip="203.0.113.10",
        src_port=50000,
        dst_port=443,
        protocol="TCP",
        first_seen=1.0,
        last_seen=4.0,
        packet_count=3,
        byte_count=180,
        packet_numbers=list(range(1, 12)),
        direction_score=100,
        initial_tcp_seq=42,
        tcp_seq_floor=42,
        tcp_seq_next=180,
    )

    data = flow.to_dict()

    # Internal reassembly bookkeeping must never leak into a report.
    for internal in (
        "direction_score",
        "last_beacon_tcp_seq",
        "initial_tcp_seq",
        "tcp_seq_floor",
        "tcp_seq_next",
        "beacon_timestamps",
        "packet_numbers",
    ):
        assert internal not in data
    assert data["duration"] == 3.0
    # The sample is bounded to eight packet numbers.
    assert data["packet_numbers_sample"] == list(range(1, 9))


def test_flow_to_dict_omits_sample_when_no_packet_numbers():
    flow = Flow(
        src_ip="10.0.0.5",
        dst_ip="203.0.113.10",
        src_port=50000,
        dst_port=443,
        protocol="TCP",
        first_seen=5.0,
        last_seen=5.0,
    )

    data = flow.to_dict()

    assert "packet_numbers_sample" not in data
    # last_seen == first_seen must clamp duration to zero, never go negative.
    assert data["duration"] == 0.0


def test_http_event_url_uses_absolute_uri_when_present():
    event = HTTPEvent(1.0, "10.0.0.5", "203.0.113.10", "GET", "ignored.host", "http://real.example/a")

    assert event.url == "http://real.example/a"


def test_http_event_url_builds_https_for_connect_method():
    event = HTTPEvent(1.0, "10.0.0.5", "203.0.113.10", "CONNECT", "", "proxy.example:443")

    assert event.url == "https://proxy.example:443"


def test_http_event_url_brackets_ipv6_host():
    event = HTTPEvent(1.0, "10.0.0.5", "2606:4700::1111", "GET", "", "/path")

    assert event.url == "http://[2606:4700::1111]/path"


def test_http_event_url_falls_back_to_dst_ip_without_host():
    event = HTTPEvent(1.0, "10.0.0.5", "203.0.113.10", "GET", "", "/beacon")

    assert event.url == "http://203.0.113.10/beacon"
    assert event.to_dict()["url"] == "http://203.0.113.10/beacon"


def test_redact_returns_uri_unchanged_when_query_is_empty():
    # A trailing "?" is technically present but carries no parameters, so there
    # is nothing to redact and the URI must be returned untouched.
    assert redact_sensitive_query_params("http://host/path?") == "http://host/path?"


def test_redact_leaves_non_sensitive_parameters_intact():
    assert redact_sensitive_query_params("http://host/a?id=1&page=2") == "http://host/a?id=1&page=2"
