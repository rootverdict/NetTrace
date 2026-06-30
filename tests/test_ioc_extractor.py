from nettrace.analysis.ioc_extractor import extract_iocs
from nettrace.models.events import DNSEvent, Flow, HTTPEvent, TLSEvent


def test_ioc_extraction_collects_domains_urls_and_ips():
    dns = [DNSEvent(1.0, "10.0.0.5", "8.8.8.8", "example.com", ["93.184.216.34"], packet_number=7)]
    http = [HTTPEvent(2.0, "10.0.0.5", "93.184.216.34", "GET", "example.com", "/a.exe", packet_number=8)]
    tls = [TLSEvent(3.0, "10.0.0.5", "13.107.5.88", 443, "secure.example.com", packet_number=9)]
    flows = [Flow("10.0.0.5", "93.184.216.34", 50000, 80, "TCP", 1.0, 2.0, first_packet_number=10)]
    values = {ioc.value for ioc in extract_iocs(dns, http, tls, flows)}
    assert "example.com" in values
    assert "http://example.com/a.exe" in values
    assert "13.107.5.88" in values
    assert next(ioc for ioc in extract_iocs(dns, http, tls, flows) if ioc.value == "http://example.com/a.exe").packet_number == 8


def test_url_ioc_preserves_case_sensitive_path_and_query():
    http = [HTTPEvent(2.0, "10.0.0.5", "203.0.113.66", "GET", "Example.COM", "/Payload.EXE?Token=ABC")]

    iocs = extract_iocs([], http, [], [])
    values = {ioc.value for ioc in iocs}

    assert "example.com" in values
    assert "http://Example.COM/Payload.EXE?Token=ABC" in values


def test_http_host_ip_is_not_added_as_domain_ioc():
    http = [HTTPEvent(2.0, "10.0.0.5", "45.202.35.190", "GET", "45.202.35.190", "/payload.sh")]

    iocs = extract_iocs([], http, [], [])

    assert not any(ioc.kind == "domain" and ioc.value == "45.202.35.190" for ioc in iocs)
    assert any(ioc.kind == "ip" and ioc.value == "45.202.35.190" for ioc in iocs)


def test_http_host_ip_with_port_is_not_added_as_domain_ioc():
    http = [HTTPEvent(2.0, "10.0.0.5", "45.202.35.190", "GET", "45.202.35.190:8080", "/payload.sh")]

    iocs = extract_iocs([], http, [], [])

    assert not any(ioc.kind == "domain" and ioc.value == "45.202.35.190:8080" for ioc in iocs)
    assert any(ioc.kind == "ip" and ioc.value == "45.202.35.190" for ioc in iocs)


def test_ioc_dedupe_keeps_earliest_packet_for_same_source():
    http = [
        HTTPEvent(2.0, "10.0.0.5", "45.202.35.190", "GET", "45.202.35.190", "/one", packet_number=22),
        HTTPEvent(3.0, "10.0.0.5", "45.202.35.190", "GET", "45.202.35.190", "/two", packet_number=16),
    ]

    iocs = extract_iocs([], http, [], [])
    host_ioc = next(ioc for ioc in iocs if ioc.kind == "ip" and ioc.value == "45.202.35.190")

    assert host_ioc.source == "http_host"
    assert host_ioc.packet_number == 16


def test_ioc_extraction_dedupes_ips_and_filters_internal_resolvers():
    http = [HTTPEvent(2.0, "10.0.0.5", "13.107.5.88", "GET", "example.com", "/a.exe")]
    flows = [
        Flow("10.0.0.5", "13.107.5.88", 50000, 80, "TCP", 1.0, 2.0),
        Flow("10.0.0.5", "8.8.8.8", 53000, 53, "UDP", 1.0, 2.0),
    ]

    iocs = extract_iocs([], http, [], flows)
    ip_values = [ioc.value for ioc in iocs if ioc.kind == "ip"]

    assert ip_values == ["13.107.5.88"]
    assert next(ioc for ioc in iocs if ioc.value == "13.107.5.88").source == "http_flow"


def test_ioc_extraction_filters_non_global_ips():
    flows = [
        Flow("10.0.0.5", "127.0.0.1", 50000, 80, "TCP", 1.0, 2.0),
        Flow("10.0.0.5", "169.254.1.1", 50001, 80, "TCP", 1.0, 2.0),
        Flow("10.0.0.5", "224.0.0.1", 50002, 80, "UDP", 1.0, 2.0),
        Flow("10.0.0.5", "192.0.2.66", 50003, 80, "TCP", 1.0, 2.0),
        Flow("10.0.0.5", "198.51.100.66", 50004, 80, "TCP", 1.0, 2.0),
        Flow("10.0.0.5", "203.0.113.66", 50003, 80, "TCP", 1.0, 2.0),
    ]

    iocs = extract_iocs([], [], [], flows)

    assert [ioc for ioc in iocs if ioc.kind == "ip"] == []


def test_flow_sourced_ips_use_structured_source_for_both_directions():
    flows = [
        Flow("13.107.5.88", "150.60.21.231", 51515, 4444, "TCP", 1.0, 2.0),
    ]

    iocs = extract_iocs([], [], [], flows)
    sources = {ioc.value: ioc.source for ioc in iocs if ioc.kind == "ip"}

    assert sources["13.107.5.88"] == "flow:tcp:51515"
    assert sources["150.60.21.231"] == "flow:tcp:4444"
