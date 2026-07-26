from nettrace.analysis.ioc_extractor import (
    extract_iocs,
    extract_observed_artifacts,
    merge_iocs_for_intel,
)
from nettrace.intel.local_ioc_lookup import LocalIntel
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


def test_domain_iocs_are_idna_normalized_and_invalid_hosts_are_rejected():
    dns = [
        DNSEvent(1.0, "10.0.0.5", "8.8.8.8", "bücher.example", packet_number=1),
        DNSEvent(2.0, "10.0.0.5", "8.8.8.8", "bad host.example", packet_number=2),
        DNSEvent(3.0, "10.0.0.5", "8.8.8.8", "empty..label.example", packet_number=3),
    ]

    values = {ioc.value for ioc in extract_iocs(dns, [], [], [])}

    assert "xn--bcher-kva.example" in values
    assert "bad host.example" not in values
    assert "empty..label.example" not in values


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

    iocs = extract_observed_artifacts(flows)
    sources = {ioc.value: ioc.source for ioc in iocs if ioc.kind == "ip"}

    assert sources["13.107.5.88"] == "flow:tcp:51515"
    assert sources["150.60.21.231"] == "flow:tcp:4444"


def test_flow_sourced_ips_are_observed_artifacts_not_iocs():
    flows = [Flow("10.0.0.5", "13.107.5.88", 50000, 443, "TCP", 1.0, 2.0)]

    assert extract_iocs([], [], [], flows) == []
    artifacts = extract_observed_artifacts(flows)

    assert len(artifacts) == 1
    assert artifacts[0].confidence == "observed"


def test_known_bad_ip_seen_only_as_raw_flow_endpoint_is_matched_by_intel():
    # Bug #2: a known-bad IP contacted over a plain TCP flow (no HTTP/TLS/DNS
    # artifact) lands only in observed_artifacts. Intel matching must still see
    # it via merge_iocs_for_intel, or the high-severity hit is missed.
    flows = [Flow("10.0.0.5", "150.60.21.231", 50000, 4444, "TCP", 1.0, 2.0, first_packet_number=9)]
    iocs = extract_iocs([], [], [], flows)
    artifacts = extract_observed_artifacts(flows)
    assert not any(ioc.value == "150.60.21.231" for ioc in iocs)  # not in reported IOC list

    intel_iocs = merge_iocs_for_intel(iocs, artifacts)
    findings = LocalIntel(domains=set(), ips={"150.60.21.231"}).match_iocs(intel_iocs)

    assert [f.evidence["ioc_value"] for f in findings] == ["150.60.21.231"]


def test_merge_for_intel_prefers_confirmed_source_and_dedupes():
    confirmed = extract_iocs(
        [], [HTTPEvent(1.0, "10.0.0.5", "150.60.21.231", "GET", "150.60.21.231", "/a")], [], []
    )
    flows = [Flow("10.0.0.5", "150.60.21.231", 50000, 80, "TCP", 1.0, 2.0)]
    artifacts = extract_observed_artifacts(flows)

    merged = merge_iocs_for_intel(confirmed, artifacts)
    matching = [ioc for ioc in merged if ioc.value == "150.60.21.231"]

    assert len(matching) == 1  # deduped by (kind, value)
    assert not matching[0].source.startswith("flow:")  # confirmed source wins over flow:*
    assert matching[0].confidence == "confirmed"


def test_absolute_form_http_url_is_not_prefixed_twice():
    http = [HTTPEvent(2.0, "10.0.0.5", "45.33.32.156", "GET", "proxy.local", "http://evil.example/a.exe")]

    iocs = extract_iocs([], http, [], [])

    assert any(ioc.kind == "url" and ioc.value == "http://evil.example/a.exe" for ioc in iocs)
    assert any(ioc.kind == "domain" and ioc.value == "evil.example" for ioc in iocs)
    assert not any("proxy.localhttp" in ioc.value for ioc in iocs)


def test_connect_target_is_extracted_independently_from_host_header():
    http = [HTTPEvent(2.0, "10.0.0.5", "45.33.32.156", "CONNECT", "proxy.local", "evil.example:443")]

    iocs = extract_iocs([], http, [], [])

    assert any(ioc.kind == "domain" and ioc.value == "evil.example" for ioc in iocs)
    assert any(ioc.kind == "url" and ioc.value == "https://evil.example:443" for ioc in iocs)


def test_ipv6_iocs_are_canonicalized():
    flows = [
        Flow("fd00::1", "2001:4860:4860:0:0:0:0:8888", 50000, 443, "TCP", 1.0, 2.0),
    ]

    iocs = extract_observed_artifacts(flows)

    assert any(ioc.kind == "ip" and ioc.value == "2001:4860:4860::8888" for ioc in iocs)


def test_ipv6_destination_fallback_produces_valid_bracketed_url():
    event = HTTPEvent(1.0, "fd00::1", "2001:4860:4860::8888", "GET", "", "/payload")

    assert event.url == "http://[2001:4860:4860::8888]/payload"
