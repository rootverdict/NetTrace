import json
from pathlib import Path

from nettrace.report.markdown_report import (
    build_markdown,
    default_output_path,
    format_ip_port,
    infer_victim_host,
    is_rfc1918,
    top_domains,
    top_http_urls,
    top_ips,
    unique,
    write_markdown_report,
)


def sample_report():
    return {
        "pcap_path": "samples/real/example.pcap",
        "summary": {
            "dns_events": 2,
            "http_events": 1,
            "tls_events": 1,
            "flows": 2,
            "iocs": 3,
            "findings": 2,
            "critical": 0,
            "high": 1,
            "medium": 1,
            "low": 0,
        },
        "http_events": [
            {
                "timestamp": 1.0,
                "src_ip": "10.0.0.5",
                "dst_ip": "203.0.113.66",
                "host": "malware-test.example",
                "url": "http://malware-test.example/payload",
            }
        ],
        "flows": [
            {"src_ip": "10.0.0.5", "dst_ip": "203.0.113.66", "dst_port": 8080, "packet_count": 80},
            {"src_ip": "203.0.113.66", "dst_ip": "10.0.0.5", "dst_port": 51515, "packet_count": 120},
        ],
        "iocs": [
            {"kind": "domain", "value": "malware-test.example"},
            {"kind": "ip", "value": "203.0.113.66"},
        ],
        "findings": [
            {
                "title": "High-frequency connection",
                "category": "high_frequency_connections",
                "severity": "medium",
                "attack_id": "T1020",
                "attack_name": "Automated Exfiltration",
                "evidence": {"src_ip": "10.0.0.5", "dst_ip": "203.0.113.66", "dst_port": 8080},
            },
            {
                "title": "Possible beaconing behavior",
                "category": "network_beaconing",
                "severity": "high",
                "attack_id": "T1071.001",
                "attack_name": "Application Layer Protocol: Web Protocols",
                "evidence": {"src_ip": "10.0.0.5", "dst_ip": "203.0.113.66", "dst_port": 8080},
            },
        ],
    }


def test_infer_victim_host_from_outbound_flows():
    assert infer_victim_host(sample_report()) == "10.0.0.5"


def test_top_http_urls_excludes_common_hosts():
    assert top_http_urls(sample_report()) == ["http://malware-test.example/payload"]


def test_top_ips_includes_public_destination_with_port():
    assert top_ips(sample_report(), "10.0.0.5")[0] == "203.0.113.66:8080"


def test_top_domains_excludes_common_microsoft_hosts():
    report = sample_report()
    report["iocs"].extend(
        [
            {"kind": "domain", "value": "dns.msftncsi.com"},
            {"kind": "domain", "value": "nexusrules.officeapps.live.com"},
            {"kind": "domain", "value": "malicious.example"},
        ]
    )

    assert top_domains(report) == ["malware-test.example", "malicious.example"]


def test_build_markdown_contains_summary_and_iocs():
    markdown = build_markdown(sample_report(), source="Unit Test", source_url="https://example.test")

    assert "# NetTrace Findings: example.pcap" in markdown
    assert "- Source: Unit Test" in markdown
    assert "- Findings: 2" in markdown
    assert "`http://malware-test.example/payload`" in markdown
    assert "T1071.001 - Application Layer Protocol: Web Protocols" in markdown


def test_default_output_path_uses_findings_folder_and_sample_name():
    path = default_output_path(Path("output/real/example_findings.json"))

    assert path == Path("findings/example_FINDINGS.md")


def test_markdown_escapes_operator_supplied_plain_text():
    report = sample_report()

    markdown = build_markdown(report, source="source\n## injected", source_url="<script>alert(1)</script>")

    # Plain-text fields are interpolated into prose, so they stay HTML-escaped
    # and single-line: neither raw markup nor an injected heading survives.
    assert "<script" not in markdown
    assert "&lt;script&gt;" in markdown
    assert "source\n## injected" not in markdown
    assert "source ## injected" in markdown


def test_capture_controlled_html_stays_inside_a_code_span():
    """Capture data is attacker-controlled, so it must not escape its span.

    A code span's content is rendered literally by a conforming Markdown
    renderer, so containment -- not entity-escaping -- is what keeps hostile
    markup inert. Entity-escaping here is what corrupted URLs (see the `&`
    test below), so the backtick-run fencing does the work instead.
    """
    report = sample_report()
    report["http_events"][0]["url"] = "http://evil/`<img src=x onerror=alert(1)>"

    markdown = build_markdown(report)

    # A lone backtick in the value cannot terminate the doubled delimiter.
    assert "``http://evil/`<img src=x onerror=alert(1)>``" in markdown
    assert "\n<img" not in markdown


def test_markdown_does_not_mangle_ampersands_in_urls():
    report = sample_report()
    report["http_events"][0]["url"] = "http://malware-test.example/a?id=1&token=2"

    markdown = build_markdown(report)

    assert "http://malware-test.example/a?id=1&token=2" in markdown
    assert "&amp;" not in markdown


def test_markdown_displays_analysis_warnings():
    report = sample_report()
    report["warnings"] = ["HTTP events truncated at 10 entries."]

    markdown = build_markdown(report)

    assert "## Analysis Warnings" in markdown
    assert "HTTP events truncated at 10 entries." in markdown


def test_ipv6_internal_host_and_endpoint_formatting():
    report = {
        "flows": [
            {
                "src_ip": "fd00::5",
                "dst_ip": "2606:4700:4700::1111",
                "src_port": 50000,
                "dst_port": 443,
                "packet_count": 20,
            }
        ],
        "findings": [
            {
                "category": "high_frequency_connections",
                "evidence": {
                    "src_ip": "fd00::5",
                    "dst_ip": "2606:4700:4700::1111",
                    "dst_port": 443,
                },
            }
        ],
        "iocs": [],
        "http_events": [],
        "dns_events": [],
        "tls_events": [],
    }

    victim = infer_victim_host(report)

    assert victim == "fd00::5"
    assert top_ips(report, victim) == ["[2606:4700:4700::1111]:443"]


def test_is_rfc1918_rejects_non_ip_strings():
    assert is_rfc1918("not-an-ip") is False
    assert is_rfc1918("10.0.0.1") is True


def test_format_ip_port_handles_ipv6_and_invalid_input():
    assert format_ip_port("2001:db8::1", 443) == "[2001:db8::1]:443"
    assert format_ip_port("not-an-ip", 80) == "not-an-ip:80"


def test_unique_stops_at_limit_and_skips_blanks_and_dupes():
    result = unique(["a", "", "a", "b", "c", "d"], limit=3)

    assert result == ["a", "b", "c"]


def test_infer_victim_host_falls_back_to_event_source_when_no_outbound_flows():
    # No flow has an internal source reaching an external destination, so the
    # heuristic falls through to the first internal host seen in the events.
    report = {
        "flows": [],
        "http_events": [{"src_ip": "10.0.0.9"}],
        "dns_events": [],
        "tls_events": [],
    }

    assert infer_victim_host(report) == "10.0.0.9"


def test_infer_victim_host_returns_unknown_without_any_internal_host():
    report = {"flows": [], "http_events": [], "dns_events": [], "tls_events": []}

    assert infer_victim_host(report) == "unknown"


def test_top_ips_appends_bare_ioc_ip_not_already_listed():
    report = {
        "flows": [],
        "http_events": [],
        "dns_events": [],
        "tls_events": [],
        "findings": [],
        "iocs": [{"kind": "ip", "value": "198.51.100.7"}],
    }

    assert top_ips(report, "10.0.0.5") == ["198.51.100.7"]


def test_analyst_paragraph_scales_down_for_low_severity_only_findings():
    report = sample_report()
    for finding in report["findings"]:
        finding["severity"] = "low"

    markdown = build_markdown(report)

    assert "lower-confidence heuristic finding" in markdown
    assert "does\nnot" not in markdown  # prose stays coherent, no stray newline


def test_analyst_paragraph_states_nothing_found_for_empty_findings():
    report = sample_report()
    report["findings"] = []
    report["summary"]["findings"] = 0

    markdown = build_markdown(report)

    assert "No behavioral findings were produced from this capture." in markdown


def test_write_markdown_report_reads_json_and_writes_findings_file(tmp_path):
    json_path = tmp_path / "capture_findings.json"
    json_path.write_text(json.dumps(sample_report()), encoding="utf-8")
    output_path = tmp_path / "out" / "capture_FINDINGS.md"

    destination = write_markdown_report(json_path, output_path)

    assert destination == output_path
    assert output_path.is_file()
    assert "# NetTrace Findings" in output_path.read_text(encoding="utf-8")
