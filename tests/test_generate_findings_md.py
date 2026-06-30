from pathlib import Path

from nettrace.report.markdown_report import (
    build_markdown,
    default_output_path,
    infer_victim_host,
    top_domains,
    top_http_urls,
    top_ips,
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
