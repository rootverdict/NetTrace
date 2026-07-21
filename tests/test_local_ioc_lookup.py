from pathlib import Path

from nettrace.config import load_config
from nettrace.intel.local_ioc_lookup import LocalIntel
from nettrace.models.events import IOC


def test_local_ioc_lookup_matches_and_ignores_misses():
    intel = LocalIntel(domains={"malware-test.example"}, ips={"203.0.113.66"})
    iocs = [
        IOC(kind="domain", value="malware-test.example", source="dns", packet_number=12),
        IOC(kind="domain", value="benign.example", source="dns"),
    ]

    findings = intel.match_iocs(iocs)

    assert len(findings) == 1
    assert findings[0].category == "threat_intel_match"
    assert findings[0].evidence["ioc_value"] == "malware-test.example"
    assert findings[0].evidence["packet_number"] == 12


def test_blank_local_intel_paths_are_ignored():
    intel = LocalIntel.from_config({"known_bad_domains": "", "known_bad_ips": ""})

    assert intel.domains == set()
    assert intel.ips == set()


def test_packaged_demo_ip_list_contains_no_unmatchable_documentation_addresses():
    config = load_config(Path("does-not-exist.yaml"))
    intel = LocalIntel.from_config(config["intel"])

    assert intel.ips == set()


def test_local_ioc_files_ignore_indented_comments(tmp_path):
    domains = tmp_path / "domains.txt"
    domains.write_text("  # analyst note\nEvil.Example\n", encoding="utf-8")

    intel = LocalIntel.from_config({"known_bad_domains": str(domains), "known_bad_ips": ""})

    assert intel.domains == {"evil.example"}


def test_local_ipv6_intel_is_canonicalized(tmp_path):
    ips = tmp_path / "ips.txt"
    ips.write_text("2001:4860:4860:0:0:0:0:8888\n", encoding="utf-8")

    intel = LocalIntel.from_config({"known_bad_domains": "", "known_bad_ips": str(ips)})

    assert intel.ips == {"2001:4860:4860::8888"}
