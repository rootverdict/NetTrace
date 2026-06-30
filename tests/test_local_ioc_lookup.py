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
