import sys
import types

from nettrace.intel.misp_lookup import MispLookup
from nettrace.mapping.severity import score_findings
from nettrace.models.events import IOC


def install_fake_pymisp(monkeypatch, response, calls=None):
    class FakeMISP:
        def __init__(self, url, api_key, verify_ssl, timeout=None):
            self.url = url
            self.api_key = api_key
            self.verify_ssl = verify_ssl
            if calls is not None:
                calls.append(("init", timeout))

        def search(self, controller, value):
            if calls is not None:
                calls.append(("search", value))
            return response

    module = types.ModuleType("pymisp")
    module.PyMISP = FakeMISP
    monkeypatch.setitem(sys.modules, "pymisp", module)


def install_failing_pymisp(monkeypatch):
    class FakeMISP:
        def __init__(self, url, api_key, verify_ssl, timeout=None):
            raise RuntimeError("bad misp config")

    module = types.ModuleType("pymisp")
    module.PyMISP = FakeMISP
    monkeypatch.setitem(sys.modules, "pymisp", module)


def test_misp_empty_attribute_response_does_not_create_match(monkeypatch):
    install_fake_pymisp(monkeypatch, {"Attribute": []})
    lookup = MispLookup(enabled=True, url="https://misp.example", api_key="token")

    findings = lookup.match_iocs([IOC("domain", "example.test", "dns")])

    assert findings == []


def test_misp_unrelated_singleton_response_does_not_create_match(monkeypatch):
    install_fake_pymisp(monkeypatch, {"Attribute": [{"value": "unrelated.example"}]})
    lookup = MispLookup(enabled=True, url="https://misp.example", api_key="token")

    findings = lookup.match_iocs([IOC("domain", "bad.example", "dns")])

    assert findings == []


def test_misp_domain_matching_is_case_insensitive(monkeypatch):
    install_fake_pymisp(monkeypatch, {"Attribute": [{"value": "BAD.EXAMPLE"}]})
    lookup = MispLookup(enabled=True, url="https://misp.example", api_key="token")

    findings = lookup.match_iocs([IOC("domain", "bad.example", "dns")])

    assert len(findings) == 1
    assert findings[0].category == "threat_intel_match"


def test_enabled_misp_with_missing_settings_returns_warning_finding():
    lookup = MispLookup(enabled=True, url="", api_key="")

    findings = lookup.match_iocs([IOC("domain", "bad.example", "dns")])

    assert len(findings) == 1
    assert findings[0].title == "MISP configuration incomplete"
    assert findings[0].evidence["missing_settings"] == ["url", "api_key"]


def test_misp_attribute_response_creates_match(monkeypatch):
    install_fake_pymisp(monkeypatch, {"Attribute": [{"value": "bad.example"}]})
    lookup = MispLookup(enabled=True, url="https://misp.example", api_key="token")

    findings = lookup.match_iocs([IOC("domain", "bad.example", "dns")])

    assert len(findings) == 1
    assert findings[0].category == "threat_intel_match"
    assert findings[0].evidence["misp_result_count"] == 1
    assert findings[0].evidence["source"] == "dns"


def test_misp_initialization_error_returns_low_error_finding(monkeypatch):
    install_failing_pymisp(monkeypatch)
    lookup = MispLookup(enabled=True, url="https://misp.example", api_key="token")

    findings = lookup.match_iocs([IOC("domain", "bad.example", "dns")])

    assert len(findings) == 1
    assert findings[0].category == "misp_error"
    assert findings[0].severity == "low"

    score_findings(findings)
    assert findings[0].severity == "low"


def test_misp_api_key_can_be_loaded_from_environment(monkeypatch):
    monkeypatch.setenv("NETTRACE_TEST_MISP_KEY", "secret-token")

    lookup = MispLookup.from_config(
        {
            "enabled": True,
            "url": "https://misp.example",
            "api_key": "",
            "api_key_env": "NETTRACE_TEST_MISP_KEY",
        }
    )

    assert lookup.api_key == "secret-token"


def test_misp_batches_queries_applies_timeout_and_caps_iocs(monkeypatch):
    calls = []
    response = {
        "Attribute": [
            {"value": "one.example"},
            {"value": "two.example"},
            {"value": "three.example"},
        ]
    }
    install_fake_pymisp(monkeypatch, response, calls)
    lookup = MispLookup(
        enabled=True,
        url="https://misp.example",
        api_key="token",
        max_iocs=3,
        batch_size=2,
        timeout_seconds=7,
    )
    iocs = [
        IOC("domain", "one.example", "dns"),
        IOC("domain", "two.example", "dns"),
        IOC("domain", "three.example", "dns"),
        IOC("domain", "four.example", "dns"),
    ]

    findings = lookup.match_iocs(iocs)

    assert calls[0] == ("init", 7)
    assert [call for call in calls if call[0] == "search"] == [
        ("search", ["one.example", "two.example"]),
        ("search", ["three.example"]),
    ]
    assert sum(finding.category == "threat_intel_match" for finding in findings) == 3
    assert any(finding.title == "MISP lookup truncated" for finding in findings)
