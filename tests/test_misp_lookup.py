import sys
import types

from nettrace.intel.misp_lookup import MispLookup
from nettrace.models.events import IOC


def install_fake_pymisp(monkeypatch, response):
    class FakeMISP:
        def __init__(self, url, api_key, verify_ssl):
            self.url = url
            self.api_key = api_key
            self.verify_ssl = verify_ssl

        def search(self, controller, value):
            return response

    module = types.ModuleType("pymisp")
    module.PyMISP = FakeMISP
    monkeypatch.setitem(sys.modules, "pymisp", module)


def install_failing_pymisp(monkeypatch):
    class FakeMISP:
        def __init__(self, url, api_key, verify_ssl):
            raise RuntimeError("bad misp config")

    module = types.ModuleType("pymisp")
    module.PyMISP = FakeMISP
    monkeypatch.setitem(sys.modules, "pymisp", module)


def test_misp_empty_attribute_response_does_not_create_match(monkeypatch):
    install_fake_pymisp(monkeypatch, {"Attribute": []})
    lookup = MispLookup(enabled=True, url="https://misp.example", api_key="token")

    findings = lookup.match_iocs([IOC("domain", "example.test", "dns")])

    assert findings == []


def test_misp_attribute_response_creates_match(monkeypatch):
    install_fake_pymisp(monkeypatch, {"Attribute": [{"value": "bad.example"}]})
    lookup = MispLookup(enabled=True, url="https://misp.example", api_key="token")

    findings = lookup.match_iocs([IOC("domain", "bad.example", "dns")])

    assert len(findings) == 1
    assert findings[0].category == "threat_intel_match"
    assert findings[0].evidence["misp_result_count"] == 1


def test_misp_initialization_error_returns_low_error_finding(monkeypatch):
    install_failing_pymisp(monkeypatch)
    lookup = MispLookup(enabled=True, url="https://misp.example", api_key="token")

    findings = lookup.match_iocs([IOC("domain", "bad.example", "dns")])

    assert len(findings) == 1
    assert findings[0].category == "misp_error"
    assert findings[0].severity == "low"
