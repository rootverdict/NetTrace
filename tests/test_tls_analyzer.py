from nettrace.analysis.tls_analyzer import analyze_tls_events
from nettrace.models.events import Flow, TLSEvent


def test_tls_sni_length_threshold_is_configurable():
    event = TLSEvent(1.0, "10.0.0.5", "203.0.113.66", 443, "abcdefghijklmnop.example")

    findings = analyze_tls_events([event], [], {"tls_sni_length_threshold": 20})
    relaxed = analyze_tls_events([event], [], {"tls_sni_length_threshold": 10})

    assert findings == []
    assert len(relaxed) == 1


def test_long_tls_requires_observed_tls_and_supports_alternate_ports():
    tls_event = TLSEvent(1.0, "10.0.0.5", "45.33.32.156", 8443, "example.com", src_port=50000)
    confirmed = Flow("10.0.0.5", "45.33.32.156", 50000, 8443, "TCP", 0.0, 1000.0)
    unconfirmed = Flow("10.0.0.5", "9.9.9.9", 50001, 443, "UDP", 0.0, 1000.0)

    findings = analyze_tls_events([tls_event], [confirmed, unconfirmed], {"long_tls_session_seconds": 900})

    long_findings = [finding for finding in findings if finding.category == "long_tls_session"]
    assert len(long_findings) == 1
    assert long_findings[0].evidence["dst_ip"] == "45.33.32.156"
