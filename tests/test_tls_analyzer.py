from nettrace.analysis.tls_analyzer import analyze_tls_events
from nettrace.models.events import TLSEvent


def test_tls_sni_length_threshold_is_configurable():
    event = TLSEvent(1.0, "10.0.0.5", "203.0.113.66", 443, "abcdefghijklmnop.example")

    findings = analyze_tls_events([event], [], {"tls_sni_length_threshold": 20})
    relaxed = analyze_tls_events([event], [], {"tls_sni_length_threshold": 10})

    assert findings == []
    assert len(relaxed) == 1
