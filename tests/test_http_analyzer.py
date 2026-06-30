from nettrace.analysis.http_analyzer import analyze_http_events
from nettrace.models.events import HTTPEvent


def test_executable_download_detection_ignores_case_and_query_string():
    event = HTTPEvent(1.0, "10.0.0.5", "203.0.113.66", "GET", "example.com", "/PAYLOAD.EXE?Token=ABC", packet_number=42)

    findings = analyze_http_events([event], {"intel": {"suspicious_user_agents": ""}})

    assert len(findings) == 1
    assert findings[0].category == "http_c2"
    assert findings[0].evidence["url"] == "http://example.com/PAYLOAD.EXE?Token=ABC"
    assert findings[0].evidence["packet_number"] == 42
    assert findings[0].evidence["wireshark_filter"] == "frame.number == 42"


def test_blank_suspicious_user_agent_path_is_ignored():
    event = HTTPEvent(1.0, "10.0.0.5", "203.0.113.66", "GET", "example.com", "/index.html")

    findings = analyze_http_events([event], {"intel": {"suspicious_user_agents": ""}})

    assert findings == []
