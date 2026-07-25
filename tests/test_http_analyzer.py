from scapy.all import IP, Raw, TCP

from nettrace.analysis.http_analyzer import analyze_http_events
from nettrace.models.events import HTTPEvent, redact_sensitive_query_params
from nettrace.parsers.http_extractor import extract_http_event


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


def test_post_to_executable_path_is_not_labeled_a_download():
    # Bug #5: POST/PUT/PATCH to a *.exe path is not evidence of a download.
    event = HTTPEvent(1.0, "10.0.0.5", "203.0.113.66", "POST", "example.com", "/upload/report.exe")

    findings = analyze_http_events([event], {"intel": {"suspicious_user_agents": ""}})

    assert len(findings) == 1
    assert "download" not in findings[0].title.lower()
    assert findings[0].confidence == "low"


def test_get_executable_path_is_labeled_possible_download():
    event = HTTPEvent(1.0, "10.0.0.5", "203.0.113.66", "GET", "example.com", "/payload.exe")

    findings = analyze_http_events([event], {"intel": {"suspicious_user_agents": ""}})

    assert findings[0].title == "Possible executable/script download request"
    assert findings[0].confidence == "medium"


def test_suspicious_user_agent_matches_by_tool_name_ignoring_version(tmp_path):
    # Bug #17: an entry for "curl/7.68.0" should still catch "curl/8.4.0",
    # and the finding is now low-confidence context, not "suspicious".
    ua_file = tmp_path / "uas.txt"
    ua_file.write_text("curl/7.68.0\n", encoding="utf-8")
    event = HTTPEvent(
        1.0, "10.0.0.5", "203.0.113.66", "GET", "example.com", "/",
        user_agent="curl/8.4.0",
    )

    findings = analyze_http_events([event], {"intel": {"suspicious_user_agents": str(ua_file)}})

    assert len(findings) == 1
    assert findings[0].category == "http_automation_client"
    assert findings[0].confidence == "low"


def test_redact_sensitive_query_params_removes_secrets():
    # Bug #16: HTTP query params were stored/exported verbatim, leaking
    # tokens/API keys/session IDs into every report format.
    assert redact_sensitive_query_params("/reset-password?token=secret123") == "/reset-password?token=%3Credacted%3E"
    assert redact_sensitive_query_params("/api?api_key=123456") == "/api?api_key=%3Credacted%3E"


def test_redact_sensitive_query_params_preserves_non_sensitive_params():
    result = redact_sensitive_query_params("/download?signature=xyz&legit_param=keepme")
    assert "legit_param=keepme" in result
    assert "signature=%3Credacted%3E" in result


def test_redact_sensitive_query_params_leaves_benign_query_untouched():
    assert redact_sensitive_query_params("/search?q=normal+query") == "/search?q=normal+query"


def test_redact_sensitive_query_params_no_query_string_untouched():
    assert redact_sensitive_query_params("/plain/path") == "/plain/path"


def test_http_extractor_redacts_query_params_in_constructed_event():
    packet = IP(src="10.0.0.5", dst="203.0.113.1") / TCP(sport=50000, dport=80, seq=100, flags="PA") / Raw(
        load=b"GET /login?session=abcdef123 HTTP/1.1\r\nHost: example.com\r\n\r\n"
    )
    packet.time = 1.0

    event = extract_http_event(packet, packet_number=1)

    assert event is not None
    assert "abcdef123" not in event.uri
    assert "session=%3Credacted%3E" in event.uri
