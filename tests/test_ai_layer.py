from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from nettrace.ai.analyzer import AIClient, run_ai_analysis
from nettrace.models.findings import Finding


def test_ai_client_not_available_when_no_key():
    client = AIClient(api_key="")
    assert not client.is_available
    assert client.generate("hello") is None


def test_ai_client_generate_success():
    client = AIClient(api_key="test-key")
    mock_response = {
        "candidates": [
            {
                "content": {
                    "parts": [{"text": '{"executive_summary": "Test summary", "threat_verdict": "MALICIOUS"}'}]
                }
            }
        ]
    }
    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_cm = MagicMock()
        mock_cm.read.return_value = json.dumps(mock_response).encode("utf-8")
        mock_cm.__enter__.return_value = mock_cm
        mock_urlopen.return_value = mock_cm

        res = client.generate("prompt")
        assert res is not None
        assert "Test summary" in res


def test_run_ai_analysis_disabled():
    config = {"ai": {"enabled": False}}
    findings = [Finding(title="Test", description="desc", evidence={}, category="test")]
    assert run_ai_analysis(findings, config) is None


def test_run_ai_analysis_enabled_with_mocked_ai(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "mock-key")
    config = {
        "ai": {
            "enabled": True,
            "api_key_env": "GEMINI_API_KEY",
            "model": "gemini-3.5-flash-lite",
            "timeout_seconds": 5,
        }
    }
    findings = [
        Finding(
            title="Beaconing to C2",
            description="Regular beaconing detected",
            evidence={"dst_ip": "198.51.100.1"},
            category="network_beaconing",
            severity="high",
            score=80,
        )
    ]

    mock_llm_json = {
        "executive_summary": "Active C2 beaconing observed.",
        "threat_verdict": "MALICIOUS",
        "confidence": "HIGH",
        "attack_narrative": "Internal host established beacon to 198.51.100.1.",
        "recommended_actions": ["Block 198.51.100.1 on firewall"],
        "wireshark_hunting_tips": ["ip.addr == 198.51.100.1"],
    }

    with patch.object(AIClient, "generate", return_value=json.dumps(mock_llm_json)):
        assessment = run_ai_analysis(findings, config, pcap_name="test.pcap")
        assert assessment is not None
        assert assessment["threat_verdict"] == "MALICIOUS"
        assert assessment["confidence"] == "HIGH"
        assert "Active C2 beaconing" in assessment["executive_summary"]
        assert len(assessment["recommended_actions"]) == 1
