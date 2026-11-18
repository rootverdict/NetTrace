from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from typing import Any

from nettrace.models.findings import Finding

logger = logging.getLogger(__name__)

DEFAULT_MODEL = "gemini-3.5-flash-lite"
API_URL_TEMPLATE = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}"


class AIClient:
    """Client for calling Google Gemini API using standard Python libraries."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str = DEFAULT_MODEL,
        timeout_seconds: int = 15,
    ) -> None:
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY", "")
        self.model = model
        self.timeout_seconds = timeout_seconds

    @property
    def is_available(self) -> bool:
        return bool(self.api_key.strip())

    def generate(self, prompt: str, system_instruction: str | None = None) -> str | None:
        if not self.is_available:
            return None

        url = API_URL_TEMPLATE.format(model=self.model, key=self.api_key)
        payload: dict[str, Any] = {
            "contents": [
                {
                    "parts": [{"text": prompt}],
                }
            ],
            "generationConfig": {
                "temperature": 0.2,
                "topP": 0.8,
                "maxOutputTokens": 2048,
                "responseMimeType": "application/json",
            },
        }
        if system_instruction:
            payload["systemInstruction"] = {
                "parts": [{"text": system_instruction}],
            }

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        import time
        max_retries = 3
        for attempt in range(max_retries):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                    result = json.loads(resp.read().decode("utf-8"))
                    candidates = result.get("candidates", [])
                    if not candidates:
                        return None
                    parts = candidates[0].get("content", {}).get("parts", [])
                    if not parts:
                        return None
                    return str(parts[0].get("text", "")).strip()
            except urllib.error.HTTPError as exc:
                if exc.code in (429, 503) and attempt < max_retries - 1:
                    time.sleep(2 * (attempt + 1))
                    continue
                logger.warning("AI API call failed: %s", exc)
                return None
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, KeyError) as exc:
                if attempt < max_retries - 1:
                    time.sleep(2 * (attempt + 1))
                    continue
                logger.warning("AI API call failed: %s", exc)
                return None


def run_ai_analysis(
    findings: list[Finding],
    config: dict[str, Any],
    pcap_name: str = "",
) -> dict[str, Any] | None:
    """Entry point for the AI threat intelligence analysis."""
    ai_config = config.get("ai", {})
    if not ai_config.get("enabled", False):
        return None

    api_key_env = ai_config.get("api_key_env", "GEMINI_API_KEY")
    api_key = os.environ.get(api_key_env, "").strip()
    if not api_key:
        logger.info("AI analysis requested but %s environment variable is not set.", api_key_env)
        return None

    model = ai_config.get("model", DEFAULT_MODEL)
    timeout = int(ai_config.get("timeout_seconds", 15))
    client = AIClient(api_key=api_key, model=model, timeout_seconds=timeout)

    relevant_findings = [
        f for f in findings
        if f.severity in ("critical", "high", "medium")
    ]
    if not relevant_findings:
        relevant_findings = findings[:10]

    findings_summary = [
        {
            "title": f.title,
            "category": f.category,
            "severity": f.severity,
            "score": f.score,
            "attack_id": f.attack_id,
            "evidence": {k: v for k, v in f.evidence.items() if k not in ("flow_samples",)},
        }
        for f in relevant_findings[:20]
    ]

    system_prompt = (
        "You are an expert Network Security Analyst and Threat Hunter analyzing malware network traffic.\n"
        "Provide your analysis strictly in valid JSON format matching this schema:\n"
        "{\n"
        '  "executive_summary": "1-2 concise paragraphs summarizing the incident and primary threats",\n'
        '  "threat_verdict": "MALICIOUS" | "SUSPICIOUS" | "BENIGN",\n'
        '  "confidence": "HIGH" | "MEDIUM" | "LOW",\n'
        '  "attack_narrative": ["Step 1: Description", "Step 2: Description", "Step 3: Description"],\n'
        '  "recommended_actions": ["Action 1", "Action 2", "Action 3"],\n'
        '  "wireshark_hunting_tips": ["Wireshark filter or guidance 1", "Guidance 2"]\n'
        "}\n"
        "IMPORTANT: 'attack_narrative' must be a list of pointwise strings detailing each step in chronological order.\n"
        "Do not include markdown code block ticks (```) around the JSON output."
    )

    user_prompt = (
        f"Analyze the following network findings extracted from capture '{pcap_name}':\n\n"
        f"{json.dumps(findings_summary, indent=2)}\n\n"
        "Evaluate the findings, correlate suspicious patterns, and produce the structured JSON assessment."
    )

    response_text = client.generate(user_prompt, system_instruction=system_prompt)
    if not response_text:
        return None

    cleaned = response_text.strip()
    if cleaned.startswith("```"):
        lines = cleaned.splitlines()
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        cleaned = "\n".join(lines).strip()

    try:
        assessment = json.loads(cleaned)
    except json.JSONDecodeError:
        # Fallback: attempt to extract fields or repair truncated JSON
        import re
        assessment = {}
        for key in ("executive_summary", "threat_verdict", "confidence"):
            match = re.search(rf'"{key}"\s*:\s*"([^"]+)"', cleaned)
            if match:
                assessment[key] = match.group(1)
        narrative_matches = re.findall(r'"attack_narrative"\s*:\s*\[(.*?)\]', cleaned, re.DOTALL)
        if narrative_matches:
            steps = re.findall(r'"([^"]+)"', narrative_matches[0])
            assessment["attack_narrative"] = steps
        actions_matches = re.findall(r'"recommended_actions"\s*:\s*\[(.*?)\]', cleaned, re.DOTALL)
        if actions_matches:
            actions = re.findall(r'"([^"]+)"', actions_matches[0])
            assessment["recommended_actions"] = actions
        tips_matches = re.findall(r'"wireshark_hunting_tips"\s*:\s*\[(.*?)\]', cleaned, re.DOTALL)
        if tips_matches:
            tips = re.findall(r'"([^"]+)"', tips_matches[0])
            assessment["wireshark_hunting_tips"] = tips

        if not assessment.get("executive_summary"):
            return None

    # Normalize attack_narrative to list of points if LLM returned a single string
    narrative = assessment.get("attack_narrative")
    if isinstance(narrative, str):
        import re
        points = re.split(r"(?:(?<=\.)\s+(?=\d+\.|\bStep\b)|\n+)", narrative)
        assessment["attack_narrative"] = [p.strip() for p in points if p.strip()]
    elif not isinstance(narrative, list):
        assessment["attack_narrative"] = []

    if not isinstance(assessment.get("recommended_actions"), list):
        assessment["recommended_actions"] = []
    if not isinstance(assessment.get("wireshark_hunting_tips"), list):
        assessment["wireshark_hunting_tips"] = []

    assessment.setdefault("threat_verdict", "SUSPICIOUS")
    assessment.setdefault("confidence", "MEDIUM")
    return assessment
