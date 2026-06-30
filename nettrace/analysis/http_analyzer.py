from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit

from nettrace.analysis.evidence import packet_evidence
from nettrace.models.events import HTTPEvent
from nettrace.models.findings import Finding


def _load_lines(path: str) -> set[str]:
    if not path:
        return set()
    file_path = Path(path)
    if not file_path.is_file():
        return set()
    return {line.strip().lower() for line in file_path.read_text(encoding="utf-8").splitlines() if line.strip()}


def event_url(event: HTTPEvent) -> str:
    host = event.host or event.dst_ip
    scheme = "http"
    return f"{scheme}://{host}{event.uri}"


def is_executable_uri(uri: str) -> bool:
    path = urlsplit(uri).path.lower()
    return path.endswith((".exe", ".dll", ".ps1", ".bat", ".vbs", ".scr"))


def analyze_http_events(events: list[HTTPEvent], config: dict) -> list[Finding]:
    findings: list[Finding] = []
    ua_path = config.get("intel", {}).get("suspicious_user_agents", "")
    suspicious_user_agents = _load_lines(ua_path)
    for event in events:
        user_agent = event.user_agent.lower()
        if user_agent and user_agent in suspicious_user_agents:
            findings.append(
                Finding(
                    title="Suspicious HTTP user agent",
                    description="HTTP request used a user agent that appears in the local suspicious list.",
                    category="http_c2",
                    timestamp=event.timestamp,
                    evidence={
                        "host": event.host,
                        "uri": event.uri,
                        "user_agent": event.user_agent,
                        "src_ip": event.src_ip,
                        "dst_ip": event.dst_ip,
                        **packet_evidence(event.packet_number),
                    },
                    tags=["http", "user-agent"],
                )
            )
        if is_executable_uri(event.uri):
            findings.append(
                Finding(
                    title="Executable download over HTTP",
                    description="HTTP URI suggests retrieval of an executable or script payload.",
                    category="http_c2",
                    timestamp=event.timestamp,
                    evidence={"url": event_url(event), "method": event.method, **packet_evidence(event.packet_number)},
                    tags=["http", "payload"],
                )
            )
    return findings
