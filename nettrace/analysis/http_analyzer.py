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
    return event.url


def is_executable_uri(uri: str) -> bool:
    path = urlsplit(uri).path.lower()
    return path.endswith((".exe", ".dll", ".ps1", ".bat", ".vbs", ".scr"))


# GET/HEAD on an executable path plausibly means "downloaded"; POST/PUT/PATCH more
# plausibly means "uploaded" (or is a report/telemetry beacon named *.exe by the
# attacker to blend in). Bug #5: the old code called both "download" regardless.
_DOWNLOAD_METHODS = {"GET", "HEAD"}
_UPLOAD_METHODS = {"POST", "PUT", "PATCH"}


def classify_http_executable(method: str) -> tuple[str, str, str]:
    """Return (title, description, confidence) for an executable-path HTTP request."""
    method_upper = (method or "").upper()
    if method_upper in _DOWNLOAD_METHODS:
        return (
            "Possible executable/script download request",
            "HTTP GET/HEAD requested an executable or script path.",
            "medium",
        )
    if method_upper in _UPLOAD_METHODS:
        return (
            "Executable/script path observed in HTTP request (upload direction)",
            "HTTP POST/PUT/PATCH targeted an executable/script path; this looks like "
            "an upload or beacon, not a download, and should not be labeled as one.",
            "low",
        )
    return (
        "Executable/script path observed in HTTP request",
        "HTTP request method does not confirm transfer direction for this "
        "executable/script path.",
        "low",
    )


def _tool_name(user_agent: str) -> str:
    """Tool identity without the version, e.g. 'curl/7.68.0' -> 'curl'."""
    return user_agent.split("/", 1)[0].strip()


def analyze_http_events(events: list[HTTPEvent], config: dict) -> list[Finding]:
    findings: list[Finding] = []
    ua_path = config.get("intel", {}).get("suspicious_user_agents", "")
    suspicious_user_agents = _load_lines(ua_path)
    suspicious_tool_names = {_tool_name(entry) for entry in suspicious_user_agents if entry}
    for event in events:
        user_agent = event.user_agent.lower()
        if user_agent and _tool_name(user_agent) in suspicious_tool_names:
            findings.append(
                Finding(
                    title="Command-line or automation HTTP client observed",
                    description=(
                        "HTTP request used a scripting/automation client (e.g. curl, wget, "
                        "python-requests). This is common for legitimate developer, CI, and "
                        "monitoring traffic -- treat as low-confidence context, not a standalone "
                        "indicator, unless combined with other suspicious signals."
                    ),
                    category="http_automation_client",
                    timestamp=event.timestamp,
                    confidence="low",
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
            title, description, confidence = classify_http_executable(event.method)
            findings.append(
                Finding(
                    title=title,
                    description=description,
                    category="http_c2",
                    timestamp=event.timestamp,
                    confidence=confidence,
                    evidence={"url": event_url(event), "method": event.method, **packet_evidence(event.packet_number)},
                    tags=["http", "payload"],
                )
            )
    return findings
