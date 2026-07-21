from __future__ import annotations

from nettrace.analysis.evidence import packet_evidence
from nettrace.models.events import FTPEvent
from nettrace.models.findings import Finding


def analyze_ftp_events(events: list[FTPEvent]) -> list[Finding]:
    findings: list[Finding] = []
    for event in events:
        if event.command not in {"PASS", "STOR", "APPE"}:
            continue
        if event.command == "PASS":
            title = "Cleartext FTP credentials"
            description = "An FTP password command was observed over an unencrypted control channel."
        else:
            title = "File upload over FTP"
            description = "An FTP upload command may indicate unencrypted data exfiltration."
        findings.append(
            Finding(
                title=title,
                description=description,
                category="ftp_exfiltration",
                timestamp=event.timestamp,
                evidence={
                    "src_ip": event.src_ip,
                    "dst_ip": event.dst_ip,
                    "dst_port": event.dst_port,
                    "command": event.command,
                    "argument": event.argument,
                    **packet_evidence(event.packet_number),
                },
                tags=["ftp", "cleartext"],
            )
        )
    return findings
