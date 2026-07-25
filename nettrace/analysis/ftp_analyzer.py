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
            # Bug #1: exposed credentials are not, by themselves, exfiltration --
            # there's no clean single ATT&CK technique for "cleartext auth
            # observed," so this stays untagged rather than forced into
            # T1048.003. attck_tagger.py has no "ftp_cleartext_credentials"
            # entry, so it is intentionally left without an ATT&CK mapping.
            findings.append(
                Finding(
                    title="Cleartext FTP credentials",
                    description="An FTP password command was observed over an unencrypted control channel.",
                    category="ftp_cleartext_credentials",
                    timestamp=event.timestamp,
                    confidence="high",
                    evidence={
                        "src_ip": event.src_ip,
                        "dst_ip": event.dst_ip,
                        "dst_port": event.dst_port,
                        "command": event.command,
                        "argument": event.argument,
                        **packet_evidence(event.packet_number),
                    },
                    tags=["ftp", "cleartext", "credentials"],
                )
            )
        else:
            # STOR/APPE is a confirmed upload direction, but "exfiltration"
            # additionally implies the destination is external/untrusted --
            # this analyzer has no destination-reputation context, so it
            # reports the observed upload at medium confidence and leaves the
            # exfiltration judgment for local-intel/MISP correlation or an
            # analyst to confirm, rather than asserting it outright.
            findings.append(
                Finding(
                    title="File upload over FTP",
                    description=(
                        "An FTP upload command was observed over an unencrypted control "
                        "channel. Confirm the destination is external/untrusted before "
                        "treating this as exfiltration."
                    ),
                    category="ftp_exfiltration",
                    timestamp=event.timestamp,
                    confidence="medium",
                    evidence={
                        "src_ip": event.src_ip,
                        "dst_ip": event.dst_ip,
                        "dst_port": event.dst_port,
                        "command": event.command,
                        "argument": event.argument,
                        **packet_evidence(event.packet_number),
                    },
                    tags=["ftp", "cleartext", "upload"],
                )
            )
    return findings
