from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from nettrace.models.events import DNSEvent, Flow, HTTPEvent, IOC, TLSEvent
from nettrace.models.findings import Finding


@dataclass
class AnalysisReport:
    pcap_path: str
    dns_events: list[DNSEvent]
    http_events: list[HTTPEvent]
    tls_events: list[TLSEvent]
    flows: list[Flow]
    iocs: list[IOC]
    findings: list[Finding]
    timeline: list[dict[str, Any]]

    def summary(self) -> dict[str, int]:
        return {
            "dns_events": len(self.dns_events),
            "http_events": len(self.http_events),
            "tls_events": len(self.tls_events),
            "flows": len(self.flows),
            "iocs": len(self.iocs),
            "findings": len(self.findings),
            "critical": sum(1 for finding in self.findings if finding.severity == "critical"),
            "high": sum(1 for finding in self.findings if finding.severity == "high"),
            "medium": sum(1 for finding in self.findings if finding.severity == "medium"),
            "low": sum(1 for finding in self.findings if finding.severity == "low"),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "pcap_path": self.pcap_path,
            "summary": self.summary(),
            "dns_events": [event.to_dict() for event in self.dns_events],
            "http_events": [event.to_dict() for event in self.http_events],
            "tls_events": [event.to_dict() for event in self.tls_events],
            "flows": [flow.to_dict() for flow in self.flows],
            "iocs": [ioc.to_dict() for ioc in self.iocs],
            "findings": [finding.to_dict() for finding in self.findings],
            "timeline": self.timeline,
        }
