from __future__ import annotations

from pathlib import Path
from typing import Any

from nettrace.analysis.beaconing import detect_beaconing
from nettrace.analysis.dga_scorer import score_domains
from nettrace.analysis.http_analyzer import analyze_http_events
from nettrace.analysis.ioc_extractor import extract_iocs
from nettrace.analysis.port_analyzer import analyze_flows
from nettrace.analysis.tls_analyzer import analyze_tls_events
from nettrace.intel.local_ioc_lookup import LocalIntel
from nettrace.intel.misp_lookup import MispLookup
from nettrace.mapping.attck_tagger import tag_findings
from nettrace.mapping.severity import score_findings
from nettrace.mapping.timeline import build_timeline
from nettrace.models.events import Flow
from nettrace.models.report import AnalysisReport
from nettrace.parsers.dns_extractor import extract_dns_event
from nettrace.parsers.flow_builder import update_flow
from nettrace.parsers.http_extractor import extract_http_event
from nettrace.parsers.pcap_loader import iter_packets
from nettrace.parsers.tls_extractor import extract_tls_event


def analyze_pcap(pcap_path: Path, config: dict[str, Any]) -> AnalysisReport:
    dns_events = []
    http_events = []
    tls_events = []
    flow_state: dict[tuple[str, str, int, int, str], Flow] = {}

    for packet_number, packet in enumerate(iter_packets(pcap_path), start=1):
        dns_event = extract_dns_event(packet, packet_number=packet_number)
        if dns_event:
            dns_events.append(dns_event)
        http_event = extract_http_event(packet, packet_number=packet_number)
        if http_event:
            http_events.append(http_event)
        tls_event = extract_tls_event(packet, packet_number=packet_number)
        if tls_event:
            tls_events.append(tls_event)
        update_flow(flow_state, packet, packet_number=packet_number)

    flows = list(flow_state.values())

    findings = []
    findings.extend(detect_beaconing(flows, config["thresholds"]))
    findings.extend(score_domains(dns_events, config["thresholds"]))
    findings.extend(analyze_http_events(http_events, config))
    findings.extend(analyze_tls_events(tls_events, flows, config["thresholds"]))
    findings.extend(analyze_flows(flows, config["thresholds"]))

    iocs = extract_iocs(dns_events, http_events, tls_events, flows)
    local_intel = LocalIntel.from_config(config["intel"])
    findings.extend(local_intel.match_iocs(iocs))

    misp = MispLookup.from_config(config.get("misp", {}))
    findings.extend(misp.match_iocs(iocs))

    tag_findings(findings)
    score_findings(findings)
    timeline = build_timeline(dns_events, http_events, tls_events, flows, findings)

    return AnalysisReport(
        pcap_path=str(pcap_path),
        dns_events=dns_events,
        http_events=http_events,
        tls_events=tls_events,
        flows=flows,
        iocs=iocs,
        findings=findings,
        timeline=timeline,
    )
